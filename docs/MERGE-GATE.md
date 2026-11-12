# faraday-ci-bot merge gate

`cli-approve-merge.yml` lets `faraday-ci-bot` merge one PR at one exact head SHA, and only after
`scripts/merge_gate.py` ALLOWs it. It **never approves**, never uses `--admin`, and never runs PR code.

## The gate refuses unless all of these hold at the exact head
1. The PR is open, not a draft, comes from a same-repo branch (no fork), its base is the default branch, and its head equals the `head_sha` input.
2. **The gate never merges changes to itself.** In `tomrivera-ops/.github`, the following always refuse, whatever the authorization (`gate_self_modification`):
   - anything under `.github/`, `scripts/` or `policy/`;
   - any `*.py`, `*.pyc` or `*.pth` file anywhere;
   - `.gitattributes`, `.gitmodules`, `CODEOWNERS` and this document;
   - the gate's workspace files (`validated.json`, `evidence.json`, `decision.json`).

   Every other path refuses too, unless it matches the documentation allowlist `gate_repository_mergeable_paths` (`*.md`, `*.template`); that refusal is `gate_repository_path_not_allowlisted`. Matching is case-insensitive, and renames count both their old and new paths.
3. **CI.** At least one check run exists; every check run at the head completed with `success` or `skipped`; every commit status is `success`; and each policy-required context is satisfied by a **GitHub Actions** check run. A commit status cannot satisfy a required context. Required contexts only add CI requirements and never authorize a merge: any workflow in the target repository can create a check run, so check runs are evidence, not authority.
4. **Codex.**
   - A `chatgpt-codex-connector[bot]` receipt names this head ("Didn't find any major issues", with "Reviewed commit" matching at least the first 10 hex characters).
   - Codex left no review at this head.
   - There is no unresolved, non-outdated review thread.
5. **Independent review evidence** at this head: a PR comment containing
   `<!-- independent-review:v1 {"head_sha":"<sha>","verdict":"PASS","critical":0,"high":0,"medium":0,"reviewer":"..."} -->`.
   This is evidence, not authority.
6. **Authorization: a founder signature only.** The founder key, `SHA256:yhaDzjdnB4aFL11XaMxhjHuTYdLwlQXw6L+rS6BILDE`, must sign the exact decision message in namespace `faraday-merge-go`. That key is not on the agent host, so agents cannot produce this signature.
   - **Policy mode is disabled.** It previously accepted a Faraday Review check run (A0/A1), and any workflow's `GITHUB_TOKEN` can create a check run with that name, so the authorization was forgeable.
   - The workflow offers only `mode=founder`. `merge_gate.py` refuses `policy` (`policy_mode_disabled`) and any other mode (`invalid_mode`) at validation, before any token is minted, and again at evaluation.
   - No check run, comment or policy key can stand in for the signature.
   - Re-enabling A0/A1 merges is a separately authorized Faraday Review milestone. It needs an authorization source that a workflow token cannot forge.

## Trusted execution
Every Python step runs as `python3 -I`, so neither the script directory, the working directory nor `PYTHON*` variables reach `sys.path`. Without isolated mode, `merge_gate.py` refuses (`interpreter_not_isolated`) before it imports anything that searches `sys.path`. Before it decides, it also refuses if any repository directory is importable (`untrusted_import_path`) or any loaded module came from the repository (`untrusted_module_loaded`). A planted `scripts/json.py` therefore never executes, and it cannot be merged by the bot in the first place.

## Founder decision (founder mode)
On the founder's own device, which holds the founder key:

    printf 'faraday-merge-decision:v1\n%s/%s#%s\n%s\n%s\n' OWNER REPO PR HEAD_SHA squash \
      | ssh-keygen -Y sign -f ~/.ssh/<founder-key> -n faraday-merge-go | base64 -w0

Dispatch the workflow with `mode=founder` and the output as `founder_signature`. The signature binds the owner, repo, PR number, the full head SHA and the merge method. Changing any of them invalidates it.

## Tokens
- **Gate job:** a read-only token for the single target repository.
- **Merge job:** runs in environment `faraday-merge`, with a contents/pull_requests write token for the single target repository. It merges with `sha=<head>`, so GitHub rejects the merge if the head moved.
- The merge commit message records `faraday-merge-gate:v1 head=... mode=... run=<url>`. The gate decision is kept as a 90-day run artifact.

## Configuration this workflow needs (separately authorized; not part of this PR)
- Environment `faraday-merge` in `tomrivera-ops/.github`, with the deployment branch limited to `main`.
- `FARADAY_APP_ID` and `FARADAY_APP_PRIVATE_KEY` as **environment secrets** of `faraday-merge`. Both jobs run in that environment, so no org-level copy is needed for this workflow.

## Activation kill-switch (default: REFUSE)
ADR-0012 §1 forbids any bot merge. This workflow therefore ships **inactive** and stays inactive until a
ratified ADR-0014 supersedes ADR-0012 §1 for the scope it names. A merge needs all three, independently:
1. Repository variable `FARADAY_BOT_MERGE_ENABLED` is exactly `true`. Otherwise both jobs are skipped and no token is minted.
2. `policy/merge-policy.json` `activation.enabled` is `true`. This file can only change through a founder-merged PR, because the bot never merges `policy/`. Otherwise every subcommand refuses `bot_merge_not_activated` before any token is minted.
3. The governing ADR named in `activation.governing_adr` is read live from `main` of its repository and its `## Status` line starts with `Accepted`. Otherwise the gate refuses `governing_adr_not_accepted` or `governing_adr_unreadable`. The shipped path is ADR-0014 (agent-contracts PR #13, Proposed, not on `main`): until it is merged AND ratified the gate refuses (`governing_adr_unreadable`, then `governing_adr_not_accepted`).

Activation never replaces the founder signature. It only permits the gate to evaluate.

## Emergency disable
Use any one of these. Each is enough on its own:
- `gh variable delete FARADAY_BOT_MERGE_ENABLED -R tomrivera-ops/.github`, or set it to anything except `true`.
- `gh workflow disable "CLI Approve & Merge" -R tomrivera-ops/.github`.
- Revoke the App private key, or suspend or uninstall the `faraday-ci-bot` App installation.

After an emergency disable, also set `activation.enabled` to `false` in a founder-merged PR, and record a `governance-event`.

## Rollback of a bot merge
The bot never reverts. The founder reverts interactively: run `git revert -m 1 <merge-sha>` for a merge commit, or `git revert <sha>` for squash or rebase. Open a PR and merge it by hand. The merge commit message (`faraday-merge-gate:v1 head=... run=<url>`) and the 90-day decision artifact identify what to revert.
