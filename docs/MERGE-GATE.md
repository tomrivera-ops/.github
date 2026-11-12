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
3. **CI.** At least one check run exists; every check run at the head completed with `success` or `skipped`; every commit status is `success`; and each policy-required context is satisfied by a **GitHub Actions** check run. A commit status cannot satisfy a required context, because any user token can forge one.
4. **Codex.**
   - A `chatgpt-codex-connector[bot]` receipt names this head ("Didn't find any major issues", with "Reviewed commit" matching at least the first 10 hex characters).
   - Codex left no review at this head.
   - There is no unresolved, non-outdated review thread.
5. **Independent review evidence** at this head: a PR comment containing
   `<!-- independent-review:v1 {"head_sha":"<sha>","verdict":"PASS","critical":0,"high":0,"medium":0,"reviewer":"..."} -->`.
   This is evidence, not authority.
6. **Authorization:**
   - `mode=founder`: an SSH signature by the founder key, `SHA256:yhaDzjdnB4aFL11XaMxhjHuTYdLwlQXw6L+rS6BILDE`, namespace `faraday-merge-go`, over the exact decision message. That key is not on the agent host, so agents cannot produce this signature.
   - `mode=policy`: a GitHub Actions check run `faraday-review / governed-summary` at the head that reports `merge_authorized: true`, `risk_class: green` and `approval_class: A0|A1`, and no protected path is touched. Faraday Review Phase 1 never authorizes, so **policy mode refuses today by design**.

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
