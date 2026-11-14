# faraday-ci-bot merge gate

`cli-approve-merge.yml` lets `faraday-ci-bot` merge one PR at one exact head SHA, and only after
`scripts/merge_gate.py` ALLOWs it. It **never approves**, never uses `--admin`, and never runs PR code.

## The gate refuses unless all of these hold at the exact head
1. The PR is open, not a draft, comes from a same-repo branch (no fork), its base is the default branch, and its head equals the `head_sha` input.
   - The default-branch tip equals the `base_sha` input (`stale_base`), and the head is not behind it (`head_behind_base`, read from the compare API). CI and reviews therefore ran on exactly the code that lands.
   - The PR author is readable (`pr_author_unreadable`) and is not the merge App (`pr_authored_by_merge_identity`).
2. **The gate never merges changes to itself.** In `tomrivera-ops/.github`, the following always refuse, whatever the authorization (`gate_self_modification`):
   - anything under `.github/`, `scripts/` or `policy/`;
   - any `*.py`, `*.pyc` or `*.pth` file anywhere;
   - `.gitattributes`, `.gitmodules`, `CODEOWNERS` and this document;
   - the gate's workspace files (`validated.json`, `evidence.json`, `decision.json`).

   Every other path refuses too, unless it matches the documentation allowlist `gate_repository_mergeable_paths` (`*.md`, `*.template`); that refusal is `gate_repository_path_not_allowlisted`. Matching is case-insensitive, and renames count both their old and new paths.
3. **CI (the complete configured set, never "any one green check").**
   - At least one check run exists; every check run at the head completed with `success` or `skipped`; every commit status is `success`.
   - The target repository must have a non-empty list in `required_contexts`; otherwise the gate refuses `required_contexts_not_configured`. The shipped lists mirror the live branch protection (`required-checks` for `.github` and `ecosystem-audit`).
   - Each required context must be a **GitHub Actions** check run whose conclusion is exactly `success`. Missing refuses `required_context_missing`; `skipped`, `neutral` or any other conclusion refuses `required_context_not_success` (ADR-0014 E3/T6). A commit status cannot satisfy a required context.
   - Required contexts only add CI requirements and never authorize a merge: any workflow in the target repository can create a check run, so check runs are evidence, not authority.
4. **Codex.**
   - A `chatgpt-codex-connector[bot]` receipt names this head ("Didn't find any major issues", with "Reviewed commit" matching at least the first 10 hex characters).
   - Codex left no review at this head.
   - There is no unresolved, non-outdated review thread.
   - The latest `codex-review-state:v1` record from the Codex App names this head, with `status: completed` and `has_unresolved_findings: false` (and no unresolved security review at this head). Otherwise the gate refuses `codex_review_state_missing`, `codex_review_state_stale` or `codex_unresolved_findings`. A clean receipt alone is not enough, because findings from an earlier round can still be open.
5. **Independent review evidence** at this head: a PR comment containing
   `<!-- independent-review:v1 {"head_sha":"<sha>","verdict":"PASS","critical":0,"high":0,"medium":0,"reviewer":"..."} -->`.
   This is evidence, not authority.
   - Only comments by a login in `independent_reviewers` count, and never one by the PR's own author. The policy refuses (`policy_invalid`) if that list names the founder account (which agent sessions share today) or the merge App.
   - The shipped list is **empty**, so the gate refuses `independent_reviewer_not_configured` until a distinct reviewer identity exists (ADR-0014 E7/T4).
   - The latest record wins, so a later `FAIL` overrides an earlier `PASS`. The counts must be the integer `0`; booleans, strings, floats or missing keys refuse `independent_review_not_clean`.
6. **Authorization: a founder signature only.** The founder key, `SHA256:yhaDzjdnB4aFL11XaMxhjHuTYdLwlQXw6L+rS6BILDE`, must sign the exact v2 decision message in namespace `faraday-merge-go`. That key is not on the agent host, so agents cannot produce this signature.
   - The decision binds the repository, PR, head SHA, **base SHA**, merge method, **policy version** and an **expiry** (ADR-0014 §5 and §6.1). A v1 signature no longer verifies.
   - The decision is an expiring grant. It refuses `grant_expired` once `expires_at` has passed, and `grant_ttl_exceeds_policy` if it was issued for longer than `grant.max_ttl_hours` (shipped: 24). Both are checked before any token is minted, again at evaluation, and again immediately before the merge.
   - It is single-use by construction: a merged or closed PR, a moved head, a moved base or a changed policy version all refuse.
   - **Policy mode is disabled.** It previously accepted a Faraday Review check run (A0/A1), and any workflow's `GITHUB_TOKEN` can create a check run with that name, so the authorization was forgeable.
   - The workflow offers only `mode=founder`. `merge_gate.py` refuses `policy` (`policy_mode_disabled`) and any other mode (`invalid_mode`) at validation, before any token is minted, and again at evaluation.
   - No check run, comment or policy key can stand in for the signature.
   - Re-enabling A0/A1 merges is a separately authorized Faraday Review milestone. It needs an authorization source that a workflow token cannot forge.

## Trusted execution
Every Python step runs as `python3 -I`, so neither the script directory, the working directory nor `PYTHON*` variables reach `sys.path`. Without isolated mode, `merge_gate.py` refuses (`interpreter_not_isolated`) before it imports anything that searches `sys.path`. Before it decides, it also refuses if any repository directory is importable (`untrusted_import_path`) or any loaded module came from the repository (`untrusted_module_loaded`). A planted `scripts/json.py` therefore never executes, and it cannot be merged by the bot in the first place.

## Founder decision (founder mode)
On the founder's own device, which holds the founder key:

    # owner/repo in lower case; HEAD_SHA and BASE_SHA are full 40-hex; BASE_SHA is the default-branch tip.
    # POLICY is policy_version from policy/merge-policy.json on main; EXPIRES is UTC, at most 24h ahead.
    printf 'faraday-merge-decision:v2\nrepo=%s/%s\npr=%s\nhead=%s\nbase=%s\nmethod=%s\npolicy=%s\nexpires=%s\n' \
        OWNER REPO PR HEAD_SHA BASE_SHA squash POLICY 2026-11-15T18:00:00Z \
      | ssh-keygen -Y sign -f ~/.ssh/<founder-key> -n faraday-merge-go | base64 -w0

Dispatch the workflow with `mode=founder`, the same `head_sha`, `base_sha` and `expires_at`, and the output as `founder_signature`. Changing any bound field invalidates the signature. If the default branch moves before the merge, the gate refuses `stale_base`; sign a new decision for the new tip.

## Tokens
- **Gate job:** a read-only token for the single target repository.
- **Merge job:** runs in environment `faraday-merge`. It first mints a contents/pull_requests **read** token (gate repository, ADR repository, target) and runs `merge_gate.py premerge`. Only then does it mint a contents/pull_requests write token for the single target repository, and it runs `premerge` again immediately before `PUT /merge`. `premerge` re-reads, live: the kill switch, the policy version on `main`, the grant expiry, the PR (open, not draft, same head, same-repo head, base still the default branch) and the default-branch tip (still `base_sha`). It merges with `sha=<head>`, so GitHub rejects the merge if the head moved.
- **Durable audit receipt:** the merge commit message records `faraday-merge-gate:v1 head=... base=... expires=... decision_sha256=... gate_commit=... mode=... run=<url>`. `decision_sha256` is the SHA-256 of the gate's `decision.json`, which is also kept as a 90-day run artifact. The digest stays in git history after the artifact expires.

## Configuration this workflow needs (separately authorized; not part of this PR)
- Environment `faraday-merge` in `tomrivera-ops/.github`, with the deployment branch limited to `main`.
- `FARADAY_APP_ID` and `FARADAY_APP_PRIVATE_KEY` as **environment secrets** of `faraday-merge`. Both jobs run in that environment, so no org-level copy is needed for this workflow.
- The org-level copies of both secrets restricted or removed. An environment secret only overrides a same-named org secret inside this workflow; while the org copies have `visibility: all`, any workflow in any repository can mint a write token without this gate.
- The App's installation permissions must include `checks: read`, `statuses: read` and `issues: read`, because the gate's read token requests them. Today the installation has only `actions: read`, `administration: read`, `contents: write`, `metadata: read` and `pull_requests: write`, so token minting would fail and the gate would refuse.
- A distinct independent-reviewer identity, added to `independent_reviewers` in a founder-merged PR.

## Activation kill-switch (default: REFUSE)
ADR-0012 §1 forbids any bot merge. This workflow therefore ships **inactive** and stays inactive until a
ratified ADR-0014 supersedes ADR-0012 §1 for the scope it names. A merge needs all three, independently:
1. Repository variable `FARADAY_BOT_MERGE_ENABLED` is exactly `true`. Otherwise both jobs are skipped and no token is minted.
2. `policy/merge-policy.json` `activation.enabled` is `true`. This file can only change through a founder-merged PR, because the bot never merges `policy/`. Otherwise every subcommand refuses `bot_merge_not_activated` before any token is minted.
3. The governing ADR named in `activation.governing_adr` is read live from `main` of its repository, its `## Status` line starts with `Accepted`, and its git blob SHA equals `activation.governing_adr.blob_sha`. Otherwise the gate refuses `governing_adr_not_accepted`, `governing_adr_unreadable` or `governing_adr_pin_mismatch`.
   - The pin exists because `agent-contracts` is private on GitHub Free: its `main` cannot be protected (the API returns 403), and several installed Apps hold `contents: write` there. Its text alone is therefore not trusted.
   - The founder sets the pin (`git hash-object decisions/ADR-0014-risk-tiered-delegated-merge.md` at the ratified commit) in the same founder-merged PR that sets `activation.enabled`. The shipped pin is empty, which refuses `policy_invalid` once enabled.
   - Any later edit to the ADR, including a forged `Accepted`, refuses until the founder re-pins it. The shipped path is ADR-0014 (agent-contracts PR #13, Proposed, not on `main`): until it is merged AND ratified the gate refuses (`governing_adr_unreadable`, then `governing_adr_not_accepted`).

   The Status is parsed strictly. HTML comments and fenced code blocks are ignored, and exactly one `## Status` section must remain; otherwise the gate refuses `governing_adr_ambiguous`. The merge job runs `merge_gate.py premerge` twice: before it mints the write token, and immediately before the merge call. Each time it re-reads live:
   - this workflow's own state (via the run id and `GITHUB_TOKEN` `actions: read`);
   - the policy file and the pinned ADR from `main`;
   - the grant expiry, before and after the reads.

   It refuses `workflow_not_active` or `policy_changed` on any change to the canonical policy content, not just to `policy_version`. Disabling the workflow, disabling `activation.enabled`, editing the policy or withdrawing the ADR therefore stops a run that the gate already allowed.

   The repository variable is evaluated when each job starts. It cannot be re-read mid-run, because the pinned `create-github-app-token` has no variables permission and `GITHUB_TOKEN` has no variables scope. For an in-flight run, use `gh workflow disable`.

Activation never replaces the founder signature. It only permits the gate to evaluate.

## Emergency disable
Use any one of these. Each is enough on its own:
- `gh workflow disable "CLI Approve & Merge" -R tomrivera-ops/.github`. This is the only switch that also stops a run already past the gate, because `premerge` reads it live.
- `gh variable delete FARADAY_BOT_MERGE_ENABLED -R tomrivera-ops/.github`, or set it to anything except `true`. This stops every job that has not started yet.
- Revoke the App private key, or suspend or uninstall the `faraday-ci-bot` App installation.

After an emergency disable, also set `activation.enabled` to `false` in a founder-merged PR, and record a `governance-event`.

## Rollback of a bot merge
The bot never reverts. The founder reverts interactively: run `git revert -m 1 <merge-sha>` for a merge commit, or `git revert <sha>` for squash or rebase. Open a PR and merge it by hand. The merge commit message (`faraday-merge-gate:v1 head=... run=<url>`) and the 90-day decision artifact identify what to revert.
