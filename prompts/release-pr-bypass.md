# Release PR Bypass Prompt

> Replace REPO_NAME and PR_NUMBER before pasting into Claude Code.

---

> WARNING: Only use for release PRs (dev → main).
> Never use for feature PRs.
> Always re-lock immediately after merge.
> Never leave enforce_admins: false overnight.

You are performing a release merge bypass on REPO_NAME.
This temporarily lowers enforce_admins on main so the
solo operator can admin-merge the release PR, then
immediately re-locks the branch.

STEP 1 — Lower enforce_admins on main
  gh api repos/tomrivera-ops/REPO_NAME/branches/main/protection \
    --method PUT \
    --input - <<'EOF'
  {
    "required_status_checks": null,
    "enforce_admins": false,
    "required_pull_request_reviews": {
      "required_approving_review_count": 1,
      "dismiss_stale_reviews": true
    },
    "restrictions": null,
    "allow_force_pushes": false,
    "allow_deletions": false
  }
  EOF

STEP 2 — Verify enforce_admins is false
  gh api repos/tomrivera-ops/REPO_NAME/branches/main/protection \
    --jq '.enforce_admins.enabled'

Expected: false
Do NOT proceed if this returns true.

STEP 3 — Report back and STOP
Report:
- enforce_admins confirmed false (yes/no)
- PR URL for mobile merge: https://github.com/tomrivera-ops/REPO_NAME/pull/PR_NUMBER

Do NOT merge the PR from CLI.
The operator will merge via GitHub mobile using merge commit.

STEP 4 — After operator confirms merge, re-lock main
  gh api repos/tomrivera-ops/REPO_NAME/branches/main/protection \
    --method PUT \
    --input - <<'EOF'
  {
    "required_status_checks": null,
    "enforce_admins": true,
    "required_pull_request_reviews": {
      "required_approving_review_count": 1,
      "dismiss_stale_reviews": true
    },
    "restrictions": null,
    "allow_force_pushes": false,
    "allow_deletions": false
  }
  EOF

STEP 5 — Verify re-lock
  gh api repos/tomrivera-ops/REPO_NAME/branches/main/protection \
    --jq '.enforce_admins.enabled'

Expected: true

STEP 6 — Final report
| Check | Expected | Actual | Pass/Fail |
|-------|----------|--------|-----------|
| enforce_admins lowered | false | ? | ? |
| PR merged | MERGED | ? | ? |
| enforce_admins re-locked | true | ? | ? |

All 3 must pass. If re-lock fails, retry immediately.
Do not end the session with enforce_admins: false.
