# Branch Protection Apply Prompt

> Replace REPO_NAME before pasting into Claude Code.

---

You are applying standard tomrivera-ops branch protection
to REPO_NAME on both main and dev.

NOTE: Branch protection requires GitHub Pro for private repos.
If the repo is private and not on Pro, this will fail with
HTTP 403. Either upgrade to Pro or make the repo public first.

STEP 1 — Apply protection to main
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

STEP 2 — Apply protection to dev
  gh api repos/tomrivera-ops/REPO_NAME/branches/dev/protection \
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

STEP 3 — Verify main
  gh api repos/tomrivera-ops/REPO_NAME/branches/main/protection \
    --jq '{
      enforce_admins: .enforce_admins.enabled,
      required_reviews: .required_pull_request_reviews.required_approving_review_count,
      dismiss_stale: .required_pull_request_reviews.dismiss_stale_reviews,
      force_push: .allow_force_pushes.enabled,
      deletions: .allow_deletions.enabled
    }'

STEP 4 — Verify dev
  gh api repos/tomrivera-ops/REPO_NAME/branches/dev/protection \
    --jq '{
      enforce_admins: .enforce_admins.enabled,
      required_reviews: .required_pull_request_reviews.required_approving_review_count,
      dismiss_stale: .required_pull_request_reviews.dismiss_stale_reviews,
      force_push: .allow_force_pushes.enabled,
      deletions: .allow_deletions.enabled
    }'

STEP 5 — Report

| Check | Expected | Actual | Pass/Fail |
|-------|----------|--------|-----------|
| main enforce_admins | true | ? | ? |
| main required_reviews | 1 | ? | ? |
| main dismiss_stale | true | ? | ? |
| main force_push | false | ? | ? |
| main deletions | false | ? | ? |
| dev enforce_admins | false | ? | ? |
| dev required_reviews | 1 | ? | ? |
| dev dismiss_stale | true | ? | ? |
| dev force_push | false | ? | ? |
| dev deletions | false | ? | ? |

All 10 checks must pass.
If any fail, report the exact error and whether it is
a private repo / GitHub Pro issue.
