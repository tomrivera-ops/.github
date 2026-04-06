# Post-Merge Verify Prompt

> Replace REPO_NAME before pasting into Claude Code.

---

You are auditing the state of REPO_NAME after a major merge.
Verify everything is clean and locked down.

STEP 1 — Sync local state
  cd ~/dev/tomrivera-ops/REPO_NAME
  git fetch origin
  git checkout main && git pull origin main
  git checkout dev && git pull origin dev

STEP 2 — Verify merge commit on main
  git log main --oneline -5

Confirm the expected merge commit is present.

STEP 3 — Verify merge commit on dev
  git log dev --oneline -5

Confirm dev history is consistent with main.

STEP 4 — Verify all expected files present on main
  git checkout main
  ls -la

Check for:
- README.md
- CLAUDE.md
- .gitignore
- package.json (or equivalent manifest)
- Source directories

Report any missing files.

STEP 5 — Verify branch protection on main
  gh api repos/tomrivera-ops/REPO_NAME/branches/main/protection \
    --jq '{
      enforce_admins: .enforce_admins.enabled,
      required_reviews: .required_pull_request_reviews.required_approving_review_count,
      dismiss_stale: .required_pull_request_reviews.dismiss_stale_reviews,
      force_push: .allow_force_pushes.enabled,
      deletions: .allow_deletions.enabled
    }'

Expected:
- enforce_admins: true
- required_reviews: 1
- dismiss_stale: true
- force_push: false
- deletions: false

STEP 6 — Verify branch protection on dev
  gh api repos/tomrivera-ops/REPO_NAME/branches/dev/protection \
    --jq '{
      enforce_admins: .enforce_admins.enabled,
      required_reviews: .required_pull_request_reviews.required_approving_review_count,
      dismiss_stale: .required_pull_request_reviews.dismiss_stale_reviews,
      force_push: .allow_force_pushes.enabled,
      deletions: .allow_deletions.enabled
    }'

Expected:
- enforce_admins: false
- required_reviews: 1
- dismiss_stale: true
- force_push: false
- deletions: false

STEP 7 — Check for stale branches
  git branch -r

List any branches that are not main, dev, or origin/HEAD.
Flag any that appear stale or already merged.

STEP 8 — Verify PR state
  gh pr list --repo tomrivera-ops/REPO_NAME --state all --limit 10

Confirm:
- Release PR is MERGED
- No PRs stuck in OPEN state that should be closed

STEP 9 — Final report

| Check | Expected | Actual | Pass/Fail |
|-------|----------|--------|-----------|
| Merge commit on main | present | ? | ? |
| Dev consistent with main | yes | ? | ? |
| README.md present | yes | ? | ? |
| CLAUDE.md present | yes | ? | ? |
| .gitignore present | yes | ? | ? |
| Manifest present | yes | ? | ? |
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
| No stale branches | clean | ? | ? |
| Release PR merged | MERGED | ? | ? |

All checks must pass. Flag any failures with recommended fix.
