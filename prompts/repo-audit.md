# Repo Audit Prompt

> Replace REPO_NAME before pasting into Claude Code.

---

You are performing a full health check on REPO_NAME
against tomrivera-ops org standards.

STEP 1 — Branch state
  cd ~/dev/tomrivera-ops/REPO_NAME
  git fetch origin
  git branch -r

Check:
- Does main exist?
- Does dev exist?
- Are there stale branches (merged but not deleted)?
- Are there branches older than 30 days with no recent commits?

List all remote branches and flag any that appear stale.

STEP 2 — Branch protection on main
  gh api repos/tomrivera-ops/REPO_NAME/branches/main/protection \
    --jq '{
      enforce_admins: .enforce_admins.enabled,
      required_reviews: .required_pull_request_reviews.required_approving_review_count,
      dismiss_stale: .required_pull_request_reviews.dismiss_stale_reviews,
      force_push: .allow_force_pushes.enabled,
      deletions: .allow_deletions.enabled
    }'

Expected: enforce_admins true, required_reviews 1,
dismiss_stale true, force_push false, deletions false.

STEP 3 — Branch protection on dev
  gh api repos/tomrivera-ops/REPO_NAME/branches/dev/protection \
    --jq '{
      enforce_admins: .enforce_admins.enabled,
      required_reviews: .required_pull_request_reviews.required_approving_review_count,
      dismiss_stale: .required_pull_request_reviews.dismiss_stale_reviews,
      force_push: .allow_force_pushes.enabled,
      deletions: .allow_deletions.enabled
    }'

Expected: enforce_admins false, required_reviews 1,
dismiss_stale true, force_push false, deletions false.

STEP 4 — Required files present
  git checkout main
  ls -la

Check for:
- README.md
- CLAUDE.md
- .gitignore

Report present or missing for each.

STEP 5 — No secrets committed
  git log --all --diff-filter=A --name-only --format="" | grep -iE '\.env$|\.env\.|credentials|secret|\.pem|\.key' | head -10

If any matches, flag immediately.
Also check:
  git show HEAD:.env 2>/dev/null && echo "WARNING: .env is tracked" || echo "OK: .env not tracked"

STEP 6 — Open PRs older than 3 days
  gh pr list --repo tomrivera-ops/REPO_NAME --state open --json number,title,createdAt,headRefName \
    --jq '.[] | select(
      (now - (.createdAt | fromdateiso8601)) > (3 * 24 * 3600)
    ) | {number, title, branch: .headRefName, created: .createdAt}'

Flag any stale PRs that should be closed or merged.

STEP 7 — Last commit dates
  echo "main:" && git log main -1 --format="%ci %s"
  echo "dev:" && git log dev -1 --format="%ci %s"

Flag if main or dev have not been updated in over 30 days.

STEP 8 — Topic tags
  gh repo view tomrivera-ops/REPO_NAME --json repositoryTopics \
    --jq '.repositoryTopics[].name'

Check that at least 2 topic tags are applied.
Flag if zero tags are set.

STEP 9 — Final report

| Check | Expected | Actual | Pass/Fail | Fix |
|-------|----------|--------|-----------|-----|
| main branch exists | yes | ? | ? | |
| dev branch exists | yes | ? | ? | Create with: git checkout -b dev && git push origin dev |
| No stale branches | clean | ? | ? | Delete merged branches |
| main enforce_admins | true | ? | ? | Run branch-protection-apply prompt |
| main required_reviews | 1 | ? | ? | Run branch-protection-apply prompt |
| main force_push | false | ? | ? | Run branch-protection-apply prompt |
| dev enforce_admins | false | ? | ? | Run branch-protection-apply prompt |
| dev required_reviews | 1 | ? | ? | Run branch-protection-apply prompt |
| dev force_push | false | ? | ? | Run branch-protection-apply prompt |
| README.md present | yes | ? | ? | Run repo-standardize prompt |
| CLAUDE.md present | yes | ? | ? | Run repo-standardize prompt |
| .gitignore present | yes | ? | ? | Add appropriate .gitignore |
| No secrets committed | clean | ? | ? | Remove with git filter-branch or BFG |
| No stale PRs | none | ? | ? | Close or merge stale PRs |
| main updated recently | <30 days | ? | ? | |
| dev updated recently | <30 days | ? | ? | |
| Topic tags applied | >=2 | ? | ? | gh repo edit --add-topic |

Flag critical failures (secrets, missing protection) at the top of the report.
