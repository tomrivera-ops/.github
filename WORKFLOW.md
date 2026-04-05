# Workflow Guide

How work actually moves through the tomrivera-ops system. This is the playbook for a solo founder operating across Cursor (desktop), Claude Code (mobile), and GitHub.

---

## Environment Roles

| Environment | Role | Best for | Limitations |
|-------------|------|----------|-------------|
| **Cursor** | Primary dev environment | Feature work, refactors, multi-file changes, testing | Requires desktop access |
| **Claude Code mobile** | Scoped edits on the go | Docs, small fixes, config tweaks, issue triage | No multi-file refactors, no testing |
| **GitHub (web)** | Review and merge hub | PR review, merge, issue management, project boards | Not for writing code |
| **Founder (you)** | PM and final approver | Architecture decisions, merge approval, priority calls | The bottleneck — protect your time |

---

## The Core Loop

```
Cursor (build) → GitHub (PR) → Claude Mobile (review/polish) → GitHub (merge) → Cursor (next task)
```

Every piece of work follows this pattern. The environment changes, but the loop stays the same.

---

## Workflow A: Standard Feature (from Cursor)

This is the most common workflow. You're at your desk, building something.

```bash
# 1. Start from dev, make sure it's current
git checkout dev
git pull origin dev

# 2. Create your feature branch
git checkout -b feat/your-feature-name

# 3. Do your work — commit as you go
git add <files>
git commit -m "feat: implement user auth flow"

# 4. Push when ready for review
git push origin feat/your-feature-name

# 5. Open a PR targeting dev
gh pr create --base dev --head feat/your-feature-name \
  --title "feat: implement user auth flow" \
  --body "Summary of changes..."

# 6. After review and approval, squash merge via GitHub UI or:
gh pr merge <number> --squash

# 7. Clean up
git checkout dev
git pull origin dev
git branch -d feat/your-feature-name
```

---

## Workflow B: Mobile Scoped Edit

You're on your phone, spotted a typo, or need to update docs.

```bash
# 1. Start from dev
git checkout dev
git pull origin dev

# 2. Create a mobile branch
git checkout -b mobile/fix-readme-typo

# 3. Make your scoped edit (1-3 files max)
git add <file>
git commit -m "docs: fix typo in README setup section"

# 4. Push immediately
git push origin mobile/fix-readme-typo

# 5. Open a PR
gh pr create --base dev --head mobile/fix-readme-typo \
  --title "docs: fix typo in README" \
  --body "Quick fix from mobile. Corrected typo in setup instructions."

# 6. Merge later from GitHub web or Cursor
```

### Mobile rules
- Never work on the same branch that Cursor is using
- Never touch files that are part of an open Cursor PR
- Keep it small and self-contained
- When in doubt, create an issue instead of a branch

---

## Workflow C: Hotfix Off Main

Something broke in production. Fix it fast.

```bash
# 1. Branch directly from main
git checkout main
git pull origin main
git checkout -b hotfix/fix-login-crash

# 2. Fix the issue
git add <files>
git commit -m "hotfix: patch login crash on expired tokens"

# 3. Push
git push origin hotfix/fix-login-crash

# 4. Open PR into main
gh pr create --base main --head hotfix/fix-login-crash \
  --title "hotfix: patch login crash" \
  --body "Critical fix for login crash when tokens expire."

# 5. After merge to main, also merge the fix into dev
git checkout dev
git pull origin dev
git merge main
git push origin dev
```

---

## Safe Resume Rules

### Resuming in Cursor
```bash
# Always start a session with:
git fetch origin
git status
git branch --show-current
git log --oneline -5

# If you're on a stale branch:
git checkout dev
git pull origin dev
# Then checkout or create your feature branch
```

### Resuming on Mobile
```bash
# Check what's active:
git fetch origin
git status
git log --oneline -3

# Only proceed if:
# - No merge conflicts
# - You're on a mobile/* branch
# - No open Cursor PRs touch the same files
```

---

## Conflict Avoidance Rules

1. **One environment per branch** — If Cursor is working on `feat/auth`, mobile does NOT touch that branch
2. **One branch per feature** — Don't pile unrelated changes onto the same branch
3. **Fetch before starting** — Always `git fetch origin` before beginning work in any environment
4. **Small branches, fast merges** — The longer a branch lives, the more likely conflicts become
5. **Communicate via issues** — If you need to hand off between environments, note it in the issue

---

## When to Use Each Environment

| Situation | Use | Why |
|-----------|-----|-----|
| Building a new feature | Cursor | Multi-file, needs testing |
| Fixing a production bug | Cursor (hotfix workflow) | Needs careful testing |
| Updating README | Either | Simple enough for mobile |
| Reviewing a PR | GitHub web or mobile | Visual diff is better |
| Triaging issues | Mobile or GitHub | Quick prioritization |
| Refactoring code | Cursor only | Too risky for mobile |
| Updating CI/CD config | Cursor | Needs testing |
| Quick env config tweak | Mobile (if scoped) | Single file change |

---

## Example Founder Workflow (Daily)

**Morning (mobile, coffee)**
- Check GitHub notifications
- Review any open PRs from yesterday
- Triage new issues, set priorities
- Maybe push a quick docs fix via `mobile/*` branch

**Work block (Cursor, desk)**
- Pull latest `dev`
- Pick highest-priority issue
- Create `feat/*` branch, build the thing
- Commit, push, open PR
- Run tests, verify locally
- Move to next task or review PRs

**Evening (mobile, couch)**
- Review PRs from the day
- Merge approved PRs via GitHub
- Update project board
- Create issues for tomorrow's work
- Maybe push a small docs or config fix

---

## Release Flow: dev → main

When `dev` is stable and you're ready to release:

```bash
# 1. Make sure dev is clean
git checkout dev
git pull origin dev

# 2. Open a release PR
gh pr create --base main --head dev \
  --title "release: v0.x.x" \
  --body "Release notes here. List of features, fixes, and changes."

# 3. Review the full diff carefully
# 4. Merge commit (not squash) to preserve history boundary
gh pr merge <number> --merge

# 5. Tag the release
git checkout main
git pull origin main
git tag -a v0.x.x -m "Release v0.x.x"
git push origin v0.x.x
```

Releases are merge commits so you can always see exactly where a release boundary is in the git log.
