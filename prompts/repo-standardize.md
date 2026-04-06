# Repo Standardize Prompt

> Replace REPO_NAME and REPO_DESCRIPTION before pasting into Claude Code.

---

You are standardizing the REPO_NAME repository to meet
tomrivera-ops org governance standards.

Reference the org governance layer at:
https://raw.githubusercontent.com/tomrivera-ops/.github/main/CONTRIBUTING.md
https://raw.githubusercontent.com/tomrivera-ops/.github/main/ORG_AI_DEVELOPMENT_STANDARD.md
https://raw.githubusercontent.com/tomrivera-ops/.github/main/CLAUDE.md.template

STEP 1 — Read the codebase first
Before doing anything else, read and report:

  ls -la
  cat package.json 2>/dev/null || cat requirements.txt 2>/dev/null || echo "no manifest found"
  find . -name "*.ts" -o -name "*.js" -o -name "*.py" | head -20
  cat README.md 2>/dev/null || echo "no README found"

Report back:
- What this repo does
- Stack and key dependencies
- Directory structure
- Existing documentation

Do not proceed to Step 2 until you have read the codebase.

STEP 2 — Verify branch state
  git branch -r
  git log --oneline -5

Check:
- Does a dev branch exist? If not, create it:
    git checkout -b dev
    git push origin dev

- What is the current default branch?
- Are there any open feature branches?

STEP 3 — Set up branch protection on main
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

Set up branch protection on dev:
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

STEP 4 — Create governance branch
  git checkout main
  git pull origin main
  git checkout -b feat/add-governance

STEP 5 — Create CLAUDE.md
Using the template from the org .github repo and everything
you learned in Step 1, create a complete CLAUDE.md for this
repo. Fill in every section:

- Repo purpose (based on actual code, not assumptions)
- How it fits the system (upstream: what triggers it,
  downstream: what depends on it)
- Stack (exact versions from package.json or equivalent)
- Key directories (actual structure from ls)
- Dev commands (actual commands from package.json scripts
  or README)
- Branch workflow (per org standard)
- Safe vs unsafe changes (specific to this codebase —
  what is actually sensitive here?)
- Do not touch section (specific files or modules that
  are high risk)
- Areas requiring caution (auth, RLS, environment checks,
  bootstrap logic — whatever applies)
- PR expectations (per org standard)
- Notes for Claude (anything unique about operating in
  this repo safely)

Do not use placeholder text. Every section must reflect
the actual codebase.

STEP 6 — Update README.md
If README.md is missing or thin, add:
- What the repo does (2-3 sentences)
- How it fits the tomrivera-ops system
- Quick start (install + run commands)
- Link to CLAUDE.md for AI usage

If README is already solid, leave it alone.

STEP 7 — Add GitHub topic tags
  gh repo edit tomrivera-ops/REPO_NAME \
    --add-topic core-system

Adjust topics based on actual stack found in Step 1.
Add language, framework, and purpose tags as appropriate.

STEP 8 — Commit and push
  git add .
  git commit -m "feat: add governance layer (CLAUDE.md, README update)"
  git push origin feat/add-governance

STEP 9 — Open PR
  gh pr create \
    --title "feat: add governance layer" \
    --body "Adds CLAUDE.md and README updates to bring REPO_NAME into tomrivera-ops governance standard. Source: Cursor / Claude Code CLI." \
    --base dev \
    --head feat/add-governance

STEP 10 — Final report
Provide:
- Summary of what the repo actually does (from reading code)
- Stack confirmed
- CLAUDE.md created (yes/no)
- README updated (yes/no)
- Branch protection on main (pass/fail)
- Branch protection on dev (pass/fail)
- Topic tags applied
- PR URL
- Any issues encountered
- Anything unusual about this codebase worth flagging
