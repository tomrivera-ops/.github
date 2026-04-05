# Contributing to tomrivera-ops

This guide governs how code moves through every repo in the org. Read it before your first commit.

---

## Branch Strategy

| Branch | Purpose | Created from | Merges into | Direct commits? |
|--------|---------|-------------|-------------|-----------------|
| `main` | Production-ready code | — | — | **Never** |
| `dev` | Integration branch | `main` | `main` | **Never** |
| `feat/*` | New features | `dev` | `dev` | Yes (on your branch) |
| `mobile/*` | Scoped edits from Claude Code mobile | `dev` | `dev` | Yes (scoped only) |
| `docs/*` | Documentation changes | `dev` | `dev` | Yes |
| `hotfix/*` | Critical production fixes | `main` | `main` AND `dev` | Yes (on your branch) |

### Rules

- **`main`** — Always deployable. Only receives merges from `dev` (releases) or `hotfix/*` (emergencies). Protected with required reviews.
- **`dev`** — Integration branch. All feature work lands here first via PR. Never commit directly.
- **`feat/*`** — Where real work happens. One feature per branch. Commit freely, PR into `dev` when done.
- **`mobile/*`** — For Claude Code mobile sessions. Scoped to specific files. Always PR into `dev`.
- **`docs/*`** — Documentation-only changes. Can PR directly into `dev`.
- **`hotfix/*`** — Emergency fixes only. Branch from `main`, PR into both `main` and `dev`.

---

## Naming Conventions

### Branches

```
feat/add-user-auth
feat/orbit-dashboard-api
mobile/fix-readme-typo
mobile/update-env-docs
docs/add-api-reference
hotfix/fix-login-crash
```

Pattern: `{type}/{short-descriptive-slug}`

### Commits

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add user authentication flow
fix: resolve null pointer in dashboard loader
docs: update API reference for /users endpoint
chore: update dependencies
refactor: extract validation into shared module
hotfix: patch login crash on expired tokens
```

Format: `{type}: {imperative description}`

Types: `feat`, `fix`, `docs`, `chore`, `refactor`, `hotfix`, `test`, `ci`

---

## Mobile Edit Rules (Claude Code Mobile)

### Allowed on mobile
- Documentation edits (README, CONTRIBUTING, comments)
- Config tweaks (env examples, CI flags)
- Small bug fixes in isolated files
- Issue triage and PR reviews

### NOT allowed on mobile
- Multi-file refactors
- New feature implementation
- Anything touching core business logic
- Dependency changes
- Database migrations
- Merge conflict resolution

### Mobile workflow
1. Always branch from `dev` → `mobile/{description}`
2. Keep changes to 1-3 files max
3. Write a clear commit message explaining the change
4. Open a PR — never merge from mobile
5. Tag for review if the change touches logic

---

## Cursor Development Rules

- Cursor is the primary development environment for all non-trivial work
- Always verify which branch you're on before starting work: `git branch --show-current`
- Pull latest before starting: `git pull origin dev`
- Use the integrated terminal for all git operations
- Run tests locally before pushing
- Do not trust AI-generated code blindly — review diffs before committing
- If Claude suggests a destructive git operation, pause and verify

---

## PR Requirements

Every PR must include:
- **Summary** — What changed and why
- **Files touched** — Quick list of modified files
- **Validation** — How you tested it (or why testing doesn't apply)
- **Source** — Where the change was made (Cursor / Claude mobile / GitHub UI)

Use the org PR template. It's pre-loaded in every repo.

### Who reviews?
- Founder reviews all PRs (this is a solo org with AI assistance)
- AI can draft PRs and suggest changes but does NOT approve or merge

---

## Merge Strategy

| Branch type | Merge method | Why |
|-------------|-------------|-----|
| `feat/*` → `dev` | **Squash merge** | Clean history, one commit per feature |
| `mobile/*` → `dev` | **Squash merge** | Keep mobile edits atomic |
| `docs/*` → `dev` | **Squash merge** | Simple and clean |
| `hotfix/*` → `main` | **Merge commit** | Preserve hotfix identity in main history |
| `dev` → `main` | **Merge commit** | Preserve the full release boundary |

---

## Rebase Policy

- **Do not rebase shared branches** (`main`, `dev`)
- You may rebase your own feature branch onto `dev` before opening a PR to keep history clean
- If your branch has been pushed and others might reference it, do not force-push
- When in doubt, merge instead of rebase

---

## GitHub is Source of Truth

- All code lives on GitHub. No local-only branches that matter.
- If it's not pushed, it doesn't exist yet.
- PRs are the only way code moves between branches.
- Issues track all work — even quick fixes get an issue if they take more than 5 minutes.
- Project boards in GitHub track priority and status.
