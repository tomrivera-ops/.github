# Org AI Development Standard

How AI is used across every repo in tomrivera-ops. This is not a philosophy doc — it's an operating standard.

---

## Core Principle

**AI is a pair programmer, not a merge approver.**

AI writes code, suggests changes, drafts PRs, reviews diffs, and accelerates every part of the workflow. But the human founder makes the final call on what ships. AI does not approve PRs, merge to protected branches, or make architectural decisions unilaterally.

---

## Action Zones

Every action AI can take falls into one of three zones.

### Green Zone — AI acts freely
| Action | Example |
|--------|---------|
| Write code in feature branches | Implementing a function, adding a component |
| Run tests | `npm test`, `pytest`, linting |
| Read and analyze code | Understanding a codebase, finding bugs |
| Draft commit messages | Following conventional commit format |
| Draft PR descriptions | Filling in the PR template |
| Create branches | `feat/*`, `docs/*`, `mobile/*` |
| Search and reference docs | Looking up API docs, library usage |
| Generate boilerplate | Scaffolding, templates, config files |
| Suggest refactors | Proposing cleaner patterns |

### Yellow Zone — AI acts, human validates before merge
| Action | Example |
|--------|---------|
| Modify business logic | Changing how a feature works |
| Update API contracts | Changing request/response shapes |
| Edit CI/CD pipelines | Modifying GitHub Actions workflows |
| Change database schemas | Migrations, model changes |
| Update dependencies | `npm update`, version bumps |
| Modify security-related code | Auth, permissions, encryption |
| Cross-repo changes | Changes that affect multiple repos |

### Red Zone — Human only
| Action | Example |
|--------|---------|
| Merge PRs to `main` or `dev` | Only the founder merges |
| Approve PRs | AI reviews but does not approve |
| Delete branches or repos | Destructive operations |
| Modify branch protection rules | Governance changes |
| Push to `main` directly | Never — not even the founder |
| Handle secrets or credentials | `.env`, API keys, tokens |
| Make architectural decisions | System design, tech stack choices |
| Force push to shared branches | Destructive and irreversible |

---

## Mobile vs Desktop AI Boundaries

| Capability | Cursor (Desktop) | Claude Code (Mobile) |
|-----------|------------------|---------------------|
| Multi-file edits | Yes | No |
| Run tests | Yes | No |
| Complex refactors | Yes | No |
| Docs and config edits | Yes | Yes |
| PR drafting | Yes | Yes (simple only) |
| Code review assist | Yes | Yes (read-only suggestions) |
| Branch creation | Yes | Yes (mobile/* only) |
| Dependency changes | Yes | No |
| Database work | Yes | No |
| Git conflict resolution | Yes | No |

---

## Human Validation by Zone

| Zone | What the founder checks | When |
|------|------------------------|------|
| **Green** | Quick scan of the diff | Before merge (can be fast) |
| **Yellow** | Full diff review, test results, impact assessment | Before merge (take your time) |
| **Red** | N/A — founder does it themselves | Always |

---

## Repo Hygiene Standards

Every repo in tomrivera-ops must have:

- [ ] `README.md` — What it is, how to run it, how it connects to other repos
- [ ] `CLAUDE.md` — AI context file (see template in this repo)
- [ ] `.gitignore` — Appropriate for the stack
- [ ] Branch protection on `main` (require PR, no direct pushes)
- [ ] PR template (inherited from this `.github` repo or custom)
- [ ] At least one CI check (lint, test, or build)
- [ ] Issues enabled with labels configured

### CLAUDE.md Requirements

Every repo must have a `CLAUDE.md` at the root. This file tells AI assistants:
- What the repo does and how it fits the system
- Tech stack and key directories
- Dev commands (install, test, build, run)
- Branch workflow specifics for this repo
- What's safe vs unsafe to change
- Do-not-touch areas
- PR expectations

Use the `CLAUDE.md.template` in this repo as a starting point.

---

## Branch Protection Expectations

### `main` branch
- Require PR before merging
- Require at least 1 review (founder self-review counts for solo org)
- Require status checks to pass (when CI is set up)
- No direct pushes
- No force pushes
- No deletions

### `dev` branch
- Require PR before merging
- Status checks recommended
- No direct pushes
- No force pushes

---

## AI Session Hygiene

### Starting a session (Cursor or mobile)
1. Read `CLAUDE.md` in the repo you're working on
2. `git fetch origin && git status`
3. Check which branch you're on
4. Review recent commits: `git log --oneline -10`
5. Check for open PRs that might conflict: `gh pr list`
6. Understand the current task from the issue or context

### Ending a session
1. Commit all work in progress with a clear message
2. Push your branch to origin
3. If work is complete, open a PR
4. If work is incomplete, note what's left in the commit message or issue
5. Do not leave uncommitted changes — they will be lost between sessions

---

## Incident Response: When AI Makes a Mistake

AI will make mistakes. Here's how to handle it:

### Severity 1 — Wrong code merged to `dev`
1. Don't panic
2. Create a `hotfix/*` or `fix/*` branch
3. Revert or fix the issue
4. PR back into `dev`
5. Note what went wrong in the PR description

### Severity 2 — Wrong code merged to `main`
1. Assess impact — is production affected?
2. If critical, revert immediately: `git revert <commit>` → PR into `main`
3. Fix properly on a `hotfix/*` branch
4. Post-mortem: what check was missed?

### Severity 3 — AI overwrote or deleted something
1. Check `git reflog` — your work is probably recoverable
2. Restore from the reflog or a previous commit
3. Add the affected area to the "do not touch" section of `CLAUDE.md`

### Prevention
- Always review diffs before merging
- Keep the red zone rules strict
- Update `CLAUDE.md` when you discover new danger zones
- Use branch protection — it exists for this reason

---

## Standards for AI Systems Built in This Org

The following systems are built and maintained within tomrivera-ops. Each has AI-specific standards:

### Orbit (Core Platform)
- AI can build features but cannot modify the core data model without founder approval
- All API changes require yellow-zone validation
- Test coverage is mandatory for AI-generated code

### Shield (Security/Compliance)
- AI operates in yellow zone by default — all changes need review
- No AI access to production credentials or secrets
- Security logic changes require explicit founder sign-off

### Founder PM (AI Project Manager)
- AI can draft plans, prioritize issues, and suggest workflows
- AI does not have authority to close issues or merge PRs
- All AI-generated priorities are suggestions until founder confirms

### General Rule
If the system handles user data, money, or security — AI operates in yellow zone minimum. No exceptions.
