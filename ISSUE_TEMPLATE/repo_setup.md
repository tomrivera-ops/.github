---
name: Repo Setup
about: Request creation and initialization of a new repository
title: "repo: "
labels: repo-setup
assignees: ''
---

## Repo name

<!-- Format: tomrivera-ops/{repo-name} -->

`tomrivera-ops/`

## Purpose

<!-- One or two sentences — what does this repo do? -->

## Category

- [ ] **core-system** — Part of the core platform (Orbit, Shield, etc.)
- [ ] **infra** — Infrastructure, CI/CD, deployment tooling
- [ ] **app** — User-facing application
- [ ] **sandbox** — Experimental or proof-of-concept
- [ ] **audit** — Logging, compliance, monitoring

## Stack

<!-- What technologies will this repo use? -->

- Language:
- Framework:
- Database:
- Other:

## Connects to

<!-- What other repos or services does this interact with? -->

- Upstream (depends on):
- Downstream (used by):

## Setup checklist

- [ ] Repo created on GitHub
- [ ] README.md with purpose, setup instructions, and system context
- [ ] CLAUDE.md generated from template
- [ ] .gitignore appropriate for stack
- [ ] Branch protection configured on `main`
- [ ] `dev` branch created and pushed
- [ ] PR template inherited from `.github` or custom added
- [ ] Issue labels configured
- [ ] First CI check added (lint, test, or build)
- [ ] Added to org project board
- [ ] Documented in org architecture overview (if applicable)
