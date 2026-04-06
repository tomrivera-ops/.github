# Claude Code Prompt Library

Reusable prompts for standard tomrivera-ops operations.
Paste directly into Claude Code CLI in WSL.

| Prompt | When to use |
|--------|-------------|
| repo-standardize.md | Onboarding a new or existing repo to org standards |
| release-pr-bypass.md | Merging a release PR as solo operator |
| post-merge-verify.md | Auditing repo state after any major merge |
| branch-protection-apply.md | Applying standard branch protection to a new repo |
| repo-audit.md | Full health check on any repo |

---

Always run prompts from the repo directory they target.
Always verify output before acting on it.
Never skip the re-lock step after a bypass.
