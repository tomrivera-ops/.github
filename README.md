# tomrivera-ops/.github

Org-wide governance, workflow standards, and AI development rules for all tomrivera-ops repositories.

## Human approval authority (2026-10-22)

Founder `tomrivera-PSE` is the **only required human approver** across founder-controlled repositories; no second independent human reviewer is required by default. Independent machine validation, tests, security checks, and audit evidence remain required where configured. GitHub PR authors cannot approve their own PR to satisfy branch-protection review requirements, so configured review-count and CODEOWNERS gates must be inspected and adjusted with administrator permissions to prevent solo-founder deadlocks. Do not treat this documentation as proof that live rulesets were changed. See [`agent-contracts` ADR-0013](https://github.com/tomrivera-ops/agent-contracts/blob/main/decisions/ADR-0013-solo-founder-human-approval.md). Founder authorization for a bounded scope is distinct from a second-human review requirement. No bypass of external segregation-of-duties obligations is authorized.
