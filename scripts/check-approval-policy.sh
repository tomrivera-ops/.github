#!/usr/bin/env bash
# Fails if any tracked doc or workflow prescribes a nonzero required-approval count or
# mandatory code-owner review (ADR-0013: the founder is the only required human approver).
set -euo pipefail
pattern='"required_approving_review_count": *[1-9]|required_reviews(:| \|) *[1-9]|"require_code_owner_reviews": *true'
if git ls-files -z -- '*.md' '*.yml' '*.yaml' '*.json' '*.template' | xargs -0 grep -nE "$pattern"; then
  echo "::error::ADR-0013 violation: a file above prescribes a mandatory human approval gate."
  exit 1
fi
echo "approval policy check passed"
