#!/usr/bin/env bash
# Flip every validate rule in the policy pack between Audit and Enforce.
# Roll out in Audit first, look at the PolicyReports, then Enforce.
# usage: scripts/policy-mode.sh audit|enforce
set -euo pipefail
cd "$(dirname "$0")/.."
case "${1:-}" in
  audit)   MODE=Audit;   VAP='["Audit"]' ;;
  enforce) MODE=Enforce; VAP='["Deny"]' ;;
  *) echo "usage: $0 audit|enforce" >&2; exit 2 ;;
esac
for f in policies/*.yaml; do
  # Kyverno rules use failureAction; the ValidatingAdmissionPolicy binding uses validationActions.
  sed -E -e "s/failureAction: (Audit|Enforce)/failureAction: $MODE/" \
         -e "s/validationActions: \[.*\]/validationActions: $VAP/" "$f"
  echo "---"
done | kubectl apply -f - 2>&1 | grep -v "is deprecated" || true
echo "Validate rules are now in $MODE mode."
