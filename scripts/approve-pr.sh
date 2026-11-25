#!/usr/bin/env bash
# The human in the loop: review, approve and merge an agent's pull request as
# platform-admin, then nudge the GitOps engine (Flux or Argo CD) to sync now.
# usage: scripts/approve-pr.sh <pr-number> [--reject "reason"]
set -euo pipefail
cd "$(dirname "$0")/.."
N="${1:?usage: $0 <pr-number> [--reject reason]}"
G=http://localhost:3000/api/v1/repos/platform/tenants
AUTH="Authorization: token $(tr -d '[:space:]' < .secrets/gitea-admin.token)"

echo "=== PR #$N diff"
curl -sf -H "$AUTH" "$G/pulls/$N.diff"
echo
if [[ "${2:-}" == "--reject" ]]; then
  curl -sf -H "$AUTH" -H 'Content-Type: application/json' -X POST "$G/pulls/$N/reviews" \
    -d "{\"event\":\"REQUEST_CHANGES\",\"body\":$(python3 -c 'import json,sys;print(json.dumps(sys.argv[1]))' "${3:-rejected}")}" >/dev/null
  curl -sf -H "$AUTH" -H 'Content-Type: application/json' -X PATCH "$G/pulls/$N" -d '{"state":"closed"}' >/dev/null
  echo "PR #$N rejected and closed."; exit 0
fi
# Gitea computes a new PR's head/mergeability asynchronously; an approval sent
# in that window can be dropped as stale, so approve again on every retry.
for attempt in $(seq 15); do
  curl -sf -H "$AUTH" -H 'Content-Type: application/json' -X POST "$G/pulls/$N/reviews" \
    -d '{"event":"APPROVED","body":"Reviewed by platform-admin"}' >/dev/null
  code=$(curl -s -o /tmp/merge.$$ -w '%{http_code}' -H "$AUTH" -H 'Content-Type: application/json' \
    -X POST "$G/pulls/$N/merge" -d '{"Do":"squash","delete_branch_after_merge":true}')
  [[ "$code" == 200 ]] && break
  [[ $attempt -eq 15 ]] && { echo "merge failed: HTTP $code $(cat /tmp/merge.$$)" >&2; rm -f /tmp/merge.$$; exit 1; }
  sleep 2
done
rm -f /tmp/merge.$$
echo "PR #$N approved and merged. Syncing GitOps engine..."
scripts/gitops-sync.sh
