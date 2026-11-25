#!/usr/bin/env bash
# End-to-end test of the happy paths, all driven through the MCP server:
#   1. the server refuses to start with an admin kubeconfig
#   2. gitops: create_environment -> PR -> agent cannot merge -> human merges
#      -> Flux or Argo CD applies -> namespace is born with every guardrail
#   3. drift: an out-of-band delete of a gitops namespace is reverted by the GitOps engine
#   4. direct (sandbox) mode: namespace created through admission, then the
#      TTL cleanup controller deletes it on its own
#   5. offline policy tests with the Kyverno CLI
set -uo pipefail
cd "$(dirname "$0")/.."
ADMIN_KUBECONFIG=$HOME/.kube/config
K="kubectl --kubeconfig $ADMIN_KUBECONFIG"
FAILS=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILS=$((FAILS+1)); }
step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

scripts/agent-kubeconfig.sh > .secrets/agent.kubeconfig
# shellcheck source=scripts/mcp-env.sh
source scripts/mcp-env.sh

step "1. MCP server refuses an admin kubeconfig"
out=$(KUBECONFIG=$ADMIN_KUBECONFIG mcp-server/.venv/bin/python mcp-server/server.py </dev/null 2>&1)
[[ $? -ne 0 && "$out" == *"refusing to start"* ]] && pass "$out" || fail "server started with admin credentials: $out"

step "2. GitOps path: PR, review, $(scripts/gitops-engine.sh status)"
out=$(mcpcall call create_environment '{"team":"checkout","env":"staging","owner":"bob","cost_center":"cc-5678","ttl":"24h","reason":"e2e test"}')
echo "$out" | head -3
PR=$(sed -n 's/^PR number: \([0-9]*\).*/\1/p' <<<"$out")
NS=$(sed -n 's/^PR number: [0-9]*  namespace: \(.*\)$/\1/p' <<<"$out")
[[ -n "$PR" && -n "$NS" ]] && pass "PR #$PR opened for $NS" || fail "no PR opened"
$K get ns "$NS" >/dev/null 2>&1 && fail "namespace exists before review" || pass "namespace not created before review"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H "Authorization: token $(tr -d '[:space:]' < .secrets/gitea-agent.token)" \
  -H 'Content-Type: application/json' "http://localhost:3000/api/v1/repos/platform/tenants/pulls/$PR/merge" -d '{"Do":"merge"}')
[[ "$code" == 403 || "$code" == 405 ]] && pass "agent cannot merge its own PR (HTTP $code)" || fail "agent merge returned HTTP $code"
KUBECONFIG=$ADMIN_KUBECONFIG scripts/approve-pr.sh "$PR" | tail -1 || fail "approve-pr.sh failed"
for _ in $(seq 30); do $K get ns "$NS" >/dev/null 2>&1 && break; sleep 2; done
sleep 4
desc=$(mcpcall call describe_environment "{\"name\":\"$NS\"}")
for want in "pod_security: restricted" "name: default-quota" "name: default-limits" "name: default-deny-all" \
            "role: ClusterRole/agent-workload-editor" "provisioned-via: gitops"; do
  grep -q "$want" <<<"$desc" && pass "$NS has $want" || fail "$NS missing $want"
done
mcpcall call get_change_request "{\"number\":$PR}" | grep -q "namespace: $NS exists" \
  && pass "get_change_request reports the namespace exists" || fail "get_change_request status"

step "3. Drift detection: out-of-band delete is reverted from git"
$K delete ns "$NS" --wait=true >/dev/null && echo "  admin deleted $NS out of band"
KUBECONFIG=$ADMIN_KUBECONFIG scripts/gitops-sync.sh | sed "s/^/  /"
for _ in $(seq 30); do $K get ns "$NS" >/dev/null 2>&1 && break; sleep 2; done
$K get ns "$NS" >/dev/null 2>&1 && pass "GitOps engine recreated $NS from git" || fail "$NS not recreated"
sleep 3
$K -n "$NS" get resourcequota default-quota >/dev/null 2>&1 && pass "recreated namespace has its quota again" || fail "no quota after recreate"

step "4. Direct (sandbox) mode + TTL expiry"
out=$(WRITE_MODE=direct mcpcall call create_environment '{"team":"spike","env":"sandbox","owner":"carol","cost_center":"cc-0001","ttl":"1m","reason":"e2e ttl test"}')
echo "$out" | head -1
DNS=$(sed -n 's/.*CREATED namespace \(team-[a-z0-9-]*\).*/\1/p' <<<"$out")
[[ -n "$DNS" ]] && pass "direct mode created $DNS" || fail "direct create failed: $out"
$K get ns "$DNS" -o jsonpath='{.metadata.labels.cleanup\.kyverno\.io/ttl}' | grep -qx 1m \
  && pass "cleanup.kyverno.io/ttl=1m set by admission" || fail "TTL label missing"
echo "  waiting for the TTL cleanup controller (up to 3 minutes)..."
for _ in $(seq 36); do $K get ns "$DNS" >/dev/null 2>&1 || break; sleep 5; done
$K get ns "$DNS" >/dev/null 2>&1 && fail "$DNS still exists after TTL" || pass "$DNS deleted by TTL cleanup"

step "5. Kyverno CLI policy tests (what CI would run)"
kyverno test policies/tests/ 2>&1 | grep -q " 0 tests failed" && pass "kyverno test" || fail "kyverno test"

step "Cleanup: expire the gitops environment through a reviewed PR"
EPR=$(python3 - "$NS" <<'EOF'
import json, sys, time, urllib.request
G = "http://localhost:3000/api/v1/repos/platform/tenants"
def call(tok, m, p, b=None):
    t = open(f".secrets/{tok}").read().strip()
    r = urllib.request.Request(G + p, method=m, data=json.dumps(b).encode() if b is not None else None,
                               headers={"Authorization": "token " + t, "Content-Type": "application/json"})
    with urllib.request.urlopen(r) as x:
        d = x.read(); return json.loads(d) if d else None
ns = sys.argv[1]; br = f"agent/expire-{ns}"
call("gitea-agent.token", "POST", "/branches", {"new_branch_name": br, "old_branch_name": "main"})
sha = call("gitea-agent.token", "GET", f"/contents/tenants/{ns}.yaml?ref={br}")["sha"]
call("gitea-agent.token", "DELETE", f"/contents/tenants/{ns}.yaml", {"branch": br, "sha": sha, "message": f"Expire {ns}"})
pr = call("gitea-agent.token", "POST", "/pulls", {"head": br, "base": "main", "title": f"Expire {ns}"})
print(pr["number"])
EOF
)
KUBECONFIG=$ADMIN_KUBECONFIG scripts/approve-pr.sh "$EPR" | tail -1
for _ in $(seq 30); do $K get ns "$NS" >/dev/null 2>&1 || break; sleep 2; done
$K get ns "$NS" >/dev/null 2>&1 && fail "GitOps engine did not prune $NS" || pass "GitOps engine pruned $NS after the expiry PR merged"

echo
if [[ $FAILS -eq 0 ]]; then printf '\033[32m\033[1mE2E PASS\033[0m\n'; else printf '\033[31m\033[1mE2E FAIL (%d)\033[0m\n' "$FAILS"; exit 1; fi
