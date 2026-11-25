#!/usr/bin/env bash
# Bring up the whole POC from nothing, following the article's ordered steps:
#   1. sandbox cluster (kind) with API-server audit logging
#   2. Kyverno + the namespace policy pack in Audit mode
#   3. agent ServiceAccounts + minimal RBAC, short-lived token
#   4. MCP server (python venv) using that token
#   5. GitOps write path: Gitea (protected main, CODEOWNERS) + Flux or Argo CD
#      (GITOPS_ENGINE=flux|argocd, default flux; switch later with
#      scripts/gitops-engine.sh)
#   6. flip policies to Enforce (audit logging + TTL cleanup are already live)
#   7. red-team: run scripts/redteam.py
set -euo pipefail
cd "$(dirname "$0")/.."
POC_DIR=$PWD
CLUSTER=mcp-guardrails
GITOPS_ENGINE="${GITOPS_ENGINE:-flux}"
[[ "$GITOPS_ENGINE" =~ ^(flux|argocd)$ ]] || { echo "GITOPS_ENGINE must be flux or argocd" >&2; exit 2; }
KYVERNO_CHART_VERSION=3.9.2   # Kyverno 1.19.x: last release that still executes kyverno.io/v1 ClusterPolicy
say() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

for bin in docker kind kubectl helm kyverno uv python3 curl git; do
  command -v "$bin" >/dev/null || { echo "missing required tool: $bin (see README)" >&2; exit 1; }
done
command -v flux >/dev/null || [[ "$GITOPS_ENGINE" == argocd ]] || { echo "missing required tool: flux" >&2; exit 1; }
mkdir -p .secrets audit

say "1/7 kind cluster '$CLUSTER' with audit logging"
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  cfg=$(mktemp)
  sed "s#__POC_DIR__#$POC_DIR#g" kind/cluster.yaml > "$cfg"
  # Corporate/sandbox TLS-intercepting proxy: trust its CA inside the node.
  for ca in /usr/local/share/ca-certificates/*.crt; do
    [[ -f "$ca" ]] || continue
    python3 - "$cfg" "$ca" <<'PY'
import sys
cfg, ca = sys.argv[1], sys.argv[2]
s = open(cfg).read()
s = s.replace("    extraMounts:\n", f"    extraMounts:\n      - hostPath: {ca}\n        containerPath: {ca}\n        readOnly: true\n", 1)
open(cfg, "w").write(s)
PY
  done
  kind create cluster --config "$cfg"
  rm -f "$cfg"
  docker exec "$CLUSTER-control-plane" sh -c 'update-ca-certificates >/dev/null 2>&1 && systemctl restart containerd' || true
fi
kubectl config use-context "kind-$CLUSTER" >/dev/null
kubectl wait --for=condition=Ready node --all --timeout=180s

say "2/7 Kyverno + policy pack (Audit mode)"
helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null 2>&1 || true
helm repo update kyverno >/dev/null
helm upgrade --install kyverno kyverno/kyverno --version "$KYVERNO_CHART_VERSION" \
  -n kyverno --create-namespace \
  --set admissionController.replicas=1 --set backgroundController.replicas=1 \
  --set cleanupController.replicas=1 --set reportsController.replicas=1 \
  --wait --timeout 8m >/dev/null
kubectl apply -f cluster/20-kyverno-rbac.yaml
scripts/policy-mode.sh audit
kubectl wait clusterpolicy --all --for=condition=Ready --timeout=120s >/dev/null

say "3/7 agent identities + RBAC, short-lived token"
kubectl apply -f cluster/00-namespace.yaml -f cluster/10-agent-rbac.yaml
scripts/agent-kubeconfig.sh namespace-agent 1h > .secrets/agent.kubeconfig
chmod 600 .secrets/agent.kubeconfig

say "4/7 MCP server environment"
[[ -x mcp-server/.venv/bin/python ]] || uv venv -q mcp-server/.venv
uv pip install -q --python mcp-server/.venv/bin/python -r mcp-server/requirements.txt

say "5/7 GitOps write path: Gitea + $GITOPS_ENGINE"
scripts/gitea-setup.sh
if [[ "$GITOPS_ENGINE" == argocd ]]; then scripts/argocd-setup.sh; else scripts/flux-setup.sh; fi

say "6/7 policies -> Enforce"
scripts/policy-mode.sh enforce

say "7/7 done"
cat <<MSG
Cluster:     kind-$CLUSTER (admin kubeconfig: ~/.kube/config)
GitOps:      $GITOPS_ENGINE   (switch: scripts/gitops-engine.sh flux|argocd)
Agent token: .secrets/agent.kubeconfig (expires in 1h; refresh: scripts/agent-kubeconfig.sh > .secrets/agent.kubeconfig)
Gitea:       http://localhost:3000/platform/tenants  (platform-admin / Admin-Passw0rd!)
Audit log:   scripts/audit-log.sh [-f]   MCP tool-call log: audit/mcp-tool-calls.jsonl

Next:
  scripts/e2e.sh                                    # happy paths through the MCP server
  mcp-server/.venv/bin/python scripts/redteam.py    # the article's red-team test
  claude   (in this directory, uses .mcp.json)      # drive it with a real agent
MSG
