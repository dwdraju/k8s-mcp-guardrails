#!/usr/bin/env bash
# Engine-agnostic "sync now": fetch main from git and apply it, then print one
# status line. Works with whichever engine scripts/gitops-engine.sh selected.
# usage: scripts/gitops-sync.sh [--status-only]
set -uo pipefail
cd "$(dirname "$0")/.."
engine() {
  if kubectl -n argocd get application tenants >/dev/null 2>&1; then echo argocd; else echo flux; fi
}
ENGINE=$(engine)
if [[ "$ENGINE" == flux ]]; then
  if [[ "${1:-}" != --status-only ]]; then
    flux -n agents reconcile source git tenants >/dev/null 2>&1
    flux -n agents reconcile kustomization tenants --timeout 45s >/dev/null 2>&1
  fi
  msg=$(kubectl -n agents get kustomization tenants -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}')
  echo "flux: $msg"
  exit 0
fi

# Argo CD: wait for the controller to see main's HEAD and finish an operation on it.
HEAD=$(curl -sf -H "Authorization: token $(tr -d '[:space:]' < .secrets/gitea-admin.token)" \
  http://localhost:3000/api/v1/repos/platform/tenants/branches/main \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["commit"]["id"])')
if [[ "${1:-}" != --status-only ]]; then
  # A failing sync (e.g. a resource the AppProject forbids) keeps retrying its
  # old revision and blocks newer commits -- such as the revert. Terminate it,
  # as `argocd app terminate-op` would.
  cur=$(kubectl -n argocd get application tenants -o jsonpath='{.status.operationState.syncResult.revision}{" "}{.status.operationState.operation.sync.revision}')
  phase=$(kubectl -n argocd get application tenants -o jsonpath='{.status.operationState.phase}')
  if [[ "$phase" == Running && "$cur" != *"$HEAD"* ]]; then
    kubectl -n argocd patch application tenants --type merge -p '{"status":{"operationState":{"phase":"Terminating"}}}' >/dev/null
    for _ in $(seq 15); do
      [[ $(kubectl -n argocd get application tenants -o jsonpath='{.status.operationState.phase}') != Terminating ]] && break; sleep 1
    done
  fi
  kubectl -n argocd annotate application tenants argocd.argoproj.io/refresh=hard --overwrite >/dev/null
  for _ in $(seq 30); do
    rev=$(kubectl -n argocd get application tenants -o jsonpath='{.status.operationState.syncResult.revision}')
    phase=$(kubectl -n argocd get application tenants -o jsonpath='{.status.operationState.phase}')
    [[ "$rev" == "$HEAD" && "$phase" =~ ^(Succeeded|Failed|Error)$ ]] && break
    # Nothing to apply for this commit (e.g. a revert back to the live state):
    # Argo marks it Synced without starting a new operation.
    read -r srev sstat < <(kubectl -n argocd get application tenants -o jsonpath='{.status.sync.revision}{" "}{.status.sync.status}')
    [[ "$srev" == "$HEAD" && "$sstat" == Synced && "$phase" != Running ]] && break
    sleep 2
  done
fi
kubectl -n argocd get application tenants -o json | python3 -c "$(cat <<'PY'
import json, sys
a = json.load(sys.stdin)["status"]
op = a.get("operationState", {})
conds = "; ".join(c["message"] for c in a.get("conditions", []))
rev = str(a.get("sync", {}).get("revision", ""))[:8]
print(f"argocd: sync={a.get('sync', {}).get('status')} health={a.get('health', {}).get('status')} "
      f"rev={rev} phase={op.get('phase')}: {op.get('message', '')} {conds}".strip())
PY
)"
