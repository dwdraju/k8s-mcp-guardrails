#!/usr/bin/env bash
# Install Argo CD and point it at the tenants repo (alternative to flux-setup.sh).
set -euo pipefail
cd "$(dirname "$0")/.."
ARGOCD_CHART_VERSION=10.20.0
helm repo add argo https://argoproj.github.io/argo-helm >/dev/null 2>&1 || true
helm repo update argo >/dev/null
helm upgrade --install argocd argo/argo-cd --version "$ARGOCD_CHART_VERSION" \
  -n argocd --create-namespace -f gitops/argocd/values.yaml --wait --timeout 8m
kubectl -n argocd create secret generic tenants-repo \
  --from-literal=type=git \
  --from-literal=url=http://gitea:3000/platform/tenants.git \
  --from-literal=username=platform-admin \
  --from-literal=password="$(tr -d '[:space:]' < .secrets/gitea-flux.token)" \
  --dry-run=client -o yaml \
  | kubectl label --local -f - argocd.argoproj.io/secret-type=repository -o yaml \
  | kubectl apply -f -
kubectl apply -f gitops/argocd/tenants-app.yaml
for _ in $(seq 60); do
  s=$(kubectl -n argocd get application tenants -o jsonpath='{.status.sync.status}' 2>/dev/null || true)
  [[ "$s" == Synced ]] && break; sleep 3
done
kubectl -n argocd get application tenants
