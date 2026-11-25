#!/usr/bin/env bash
# Install Flux (source + kustomize controllers) and point it at the tenants repo.
set -euo pipefail
cd "$(dirname "$0")/.."
flux install --components=source-controller,kustomize-controller --network-policy=false
kubectl -n agents create secret generic tenants-repo-auth \
  --from-literal=username=platform-admin \
  --from-literal=password="$(tr -d "[:space:]" < .secrets/gitea-flux.token)" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f gitops/flux/tenants-sync.yaml
kubectl -n agents wait gitrepository/tenants --for=condition=Ready --timeout=120s
