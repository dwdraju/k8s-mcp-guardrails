#!/usr/bin/env bash
# Switch the GitOps engine that applies the tenants repo: flux <-> argocd.
# Hand-over never deletes tenant namespaces: the outgoing engine is detached
# without pruning, then the incoming one adopts the existing objects.
# usage: scripts/gitops-engine.sh flux|argocd|status
set -euo pipefail
cd "$(dirname "$0")/.."
current() {
  if kubectl -n argocd get application tenants >/dev/null 2>&1; then echo argocd
  elif kubectl -n agents get kustomization tenants >/dev/null 2>&1; then echo flux
  else echo none; fi
}
case "${1:-status}" in
  status) current; exit 0 ;;
  flux)
    if [[ $(current) == argocd ]]; then
      # No resources-finalizer on the Application, so deleting it orphans
      # (keeps) the namespaces.
      kubectl -n argocd delete application tenants
      kubectl -n argocd delete appproject tenants
      helm uninstall argocd -n argocd --wait
      kubectl delete namespace argocd --wait=false
    fi
    scripts/flux-setup.sh
    scripts/gitops-sync.sh ;;
  argocd)
    if [[ $(current) == flux ]]; then
      # prune=false first, otherwise deleting the Kustomization garbage-collects
      # every tenant namespace.
      kubectl -n agents patch kustomization tenants --type merge -p '{"spec":{"prune":false,"suspend":true}}'
      kubectl -n agents delete kustomization tenants
      kubectl -n agents delete gitrepository tenants
      kubectl -n agents delete secret tenants-repo-auth --ignore-not-found
      flux uninstall --silent --keep-namespace=false
    fi
    scripts/argocd-setup.sh
    scripts/gitops-sync.sh ;;
  *) echo "usage: $0 flux|argocd|status" >&2; exit 2 ;;
esac
echo "GitOps engine: $(current)"
