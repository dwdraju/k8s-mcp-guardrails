#!/usr/bin/env bash
# Issue a short-lived, audience-bound token for an agent ServiceAccount via the
# TokenRequest API and wrap it in a kubeconfig. Nothing long-lived is stored:
# the token expires after DURATION (default 1h) and the file is regenerated
# for every session.
#
# usage: scripts/agent-kubeconfig.sh [serviceaccount] [duration] > kubeconfig
set -euo pipefail
SA="${1:-namespace-agent}"
DURATION="${2:-1h}"
NS=agents
CLUSTER=kind-mcp-guardrails
# Always mint with the admin credentials, never whatever KUBECONFIG points at
# (after `source scripts/mcp-env.sh` that is the agent's own, possibly being
# overwritten by this very command's redirect).
ADMIN_KUBECONFIG="${ADMIN_KUBECONFIG:-$HOME/.kube/config}"
kubectl() { command kubectl --kubeconfig "$ADMIN_KUBECONFIG" "$@"; }

SERVER=$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name=='$CLUSTER')].cluster.server}")
CA=$(kubectl config view --raw -o jsonpath="{.clusters[?(@.name=='$CLUSTER')].cluster.certificate-authority-data}")
TOKEN=$(kubectl --context "$CLUSTER" -n "$NS" create token "$SA" --duration "$DURATION")

cat <<KCFG
apiVersion: v1
kind: Config
clusters:
  - name: $CLUSTER
    cluster:
      server: $SERVER
      certificate-authority-data: $CA
users:
  - name: $SA
    user:
      token: $TOKEN
contexts:
  - name: $SA@$CLUSTER
    context:
      cluster: $CLUSTER
      user: $SA
current-context: $SA@$CLUSTER
KCFG
