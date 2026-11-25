#!/usr/bin/env bash
# Tear everything down.
set -euo pipefail
cd "$(dirname "$0")/.."
# audit.log is created by kube-apiserver as root:root, so delete it from inside
# the node while it still exists; a plain rm would fail on most Docker hosts.
docker exec mcp-guardrails-control-plane sh -c 'rm -f /var/log/kubernetes/audit/*.log' 2>/dev/null || true
kind delete cluster --name mcp-guardrails || true
docker rm -f gitea >/dev/null 2>&1 || true
rm -rf .secrets audit/*.jsonl
rm -f audit/*.log 2>/dev/null || echo "note: audit/*.log is root-owned; remove with: sudo rm -f audit/*.log"
echo "POC removed."
