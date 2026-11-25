#!/usr/bin/env bash
# Print the Kubernetes API-server audit log (JSON lines).
#
# kube-apiserver runs as root inside the kind node and creates audit.log as
# root:root 0600, so on a normal Docker host the bind-mounted copy in audit/
# is not readable by your user. Read it from inside the node instead.
# usage: scripts/audit-log.sh [-f]      (-f to follow)
set -euo pipefail
cd "$(dirname "$0")/.."
NODE=mcp-guardrails-control-plane
LOG=/var/log/kubernetes/audit/audit.log
if [[ -r audit/audit.log ]]; then
  if [[ "${1:-}" == -f ]]; then exec tail -n +1 -f audit/audit.log; else exec cat audit/audit.log; fi
fi
if [[ "${1:-}" == -f ]]; then exec docker exec "$NODE" tail -n +1 -f "$LOG"; else exec docker exec "$NODE" cat "$LOG"; fi
