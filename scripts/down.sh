#!/usr/bin/env bash
# Tear everything down.
set -euo pipefail
cd "$(dirname "$0")/.."
kind delete cluster --name mcp-guardrails || true
docker rm -f gitea >/dev/null 2>&1 || true
rm -rf .secrets audit/*.log audit/*.jsonl
echo "POC removed."
