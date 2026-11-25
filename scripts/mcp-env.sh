# Source me: environment for running the MCP server / client as the agent.
POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export KUBECONFIG="$POC_DIR/.secrets/agent.kubeconfig"
export GITEA_URL="${GITEA_URL:-http://localhost:3000}"
export GITEA_REPO="${GITEA_REPO:-platform/tenants}"
export GITEA_TOKEN_FILE="$POC_DIR/.secrets/gitea-agent.token"
export MCP_AUDIT_LOG="$POC_DIR/audit/mcp-tool-calls.jsonl"
export WRITE_MODE="${WRITE_MODE:-gitops}"
mcpcall() { "$POC_DIR/mcp-server/.venv/bin/python" "$POC_DIR/mcp-server/client.py" "$@" 2> >(grep -v '^namespace-agent MCP server:' >&2); }
