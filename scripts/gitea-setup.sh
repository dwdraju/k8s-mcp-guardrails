#!/usr/bin/env bash
# Start a local Gitea (stand-in for GitHub/GitLab) and create the reviewed
# tenants repo:
#   - org "platform", repo "tenants" with CODEOWNERS
#   - main is protected: no direct pushes, 1 approval required, and only
#     approvals from platform-admin count (the human reviewer)
#   - namespace-agent can push branches and open PRs, never merge
# Tokens land in .secrets/ (git-ignored).
set -euo pipefail
cd "$(dirname "$0")/.."
G=http://localhost:3000
ADMIN=platform-admin; ADMIN_PW='Admin-Passw0rd!'
AGENT=namespace-agent; AGENT_PW='Agent-Passw0rd!'
mkdir -p .secrets

if ! docker ps --format '{{.Names}}' | grep -qx gitea; then
  docker rm -f gitea >/dev/null 2>&1 || true
  docker run -d --name gitea --network kind -p 127.0.0.1:3000:3000 \
    -e GITEA__security__INSTALL_LOCK=true \
    -e GITEA__server__ROOT_URL=$G/ -e GITEA__server__DOMAIN=localhost \
    -e GITEA__database__DB_TYPE=sqlite3 \
    -e GITEA__service__DISABLE_REGISTRATION=true \
    -e GITEA__repository__DEFAULT_BRANCH=main \
    docker.gitea.com/gitea:1-rootless >/dev/null
fi
for _ in $(seq 60); do curl -sf $G/api/healthz >/dev/null && break; sleep 2; done

mkuser() { docker exec gitea gitea admin user create --username "$1" --password "$2" \
  --email "$1@example.com" --must-change-password=false ${3:-} >/dev/null 2>&1 || true; }
mkuser $ADMIN "$ADMIN_PW" --admin
mkuser $AGENT "$AGENT_PW"

api() { local auth=$1 method=$2 path=$3; shift 3
  curl -sS -u "$auth" -X "$method" -H 'Content-Type: application/json' "$G/api/v1$path" "$@"; }
token() { # user pw name scopes...
  local u=$1 pw=$2 name=$3; shift 3
  api "$u:$pw" DELETE "/users/$u/tokens/$name" >/dev/null 2>&1 || true
  local scopes; scopes=$(printf '"%s",' "$@"); scopes="[${scopes%,}]"
  api "$u:$pw" POST "/users/$u/tokens" -d "{\"name\":\"$name\",\"scopes\":$scopes}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha1"])'
}

api "$ADMIN:$ADMIN_PW" POST /orgs -d '{"username":"platform","visibility":"private"}' >/dev/null || true
if ! api "$ADMIN:$ADMIN_PW" GET /repos/platform/tenants -f >/dev/null 2>&1; then
  api "$ADMIN:$ADMIN_PW" POST /orgs/platform/repos \
    -d '{"name":"tenants","private":true,"default_branch":"main","auto_init":false}' >/dev/null
  tmp=$(mktemp -d)
  cp -r gitops/repo-seed/. "$tmp/"
  git -C "$tmp" init -q -b main
  git -C "$tmp" -c user.name=$ADMIN -c user.email=$ADMIN@example.com add -A
  git -C "$tmp" -c user.name=$ADMIN -c user.email=$ADMIN@example.com commit -qm "Seed tenants repo"
  git -C "$tmp" push -q "http://$ADMIN:$(printf %s "$ADMIN_PW" | python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.stdin.read()))')@localhost:3000/platform/tenants.git" main
  rm -rf "$tmp"
fi

api "$ADMIN:$ADMIN_PW" PUT /repos/platform/tenants/collaborators/$AGENT -d '{"permission":"write"}' >/dev/null
api "$ADMIN:$ADMIN_PW" DELETE /repos/platform/tenants/branch_protections/main >/dev/null 2>&1 || true
api "$ADMIN:$ADMIN_PW" POST /repos/platform/tenants/branch_protections -d "{
  \"rule_name\": \"main\",
  \"enable_push\": false,
  \"required_approvals\": 1,
  \"enable_approvals_whitelist\": true,
  \"approvals_whitelist_username\": [\"$ADMIN\"],
  \"enable_merge_whitelist\": true,
  \"merge_whitelist_usernames\": [\"$ADMIN\"],
  \"block_on_rejected_reviews\": true,
  \"dismiss_stale_approvals\": true,
  \"block_on_outdated_branch\": false
}" >/dev/null

# Agent: may push branches + open PRs. Admin: reviews/merges. Flux: read-only.
token $AGENT "$AGENT_PW" mcp-agent write:repository write:issue read:user > .secrets/gitea-agent.token
token $ADMIN "$ADMIN_PW" reviewer write:repository write:issue read:user read:organization > .secrets/gitea-admin.token
token $ADMIN "$ADMIN_PW" flux-reader read:repository > .secrets/gitea-flux.token
chmod 600 .secrets/*.token
echo "Gitea ready at $G (platform-admin / $ADMIN_PW). Repo: $G/platform/tenants"
