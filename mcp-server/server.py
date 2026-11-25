#!/usr/bin/env python3
"""namespace-agent MCP server.

An intent-level Kubernetes MCP server for provisioning team namespaces, built
to the layering in "Kubernetes MCP server: agent namespace guardrails":

  * a handful of read tools plus exactly ONE write tool (create_environment);
    no raw kubectl passthrough
  * runs with a short-lived, per-agent ServiceAccount token (refuses to start
    with an over-privileged kubeconfig)
  * every guardrail lives in the cluster (RBAC + Kyverno admission), not here:
    local checks only exist to give the model faster, friendlier feedback
  * writes go through git by default: the tool opens a pull request and returns
    the rendered diff and PR link, never a bare "done"

Configuration (environment variables):
  KUBECONFIG              kubeconfig with the agent's short-lived token (required)
  WRITE_MODE              "gitops" (default: open a PR) or "direct" (sandbox only:
                          create the namespace immediately through admission)
  GITEA_URL               default http://localhost:3000
  GITEA_REPO              default platform/tenants
  GITEA_TOKEN_FILE        file holding the agent's git token
  MCP_AUDIT_LOG           JSONL file recording every tool call (optional)
  MCP_ENABLE_RAW_APPLY    "1" registers apply_manifest, a raw passthrough used
                          ONLY to red-team the cluster guardrails. Off by default.
"""

from __future__ import annotations

import base64
import datetime as dt
import functools
import json
import os
import re
import secrets
import string
import sys
from typing import Any

import logging

import httpx
import yaml
from kubernetes import client, config, dynamic
from kubernetes.client.rest import ApiException
from mcp.server.mcpserver import MCPServer

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
WRITE_MODE = os.environ.get("WRITE_MODE", "gitops").lower()
GITEA_URL = os.environ.get("GITEA_URL", "http://localhost:3000").rstrip("/")
GITEA_REPO = os.environ.get("GITEA_REPO", "platform/tenants")
GITEA_TOKEN_FILE = os.environ.get("GITEA_TOKEN_FILE", "")
AUDIT_LOG = os.environ.get("MCP_AUDIT_LOG", "")
RAW_APPLY = os.environ.get("MCP_ENABLE_RAW_APPLY") == "1"

logging.getLogger("httpx").setLevel(logging.WARNING)

if WRITE_MODE not in ("gitops", "direct"):
    sys.exit(f"WRITE_MODE must be gitops or direct, got {WRITE_MODE!r}")

# Mirrors policies/10-agent-namespace-naming.yaml. The cluster is the source of
# truth; this is only here so the model gets an answer without a round trip.
NAME_RE = re.compile(r"^team-[a-z0-9]{2,12}-(dev|staging|preview|sandbox)-[a-z0-9]{4,8}$")
TEAM_RE = re.compile(r"^[a-z0-9]{2,12}$")
ENVS = ("dev", "staging", "preview", "sandbox")
TTL_RE = re.compile(r"^[1-9][0-9]{0,2}[mh]$")
LABEL_VALUE_RE = re.compile(r"^[a-z0-9]([-a-z0-9_.]{0,61}[a-z0-9])?$")

# --------------------------------------------------------------------------
# Kubernetes client (agent identity)
# --------------------------------------------------------------------------
config.load_kube_config()
api_client = client.ApiClient()
core = client.CoreV1Api(api_client)
rbac = client.RbacAuthorizationV1Api(api_client)
networking = client.NetworkingV1Api(api_client)
authn = client.AuthenticationV1Api(api_client)
authz = client.AuthorizationV1Api(api_client)
custom = client.CustomObjectsApi(api_client)


def _can(verb: str, resource: str, group: str = "", namespace: str | None = None) -> bool:
    review = client.V1SelfSubjectAccessReview(
        spec=client.V1SelfSubjectAccessReviewSpec(
            resource_attributes=client.V1ResourceAttributes(
                verb=verb, resource=resource, group=group, namespace=namespace
            )
        )
    )
    return bool(authz.create_self_subject_access_review(review).status.allowed)


def _whoami() -> dict[str, Any]:
    review = authn.create_self_subject_review(client.V1SelfSubjectReview())
    info = review.status.user_info
    return {"username": info.username, "groups": info.groups or []}


def _assert_least_privilege() -> dict[str, Any]:
    """Refuse to serve tools with an admin / human kubeconfig.

    'Never mount an admin kubeconfig into an MCP process' -- enforce it.
    """
    try:
        ident = _whoami()
    except ApiException as e:
        sys.exit(f"cannot authenticate to the cluster ({e.status} {e.reason}); "
                 "the agent token may have expired -- run scripts/agent-kubeconfig.sh")
    if not ident["username"].startswith("system:serviceaccount:agents:"):
        sys.exit(f"refusing to start: identity {ident['username']!r} is not an agent "
                 "ServiceAccount in the 'agents' namespace")
    dangerous = [
        ("*", "*", "*"),
        ("create", "clusterrolebindings", "rbac.authorization.k8s.io"),
        ("delete", "namespaces", ""),
        ("get", "secrets", ""),
    ]
    held = [f"{v} {g + '/' if g and g != '*' else ''}{r}" for v, r, g in dangerous if _can(v, r, g)]
    if held:
        sys.exit(f"refusing to start: agent identity is over-privileged ({', '.join(held)})")
    return ident


IDENTITY = _assert_least_privilege()

# --------------------------------------------------------------------------
# Audit trail of tool calls (complements the Kubernetes audit log)
# --------------------------------------------------------------------------


def _audit(tool: str, args: dict[str, Any], outcome: str) -> None:
    if not AUDIT_LOG:
        return
    entry = {
        "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
        "agent": IDENTITY["username"],
        "tool": tool,
        "args": args,
        "outcome": outcome,
    }
    with open(AUDIT_LOG, "a") as fh:
        fh.write(json.dumps(entry) + "\n")


def audited(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            result = fn(*args, **kwargs)
        except Exception as e:  # surface errors to the model, keep a record
            _audit(fn.__name__, kwargs, f"error: {e}")
            raise
        first_line = str(result).splitlines()[0] if result else ""
        _audit(fn.__name__, kwargs, first_line[:200])
        return result

    return wrapper


def _api_error(e: ApiException) -> str:
    """Return the API server's (or admission webhook's) own words."""
    try:
        body = json.loads(e.body)
        return f"{e.status} {body.get('reason', e.reason)}: {body.get('message', '')}"
    except Exception:
        return f"{e.status} {e.reason}: {e.body}"


def _dump(obj: Any) -> str:
    return yaml.safe_dump(obj, sort_keys=False, default_flow_style=False).rstrip()


def _age(ts: dt.datetime | None) -> str:
    if not ts:
        return "?"
    secs = int((dt.datetime.now(dt.timezone.utc) - ts).total_seconds())
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= size:
            return f"{secs // size}{unit}"
    return f"{secs}s"


def _ttl_seconds(ttl: str) -> int:
    return int(ttl[:-1]) * (60 if ttl.endswith("m") else 3600)


# --------------------------------------------------------------------------
# MCP server
# --------------------------------------------------------------------------
mcp = MCPServer(
    name="namespace-agent",
    instructions=(
        "Provision and inspect team namespaces ('environments') on the "
        "mcp-guardrails Kubernetes cluster. You can only create namespaces "
        "named team-<team>-<env>-<id> for env in dev|staging|preview|sandbox. "
        "Every environment is created with a quota, limit range, default-deny "
        "network policy, Pod Security 'restricted' and a TTL by the cluster "
        "itself. In gitops mode create_environment opens a pull request that a "
        "human must approve; report the PR link and diff to the user. If the "
        "cluster rejects something, report the rejection verbatim -- do not "
        "try to work around guardrails."
    ),
)


@mcp.tool()
@audited
def whoami() -> str:
    """Show the agent's cluster identity, write mode, and what it may do."""
    checks = {
        "list namespaces": _can("list", "namespaces"),
        "create namespaces": _can("create", "namespaces"),
        "delete namespaces": _can("delete", "namespaces"),
        "create clusterrolebindings": _can("create", "clusterrolebindings", "rbac.authorization.k8s.io"),
        "read secrets": _can("get", "secrets"),
    }
    return _dump({
        "identity": IDENTITY,
        "write_mode": WRITE_MODE,
        "write_path": (f"pull request to {GITEA_URL}/{GITEA_REPO}, applied by "
                       f"{_gitops_status().get('engine', 'gitops')} (as agents/gitops-applier) after review"
                       if WRITE_MODE == "gitops" else "direct API create, through admission control"),
        "raw_apply_enabled": RAW_APPLY,
        "permissions": checks,
    })


@mcp.tool()
@audited
def list_environments() -> str:
    """List agent-provisioned namespaces with owner, TTL, age and source."""
    nss = core.list_namespace(label_selector="provisioned-via").items
    rows = []
    for ns in sorted(nss, key=lambda n: n.metadata.name):
        lab = ns.metadata.labels or {}
        ttl = lab.get("ttl", "")
        created = ns.metadata.creation_timestamp
        expires = ""
        if ttl and TTL_RE.match(ttl) and created:
            remaining = _ttl_seconds(ttl) - int((dt.datetime.now(dt.timezone.utc) - created).total_seconds())
            expires = "expired" if remaining <= 0 else f"in {_age(dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=remaining))}"
        rows.append({
            "name": ns.metadata.name,
            "status": ns.status.phase,
            "owner": lab.get("owner"),
            "cost_center": lab.get("cost-center"),
            "ttl": ttl,
            "expires": expires or "n/a",
            "provisioned_via": lab.get("provisioned-via"),
            "age": _age(created),
        })
    if not rows:
        return "No agent-provisioned environments."
    return _dump({"environments": rows})


@mcp.tool()
@audited
def describe_environment(name: str) -> str:
    """Show one environment and its guardrails: labels, Pod Security level,
    ResourceQuota usage, LimitRange, NetworkPolicies, RoleBindings and pods."""
    try:
        ns = core.read_namespace(name)
    except ApiException as e:
        return f"Cannot read namespace {name}: {_api_error(e)}"
    lab = ns.metadata.labels or {}
    out: dict[str, Any] = {
        "name": name,
        "status": ns.status.phase,
        "age": _age(ns.metadata.creation_timestamp),
        "labels": lab,
        "pod_security": lab.get("pod-security.kubernetes.io/enforce", "NOT SET"),
        "ttl_cleanup": lab.get("cleanup.kyverno.io/ttl", "not scheduled (gitops-managed: expire by removing the file in git)"
                              if lab.get("provisioned-via") == "gitops" else "NOT SET"),
    }
    try:
        out["resource_quotas"] = [
            {"name": q.metadata.name, "hard": q.status.hard or q.spec.hard, "used": q.status.used or {}}
            for q in core.list_namespaced_resource_quota(name).items
        ] or "NONE"
        out["limit_ranges"] = [
            {"name": l.metadata.name, "limits": [api_client.sanitize_for_serialization(x) for x in l.spec.limits]}
            for l in core.list_namespaced_limit_range(name).items
        ] or "NONE"
        out["network_policies"] = [
            {"name": p.metadata.name, "pod_selector": p.spec.pod_selector.match_labels or "all pods",
             "policy_types": p.spec.policy_types}
            for p in networking.list_namespaced_network_policy(name).items
        ] or "NONE"
        out["role_bindings"] = [
            {"name": b.metadata.name, "role": f"{b.role_ref.kind}/{b.role_ref.name}",
             "subjects": [f"{s.kind}:{(s.namespace + '/') if s.namespace else ''}{s.name}" for s in (b.subjects or [])]}
            for b in rbac.list_namespaced_role_binding(name).items
        ]
        out["pods"] = [
            {"name": p.metadata.name, "phase": p.status.phase} for p in core.list_namespaced_pod(name).items
        ]
    except ApiException as e:
        out["error"] = _api_error(e)
    return _dump(out)


@mcp.tool()
@audited
def list_pods(namespace: str) -> str:
    """List pods in a namespace with phase, restarts and age."""
    try:
        pods = core.list_namespaced_pod(namespace).items
    except ApiException as e:
        return _api_error(e)
    if not pods:
        return f"No pods in {namespace}."
    return _dump([{
        "name": p.metadata.name,
        "phase": p.status.phase,
        "restarts": sum(c.restart_count for c in (p.status.container_statuses or [])),
        "age": _age(p.metadata.creation_timestamp),
    } for p in pods])


@mcp.tool()
@audited
def get_events(namespace: str, limit: int = 20) -> str:
    """Recent events in a namespace (newest last)."""
    try:
        evs = core.list_namespaced_event(namespace).items
    except ApiException as e:
        return _api_error(e)
    evs.sort(key=lambda e: e.last_timestamp or e.event_time or e.metadata.creation_timestamp)
    return _dump([{
        "type": e.type, "reason": e.reason,
        "object": f"{e.involved_object.kind}/{e.involved_object.name}",
        "message": e.message,
    } for e in evs[-max(1, min(limit, 100)):]]) or f"No events in {namespace}."


# --------------------------------------------------------------------------
# Git (Gitea) helpers for the gitops write path
# --------------------------------------------------------------------------


def _gitea() -> httpx.Client:
    if not GITEA_TOKEN_FILE:
        raise RuntimeError("GITEA_TOKEN_FILE is not set; gitops mode needs the agent's git token")
    with open(GITEA_TOKEN_FILE) as fh:
        token = fh.read().strip()
    return httpx.Client(base_url=f"{GITEA_URL}/api/v1", timeout=20,
                        headers={"Authorization": f"token {token}"})


def _check(r: httpx.Response) -> Any:
    if r.status_code >= 400:
        raise RuntimeError(f"git server: {r.request.method} {r.request.url.path} -> {r.status_code} {r.text[:300]}")
    return r.json() if r.content else None


def _argocd_status() -> dict[str, Any] | None:
    """Status of the Argo CD Application 'tenants', or None if Argo isn't the engine."""
    try:
        app = custom.get_namespaced_custom_object("argoproj.io", "v1alpha1", "argocd", "applications", "tenants")
    except ApiException as e:
        if e.status == 404:
            return None
        return {"engine": "argocd", "error": _api_error(e)}
    st = app.get("status", {})
    op = st.get("operationState", {})
    return {
        "engine": "argocd",
        "sync": st.get("sync", {}).get("status"),
        "health": st.get("health", {}).get("status"),
        "revision": op.get("syncResult", {}).get("revision") or st.get("sync", {}).get("revision"),
        "phase": op.get("phase"),
        "message": (op.get("message") or "")[:300],
        "conditions": [c.get("message", "")[:300] for c in st.get("conditions", [])],
    }


def _flux_status() -> dict[str, Any]:
    out: dict[str, Any] = {"engine": "flux"}
    for key, plural, group in (("gitrepository", "gitrepositories", "source.toolkit.fluxcd.io"),
                               ("kustomization", "kustomizations", "kustomize.toolkit.fluxcd.io")):
        try:
            obj = custom.get_namespaced_custom_object(group, "v1", "agents", plural, "tenants")
            ready = next((c for c in obj.get("status", {}).get("conditions", []) if c["type"] == "Ready"), {})
            out[key] = {
                "ready": ready.get("status"),
                "revision": obj.get("status", {}).get("lastAppliedRevision") or obj.get("status", {}).get("artifact", {}).get("revision"),
                "message": ready.get("message", "")[:300],
            }
        except ApiException as e:
            out[key] = _api_error(e)
    return out


def _gitops_status() -> dict[str, Any]:
    """Whichever engine applies the tenants repo: Argo CD if present, else Flux."""
    return _argocd_status() or _flux_status()


@mcp.tool()
@audited
def get_change_request(number: int) -> str:
    """Status of an environment pull request: review state, merge, GitOps (Flux or Argo CD) sync,
    and whether the namespace now exists with its guardrails."""
    with _gitea() as g:
        pr = _check(g.get(f"/repos/{GITEA_REPO}/pulls/{number}"))
        reviews = _check(g.get(f"/repos/{GITEA_REPO}/pulls/{number}/reviews")) or []
        files = _check(g.get(f"/repos/{GITEA_REPO}/pulls/{number}/files")) or []
    out: dict[str, Any] = {
        "pr": pr["html_url"],
        "title": pr["title"],
        "state": pr["state"],
        "merged": pr.get("merged", False),
        "reviews": [{"by": r["user"]["login"], "state": r["state"]} for r in reviews],
        "gitops": _gitops_status(),
    }
    for f in files:
        m = re.match(r"^tenants/(team-[a-z0-9-]+)\.yaml$", f["filename"])
        if m:
            try:
                core.read_namespace(m.group(1))
                out["namespace"] = f"{m.group(1)} exists"
            except ApiException as e:
                out["namespace"] = f"{m.group(1)}: {'not created yet' if e.status == 404 else _api_error(e)}"
    return _dump(out)


# --------------------------------------------------------------------------
# The one write tool
# --------------------------------------------------------------------------


def _render_namespace(name: str, team: str, env: str, owner: str, cost_center: str, ttl: str, reason: str) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": name,
            "labels": {
                "team": team,
                "env": env,
                "owner": owner,
                "cost-center": cost_center,
                "ttl": ttl,
                "provisioned-via": WRITE_MODE,
                "app.kubernetes.io/managed-by": "namespace-agent-mcp",
            },
            "annotations": {
                "agents.example.com/requested-by": IDENTITY["username"],
                "agents.example.com/reason": reason[:500],
            },
        },
    }


def _admission_preview(manifest: dict) -> tuple[bool, str, dict | None]:
    """Server-side dry run: RBAC + every admission webhook, nothing persisted."""
    try:
        res = core.create_namespace(manifest, dry_run="All")
        return True, "allowed", api_client.sanitize_for_serialization(res)
    except ApiException as e:
        return False, _api_error(e), None


@mcp.tool()
@audited
def create_environment(team: str, env: str, owner: str, cost_center: str,
                       ttl: str = "4h", reason: str = "") -> str:
    """Request a new team environment (namespace).

    The namespace is named team-<team>-<env>-<random id>. env must be one of
    dev, staging, preview, sandbox. ttl is how long it lives, e.g. 30m or 4h
    (max 999h). The cluster adds a ResourceQuota, LimitRange, default-deny
    NetworkPolicy, Pod Security 'restricted' and an agent RoleBinding itself.

    In gitops mode (default) this opens a pull request and returns its link and
    diff; a human reviewer must approve and merge it before the GitOps engine (Flux or Argo CD) applies it.
    In direct mode (sandbox clusters only) the namespace is created immediately.
    """
    problems = []
    if not TEAM_RE.match(team or ""):
        problems.append("team must be 2-12 lowercase letters/digits")
    if env not in ENVS:
        problems.append(f"env must be one of {', '.join(ENVS)} (production is never agent-provisioned)")
    if not TTL_RE.match(ttl or ""):
        problems.append("ttl must look like 30m or 4h (1m..999h)")
    for label, value in (("owner", owner), ("cost_center", cost_center)):
        if not LABEL_VALUE_RE.match(value or ""):
            problems.append(f"{label} must be a valid lowercase label value")
    if problems:
        return "REJECTED (input validation, nothing sent): " + "; ".join(problems)

    suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6))
    name = f"team-{team}-{env}-{suffix}"
    manifest = _render_namespace(name, team, env, owner, cost_center, ttl, reason)
    rendered = yaml.safe_dump(manifest, sort_keys=False)

    allowed, verdict, mutated = _admission_preview(manifest)
    if not allowed:
        return f"REJECTED by the cluster (server-side dry run, nothing created or committed):\n{verdict}"
    added = {k: v for k, v in ((mutated or {}).get("metadata", {}).get("labels", {}) or {}).items()
             if k not in manifest["metadata"]["labels"] and k != "kubernetes.io/metadata.name"}

    if WRITE_MODE == "direct":
        try:
            core.create_namespace(manifest)
        except ApiException as e:
            return f"REJECTED by the cluster:\n{_api_error(e)}"
        return _dump({
            "result": f"CREATED namespace {name} (direct mode)",
            "admission_added_labels": added,
            "note": "Kyverno is generating quota, limitrange, default-deny netpol and rolebinding; "
                    f"check with describe_environment('{name}'). Expires after {ttl}.",
        })

    # ---- gitops: branch, commit, PR -------------------------------------
    branch = f"agent/{name}"
    path = f"tenants/{name}.yaml"
    body = (
        f"Requested by `{IDENTITY['username']}` via the namespace-agent MCP server.\n\n"
        f"**Reason:** {reason or '(none given)'}\n\n"
        f"| field | value |\n|---|---|\n| team | {team} |\n| env | {env} |\n"
        f"| owner | {owner} |\n| cost-center | {cost_center} |\n| ttl | {ttl} |\n\n"
        "**Admission preview** (server-side dry run as the agent): allowed.\n"
        f"Kyverno will add: `{', '.join(f'{k}={v}' for k, v in added.items()) or 'nothing'}` and generate "
        "ResourceQuota `default-quota`, LimitRange `default-limits`, NetworkPolicy `default-deny-all`, "
        "RoleBinding `namespace-agent-workloads`.\n\n"
        "After merge the GitOps engine (Flux or Argo CD) applies this as `agents/gitops-applier`. "
        "To expire it, delete the file in a new PR."
    )
    with _gitea() as g:
        _check(g.post(f"/repos/{GITEA_REPO}/branches", json={"new_branch_name": branch, "old_branch_name": "main"}))
        _check(g.post(f"/repos/{GITEA_REPO}/contents/{path}", json={
            "branch": branch,
            "content": base64.b64encode(rendered.encode()).decode(),
            "message": f"Add environment {name}\n\nRequested-by: {IDENTITY['username']}",
            "author": {"name": "namespace-agent", "email": "namespace-agent@example.com"},
        }))
        pr = _check(g.post(f"/repos/{GITEA_REPO}/pulls", json={
            "head": branch, "base": "main",
            "title": f"Add environment {name}",
            "body": body,
        }))
        diff = g.get(f"/repos/{GITEA_REPO}/pulls/{pr['number']}.diff").text
    return (
        f"PULL REQUEST OPENED (not applied yet): {pr['html_url']}\n"
        f"PR number: {pr['number']}  namespace: {name}\n"
        "A platform reviewer must approve and merge it; the GitOps engine then applies it. "
        f"Track it with get_change_request({pr['number']}).\n"
        f"TTL: gitops-managed namespaces are NOT auto-deleted by the cluster (the GitOps engine would recreate them); "
        f"the {ttl} ttl label is recorded for the owner, and the environment is expired by a PR that "
        f"deletes tenants/{name}.yaml, after which the GitOps engine prunes it.\n\n"
        f"Admission preview: allowed. Kyverno will add labels: {added}\n\n"
        f"Diff:\n{diff}"
    )


# --------------------------------------------------------------------------
# Red-team only: raw passthrough. Shows that the cluster, not this server,
# says no. Never enable this outside a guardrail test.
# --------------------------------------------------------------------------
if RAW_APPLY:
    _dyn = dynamic.DynamicClient(api_client)

    @mcp.tool()
    @audited
    def apply_manifest(manifest_yaml: str) -> str:
        """[RED-TEAM MODE] Create arbitrary Kubernetes objects with the agent's
        own credentials. Exists only to prove the cluster guardrails hold even
        when an agent has a raw write path."""
        results = []
        for doc in yaml.safe_load_all(manifest_yaml):
            if not doc:
                continue
            kind, name = doc.get("kind"), doc.get("metadata", {}).get("name")
            try:
                res = _dyn.resources.get(api_version=doc["apiVersion"], kind=kind)
                res.create(body=doc, namespace=doc.get("metadata", {}).get("namespace"))
                results.append(f"{kind}/{name}: CREATED")
            except ApiException as e:
                results.append(f"{kind}/{name}: REJECTED {_api_error(e)}")
            except Exception as e:  # noqa: BLE001
                results.append(f"{kind}/{name}: ERROR {e}")
        return "\n".join(results) or "no objects in manifest"

    @mcp.tool()
    @audited
    def delete_namespace(name: str) -> str:
        """[RED-TEAM MODE] Try to delete a namespace with the agent's credentials."""
        try:
            core.delete_namespace(name)
            return f"Namespace/{name}: DELETED"
        except ApiException as e:
            return f"Namespace/{name}: REJECTED {_api_error(e)}"


if __name__ == "__main__":
    print(f"namespace-agent MCP server: identity={IDENTITY['username']} mode={WRITE_MODE} "
          f"raw_apply={RAW_APPLY}", file=sys.stderr)
    mcp.run("stdio")
