# tenants

Desired state for agent-provisioned namespaces. Flux reconciles `tenants/`
into the cluster as the `agents/gitops-applier` identity.

- One file per namespace: `tenants/<namespace>.yaml`
- Agents open pull requests; `platform-admin` (CODEOWNERS) reviews and merges.
- To expire an environment, open a PR deleting its file; Flux prunes it.
- Quota, LimitRange, NetworkPolicy, PSA and RoleBinding are *not* in git:
  Kyverno generates them at admission, so they cannot be forgotten.
