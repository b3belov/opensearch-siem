# OpenSearch SIEM GitOps

Git is the source of truth for customers, credentials metadata, allowlists, sources, retention, routing, OpenSearch templates, ISM policies, and OpenSearch security objects.

Edit files under `gitops/desired/**`, run validation, render generated artifacts, review the diff, and then apply through the reconciler.

Runtime services mount `gitops/rendered/**`. They do not mount `gitops/desired/**` directly.

Plaintext secrets are not committed. Desired state stores secret references only.
