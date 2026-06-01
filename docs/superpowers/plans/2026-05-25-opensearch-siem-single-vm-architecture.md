# OpenSearch SIEM Single-VM Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the version-one single-VM, multi-customer OpenSearch SIEM foundation with relay-only ingestion, GitOps-managed tenant config, central Logstash persistent queues, customer-scoped data streams, and internal-only Dashboards.

**Architecture:** Customer networks run local Logstash forwarders that send outbound to central Logstash. The central Docker host runs one properly sized OpenSearch node, internal OpenSearch Dashboards, GitOps validation/rendering jobs, and optional backup jobs. GitOps desired state generates Logstash routing, OpenSearch templates, retention policies, roles, and relay bundles.

**Tech Stack:** Docker Compose, OpenSearch 3.6.0, OpenSearch Dashboards 3.6.0, Logstash OSS with OpenSearch output plugin, Python 3.12, PyYAML, jsonschema, Jinja2, pytest, Bash, SOPS/age-compatible secret references, S3-compatible snapshot storage.

---

## Source Spec

Implement from:

- `docs/superpowers/specs/2026-05-25-opensearch-siem-single-vm-architecture-design.md`

## Scope Boundaries

In scope:

- single-node central OpenSearch deployment
- internal-only OpenSearch Dashboards
- relay-only customer ingestion
- one central-ingest credential per customer
- source IP/CIDR allowlisting as an additional control
- central Logstash persistent queues
- customer/dataset data streams with readable customer slugs
- GitOps desired-state validation and rendering
- OpenSearch reconciler for templates, ISM policies, roles, role mappings, and initial data streams
- customer relay bundle generation
- optional S3-compatible backup configuration
- operator documentation and validation scripts

Out of scope:

- direct customer device ingest to central SIEM
- customer Dashboards access
- SOAR/case-management services
- Redpanda, Kafka, or another broker
- multi-VM OpenSearch cluster
- per-customer OpenSearch clusters
- PostgreSQL or an admin API as the source of truth
- plaintext secrets in Git

## Target File Structure

Create:

```text
.gitignore
docker-compose.yml
requirements-gitops.txt

ingest-edge/Dockerfile
ingest-edge/app.py
ingest-edge/requirements.txt

gitops/README.md
gitops/schemas/customer.schema.json
gitops/schemas/customer-credential.schema.json
gitops/schemas/allowlist.schema.json
gitops/schemas/source.schema.json
gitops/schemas/retention-policy.schema.json
gitops/schemas/service-account.schema.json
gitops/schemas/backup.schema.json
gitops/desired/global/retention-policies.yml
gitops/desired/global/service-accounts.yml
gitops/desired/global/backup.yml
gitops/desired/customers/acme/customer.yml
gitops/desired/customers/acme/credentials.yml
gitops/desired/customers/acme/allowlist.yml
gitops/desired/customers/acme/sources/firewall.yml
gitops/desired/customers/acme/sources/windows.yml
gitops/rendered/.gitkeep

scripts/lib/__init__.py
scripts/lib/gitops_config.py
scripts/lib/test_helpers.sh
scripts/validate-gitops-config.py
scripts/render-gitops-config.py
scripts/reconcile-opensearch-gitops.py
scripts/generate-relay-bundle.sh
scripts/setup-local-secrets.sh
scripts/test-gitops-config.sh
scripts/test-rendered-gitops-config.sh
scripts/test-target-compose.sh
scripts/test-logstash-config.sh
scripts/test-opensearch-reconciler.sh
scripts/test-relay-bundle.sh
scripts/test-secret-ignore.sh
scripts/test-ingest-edge.sh

logstash/config/logstash.yml
logstash/config/pipelines.yml
logstash/pipeline/00-relay-input.conf
logstash/pipeline/10-route-and-enrich.conf
logstash/pipeline/20-normalize.conf
logstash/pipeline/90-opensearch-output.conf
logstash/templates/customer-auth.yml.j2
logstash/templates/source-routing.yml.j2

opensearch/base/index-templates/logs-template.json
opensearch/base/index-templates/alerts-template.json
opensearch/base/ism/critical-30d.json
opensearch/base/ism/standard-7d.json
opensearch/base/ism/noisy-3d.json
opensearch/base/ism/quarantine-7d.json
opensearch/base/security/logstash-writer-role.json.j2
opensearch/base/security/soc-admin-role.json.j2

relay/templates/logstash.yml.j2
relay/templates/pipeline.conf.j2

backup/Dockerfile
backup/backup-opensearch.sh
backup/backup-gitops-repo.sh

docs/opensearch-siem-operations.md
```

## Task 1: Add Git Ignore And Python Dependency Foundation

**Files:**
- Create: `.gitignore`
- Create: `requirements-gitops.txt`
- Create: `scripts/lib/__init__.py`
- Create: `scripts/lib/test_helpers.sh`
- Create: `scripts/test-secret-ignore.sh`

- [ ] **Step 1: Create the secret-ignore regression test**

Create `scripts/test-secret-ignore.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

paths=(
  ".env"
  "secrets/local/admin-password"
  "secrets/local/customer-acme-password"
  "secrets/certs/central.key"
  "secrets/certs/central.crt"
  "relay/bundles/acme-forwarder.tar.gz"
  "gitops/rendered/secrets/decrypted.yml"
)

for path in "${paths[@]}"; do
  if ! git check-ignore -q "$path"; then
    echo "not ignored: $path" >&2
    exit 1
  fi
done

echo "secret ignore checks passed"
```

- [ ] **Step 2: Run the test and confirm it fails before `.gitignore` exists**

Run: `bash scripts/test-secret-ignore.sh`

Expected: FAIL with `not ignored: .env`.

- [ ] **Step 3: Create `.gitignore`**

Create `.gitignore`:

```gitignore
.DS_Store
__pycache__/
.pytest_cache/
.venv/

.env
secrets/local/
secrets/certs/*.key
secrets/certs/*.crt
relay/bundles/
gitops/rendered/secrets/

data/opensearch/
logs/
tmp/
```

- [ ] **Step 4: Create Python dependency manifest**

Create `requirements-gitops.txt`:

```text
Jinja2==3.1.4
jsonschema==4.23.0
PyYAML==6.0.2
requests==2.32.3
pytest==8.3.3
```

- [ ] **Step 5: Create shared shell helpers**

Create `scripts/lib/test_helpers.sh`:

```bash
#!/usr/bin/env bash

repo_root() {
  cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd
}

assert_file_exists() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "missing file: $path" >&2
    return 1
  fi
}

assert_contains() {
  local path="$1"
  local pattern="$2"
  if ! grep -Eq "$pattern" "$path"; then
    echo "missing pattern '$pattern' in $path" >&2
    return 1
  fi
}
```

- [ ] **Step 6: Create Python package marker**

Create `scripts/lib/__init__.py`:

```python
"""Shared helpers for OpenSearch SIEM GitOps tooling."""
```

- [ ] **Step 7: Run the ignore test**

Run: `bash scripts/test-secret-ignore.sh`

Expected: PASS with `secret ignore checks passed`.

- [ ] **Step 8: Commit**

```bash
git add .gitignore requirements-gitops.txt scripts/lib/__init__.py scripts/lib/test_helpers.sh scripts/test-secret-ignore.sh
git commit -m "chore: add gitops tooling foundation"
```

## Task 2: Add GitOps Desired-State Schemas And Example Customer

**Files:**
- Create: `gitops/schemas/customer.schema.json`
- Create: `gitops/schemas/customer-credential.schema.json`
- Create: `gitops/schemas/allowlist.schema.json`
- Create: `gitops/schemas/source.schema.json`
- Create: `gitops/schemas/retention-policy.schema.json`
- Create: `gitops/schemas/service-account.schema.json`
- Create: `gitops/schemas/backup.schema.json`
- Create: `gitops/desired/global/retention-policies.yml`
- Create: `gitops/desired/global/service-accounts.yml`
- Create: `gitops/desired/global/backup.yml`
- Create: `gitops/desired/customers/acme/customer.yml`
- Create: `gitops/desired/customers/acme/credentials.yml`
- Create: `gitops/desired/customers/acme/allowlist.yml`
- Create: `gitops/desired/customers/acme/sources/firewall.yml`
- Create: `gitops/desired/customers/acme/sources/windows.yml`
- Create: `gitops/rendered/.gitkeep`
- Create: `gitops/README.md`

- [ ] **Step 1: Create schema directory and desired-state directories**

Run:

```bash
mkdir -p gitops/schemas \
  gitops/desired/global \
  gitops/desired/customers/acme/sources \
  gitops/rendered
touch gitops/rendered/.gitkeep
```

Expected: command exits 0.

- [ ] **Step 2: Create customer schema**

Create `gitops/schemas/customer.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["apiVersion", "kind", "slug", "name", "enabled"],
  "additionalProperties": false,
  "properties": {
    "apiVersion": { "const": "siem.local/v1" },
    "kind": { "const": "Customer" },
    "slug": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,30}[a-z0-9]$" },
    "name": { "type": "string", "minLength": 1 },
    "enabled": { "type": "boolean" }
  }
}
```

- [ ] **Step 3: Create credential schema**

Create `gitops/schemas/customer-credential.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["apiVersion", "kind", "customer", "credentials"],
  "additionalProperties": false,
  "properties": {
    "apiVersion": { "const": "siem.local/v1" },
    "kind": { "const": "CustomerCredentialList" },
    "customer": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,30}[a-z0-9]$" },
    "credentials": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "required": ["id", "enabled", "secretRef"],
        "additionalProperties": false,
        "properties": {
          "id": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,40}$" },
          "enabled": { "type": "boolean" },
          "secretRef": { "type": "string", "pattern": "^secrets/local/[a-z0-9-]+$" }
        }
      }
    }
  }
}
```

- [ ] **Step 4: Create allowlist schema**

Create `gitops/schemas/allowlist.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["apiVersion", "kind", "customer", "entries"],
  "additionalProperties": false,
  "properties": {
    "apiVersion": { "const": "siem.local/v1" },
    "kind": { "const": "CustomerAllowlist" },
    "customer": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,30}[a-z0-9]$" },
    "entries": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["cidr", "description"],
        "additionalProperties": false,
        "properties": {
          "cidr": { "type": "string", "pattern": "^[0-9a-fA-F:.]+/[0-9]{1,3}$" },
          "description": { "type": "string", "minLength": 1 }
        }
      }
    }
  }
}
```

- [ ] **Step 5: Create source schema**

Create `gitops/schemas/source.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["apiVersion", "kind", "customer", "id", "name", "dataset", "parser", "retentionPolicy", "priority", "enabled"],
  "additionalProperties": false,
  "properties": {
    "apiVersion": { "const": "siem.local/v1" },
    "kind": { "const": "Source" },
    "customer": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,30}[a-z0-9]$" },
    "id": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,40}$" },
    "name": { "type": "string", "minLength": 1 },
    "dataset": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,40}$" },
    "parser": { "type": "string", "enum": ["generic-syslog", "windows-json", "passthrough"] },
    "retentionPolicy": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,40}$" },
    "priority": { "type": "string", "enum": ["critical", "standard", "noisy"] },
    "dailyVolumeBudgetGb": { "type": "number", "minimum": 0 },
    "enabled": { "type": "boolean" }
  }
}
```

- [ ] **Step 6: Create global schemas**

Create `gitops/schemas/retention-policy.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["apiVersion", "kind", "policies"],
  "additionalProperties": false,
  "properties": {
    "apiVersion": { "const": "siem.local/v1" },
    "kind": { "const": "RetentionPolicyList" },
    "policies": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "required": ["name", "days", "priority"],
        "additionalProperties": false,
        "properties": {
          "name": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,40}$" },
          "days": { "type": "integer", "minimum": 1, "maximum": 90 },
          "priority": { "type": "string", "enum": ["critical", "standard", "noisy", "quarantine"] }
        }
      }
    }
  }
}
```

Create `gitops/schemas/service-account.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["apiVersion", "kind", "accounts"],
  "additionalProperties": false,
  "properties": {
    "apiVersion": { "const": "siem.local/v1" },
    "kind": { "const": "ServiceAccountList" },
    "accounts": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["name", "role", "secretRef"],
        "additionalProperties": false,
        "properties": {
          "name": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,40}$" },
          "role": { "type": "string", "enum": ["logstash-writer", "gitops-reconciler", "backup-writer", "soc-admin"] },
          "secretRef": { "type": "string", "pattern": "^secrets/local/[a-z0-9-]+$" }
        }
      }
    }
  }
}
```

Create `gitops/schemas/backup.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["apiVersion", "kind", "enabled", "repository"],
  "additionalProperties": false,
  "properties": {
    "apiVersion": { "const": "siem.local/v1" },
    "kind": { "const": "BackupConfig" },
    "enabled": { "type": "boolean" },
    "repository": {
      "type": "object",
      "required": ["type", "name", "bucket", "basePath"],
      "additionalProperties": false,
      "properties": {
        "type": { "const": "s3" },
        "name": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,40}$" },
        "bucket": { "type": "string", "minLength": 1 },
        "basePath": { "type": "string", "minLength": 1 }
      }
    }
  }
}
```

- [ ] **Step 7: Create desired-state examples**

Create `gitops/desired/global/retention-policies.yml`:

```yaml
apiVersion: siem.local/v1
kind: RetentionPolicyList
policies:
  - name: critical-30d
    days: 30
    priority: critical
  - name: standard-7d
    days: 7
    priority: standard
  - name: noisy-3d
    days: 3
    priority: noisy
  - name: quarantine-7d
    days: 7
    priority: quarantine
```

Create `gitops/desired/global/service-accounts.yml`:

```yaml
apiVersion: siem.local/v1
kind: ServiceAccountList
accounts:
  - name: logstash-writer
    role: logstash-writer
    secretRef: secrets/local/logstash-writer-password
  - name: gitops-reconciler
    role: gitops-reconciler
    secretRef: secrets/local/gitops-reconciler-password
  - name: backup-writer
    role: backup-writer
    secretRef: secrets/local/backup-writer-password
```

Create `gitops/desired/global/backup.yml`:

```yaml
apiVersion: siem.local/v1
kind: BackupConfig
enabled: false
repository:
  type: s3
  name: siem-snapshots
  bucket: opensearch-siem-snapshots
  basePath: single-vm
```

Create `gitops/desired/customers/acme/customer.yml`:

```yaml
apiVersion: siem.local/v1
kind: Customer
slug: acme
name: Acme Corp
enabled: true
```

Create `gitops/desired/customers/acme/credentials.yml`:

```yaml
apiVersion: siem.local/v1
kind: CustomerCredentialList
customer: acme
credentials:
  - id: acme-primary
    enabled: true
    secretRef: secrets/local/customer-acme-password
```

Create `gitops/desired/customers/acme/allowlist.yml`:

```yaml
apiVersion: siem.local/v1
kind: CustomerAllowlist
customer: acme
entries:
  - cidr: 203.0.113.10/32
    description: Acme primary office forwarder
```

Create `gitops/desired/customers/acme/sources/firewall.yml`:

```yaml
apiVersion: siem.local/v1
kind: Source
customer: acme
id: firewall
name: Acme firewall syslog
dataset: firewall
parser: generic-syslog
retentionPolicy: critical-30d
priority: critical
dailyVolumeBudgetGb: 2
enabled: true
```

Create `gitops/desired/customers/acme/sources/windows.yml`:

```yaml
apiVersion: siem.local/v1
kind: Source
customer: acme
id: windows
name: Acme Windows events
dataset: windows
parser: windows-json
retentionPolicy: standard-7d
priority: standard
dailyVolumeBudgetGb: 3
enabled: true
```

- [ ] **Step 8: Create GitOps README**

Create `gitops/README.md`:

```markdown
# OpenSearch SIEM GitOps

Git is the source of truth for customers, credentials metadata, allowlists, sources, retention, routing, OpenSearch templates, ISM policies, and OpenSearch security objects.

Edit files under `gitops/desired/**`, run validation, render generated artifacts, review the diff, and then apply through the reconciler.

Runtime services mount `gitops/rendered/**`. They do not mount `gitops/desired/**` directly.

Plaintext secrets are not committed. Desired state stores secret references only.
```

- [ ] **Step 9: Commit**

```bash
git add gitops
git commit -m "feat: add gitops desired-state contracts"
```

## Task 3: Implement GitOps Loader And Validator

**Files:**
- Create: `scripts/lib/gitops_config.py`
- Create: `scripts/validate-gitops-config.py`
- Create: `scripts/test-gitops-config.sh`

- [ ] **Step 1: Write validator test**

Create `scripts/test-gitops-config.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 scripts/validate-gitops-config.py
echo "gitops config validation passed"
```

- [ ] **Step 2: Run validator test and confirm it fails before implementation**

Run: `bash scripts/test-gitops-config.sh`

Expected: FAIL with a Python error that `scripts/validate-gitops-config.py` is missing.

- [ ] **Step 3: Create shared GitOps loader**

Create `scripts/lib/gitops_config.py`:

```python
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network
from pathlib import Path
from typing import Any

import json
import yaml
from jsonschema import Draft202012Validator


REPO_ROOT = Path(__file__).resolve().parents[2]
DESIRED = REPO_ROOT / "gitops" / "desired"
SCHEMAS = REPO_ROOT / "gitops" / "schemas"


@dataclass(frozen=True)
class Customer:
    slug: str
    name: str
    enabled: bool
    path: Path


@dataclass(frozen=True)
class Source:
    customer: str
    id: str
    dataset: str
    parser: str
    retention_policy: str
    priority: str
    enabled: bool
    path: Path


def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected YAML mapping")
    return value


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def validate_schema(document: dict[str, Any], schema_name: str, path: Path) -> None:
    schema = read_json(SCHEMAS / schema_name)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    if errors:
        rendered = "; ".join(f"{'/'.join(map(str, error.path))}: {error.message}" for error in errors)
        raise ValueError(f"{path}: {rendered}")


def customer_dirs() -> list[Path]:
    root = DESIRED / "customers"
    return sorted(path for path in root.iterdir() if path.is_dir())


def load_customers() -> dict[str, Customer]:
    customers: dict[str, Customer] = {}
    for customer_dir in customer_dirs():
        path = customer_dir / "customer.yml"
        doc = read_yaml(path)
        validate_schema(doc, "customer.schema.json", path)
        slug = doc["slug"]
        if slug in customers:
            raise ValueError(f"duplicate customer slug: {slug}")
        if customer_dir.name != slug:
            raise ValueError(f"{path}: directory name must match slug {slug}")
        customers[slug] = Customer(slug=slug, name=doc["name"], enabled=doc["enabled"], path=path)
    return customers


def load_retention_policy_names() -> set[str]:
    path = DESIRED / "global" / "retention-policies.yml"
    doc = read_yaml(path)
    validate_schema(doc, "retention-policy.schema.json", path)
    names = [policy["name"] for policy in doc["policies"]]
    if len(names) != len(set(names)):
        raise ValueError(f"{path}: duplicate retention policy name")
    return set(names)


def load_sources(customers: dict[str, Customer], retention_names: set[str]) -> list[Source]:
    sources: list[Source] = []
    seen_streams: set[tuple[str, str]] = set()
    for customer_dir in customer_dirs():
        source_dir = customer_dir / "sources"
        for path in sorted(source_dir.glob("*.yml")):
            doc = read_yaml(path)
            validate_schema(doc, "source.schema.json", path)
            customer = doc["customer"]
            dataset = doc["dataset"]
            stream_key = (customer, dataset)
            if customer not in customers:
                raise ValueError(f"{path}: unknown customer {customer}")
            if doc["retentionPolicy"] not in retention_names:
                raise ValueError(f"{path}: unknown retention policy {doc['retentionPolicy']}")
            if not customers[customer].enabled and doc["enabled"]:
                raise ValueError(f"{path}: enabled source under disabled customer {customer}")
            if stream_key in seen_streams:
                raise ValueError(f"{path}: duplicate dataset {dataset} for customer {customer}")
            seen_streams.add(stream_key)
            sources.append(Source(
                customer=customer,
                id=doc["id"],
                dataset=dataset,
                parser=doc["parser"],
                retention_policy=doc["retentionPolicy"],
                priority=doc["priority"],
                enabled=doc["enabled"],
                path=path,
            ))
    return sources


def validate_customer_sidecars(customers: dict[str, Customer]) -> None:
    for customer_dir in customer_dirs():
        slug = customer_dir.name
        for path, schema_name in [
            (customer_dir / "credentials.yml", "customer-credential.schema.json"),
            (customer_dir / "allowlist.yml", "allowlist.schema.json"),
        ]:
            doc = read_yaml(path)
            validate_schema(doc, schema_name, path)
            if doc["customer"] != slug:
                raise ValueError(f"{path}: customer must be {slug}")
            if doc["customer"] not in customers:
                raise ValueError(f"{path}: unknown customer {doc['customer']}")
            if doc["kind"] == "CustomerAllowlist":
                for entry in doc["entries"]:
                    ip_network(entry["cidr"], strict=False)


def validate_global_files() -> None:
    service_accounts = DESIRED / "global" / "service-accounts.yml"
    backup = DESIRED / "global" / "backup.yml"
    validate_schema(read_yaml(service_accounts), "service-account.schema.json", service_accounts)
    validate_schema(read_yaml(backup), "backup.schema.json", backup)


def validate_all() -> None:
    validate_global_files()
    customers = load_customers()
    retention_names = load_retention_policy_names()
    validate_customer_sidecars(customers)
    load_sources(customers, retention_names)
```

- [ ] **Step 4: Create validator entrypoint**

Create `scripts/validate-gitops-config.py`:

```python
#!/usr/bin/env python3
from __future__ import annotations

from scripts.lib.gitops_config import validate_all


def main() -> None:
    validate_all()
    print("gitops config validation passed")


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Run validator**

Run: `bash scripts/test-gitops-config.sh`

Expected: PASS with `gitops config validation passed`.

- [ ] **Step 6: Commit**

```bash
git add scripts/lib/gitops_config.py scripts/validate-gitops-config.py scripts/test-gitops-config.sh
git commit -m "feat: validate gitops desired state"
```

## Task 4: Render Logstash And OpenSearch Runtime Artifacts

**Files:**
- Create: `logstash/templates/customer-auth.yml.j2`
- Create: `logstash/templates/source-routing.yml.j2`
- Create: `opensearch/base/security/logstash-writer-role.json.j2`
- Create: `scripts/render-gitops-config.py`
- Create: `scripts/test-rendered-gitops-config.sh`

- [ ] **Step 1: Create stale-render test**

Create `scripts/test-rendered-gitops-config.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

before="$(git status --porcelain)"
python3 scripts/render-gitops-config.py
after="$(git status --porcelain)"

if [[ "$before" != "$after" ]]; then
  echo "rendered artifacts are stale; run scripts/render-gitops-config.py and commit the result" >&2
  git status --short >&2
  exit 1
fi

test -f gitops/rendered/logstash/customer-auth.yml
test -f gitops/rendered/logstash/source-routing.yml
test -f gitops/rendered/ingest-edge/customer-auth.yml
test -f gitops/rendered/opensearch/index-templates/logs-acme-firewall-template.json
test -f gitops/rendered/opensearch/security/logstash-writer-role.json

echo "rendered gitops config is current"
```

- [ ] **Step 2: Run stale-render test and confirm it fails before renderer exists**

Run: `bash scripts/test-rendered-gitops-config.sh`

Expected: FAIL with Python error that `scripts/render-gitops-config.py` is missing.

- [ ] **Step 3: Create Logstash templates**

Create `logstash/templates/customer-auth.yml.j2`:

```jinja
customers:
{% for customer in customers %}
  {{ customer.slug }}:
    enabled: {{ customer.enabled | lower }}
    credential_ids:
{% for credential_id in credentials[customer.slug] %}
      - {{ credential_id }}
{% endfor %}
{% endfor %}
```

Create `logstash/templates/source-routing.yml.j2`:

```jinja
sources:
{% for source in sources %}
  {{ source.customer }}:{{ source.id }}:
    customer_slug: {{ source.customer }}
    source_id: {{ source.id }}
    dataset: {{ source.dataset }}
    stream: logs-{{ source.customer }}-{{ source.dataset }}
    quarantine_stream: logs-{{ source.customer }}-{{ source.dataset }}-quarantine
    parser: {{ source.parser }}
    retention_policy: {{ source.retention_policy }}
    priority: {{ source.priority }}
    enabled: {{ source.enabled | lower }}
{% endfor %}
```

- [ ] **Step 4: Create OpenSearch role template**

Create `opensearch/base/security/logstash-writer-role.json.j2`:

```jinja
{
  "cluster_permissions": [],
  "index_permissions": [
{% for stream in streams %}
    {
      "index_patterns": [
        "{{ stream }}",
        "{{ stream }}-*"
      ],
      "allowed_actions": [
        "indices:data/write/bulk",
        "indices:data/write/create",
        "indices:data/write/index",
        "indices:admin/create",
        "indices:admin/mapping/put"
      ]
    }{% if not loop.last %},{% endif %}
{% endfor %}
  ],
  "tenant_permissions": []
}
```

- [ ] **Step 5: Create renderer**

Create `scripts/render-gitops-config.py`:

```python
#!/usr/bin/env python3
from __future__ import annotations

import json
import yaml
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from scripts.lib.gitops_config import (
    DESIRED,
    REPO_ROOT,
    load_customers,
    load_retention_policy_names,
    load_sources,
    read_yaml,
    validate_all,
)


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value.rstrip() + "\n", encoding="utf-8")


def write_json(path: Path, value: dict[str, object]) -> None:
    write_text(path, json.dumps(value, indent=2, sort_keys=True))


def credential_ids_by_customer() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for customer_dir in sorted((DESIRED / "customers").iterdir()):
        if not customer_dir.is_dir():
            continue
        doc = read_yaml(customer_dir / "credentials.yml")
        result[doc["customer"]] = [item["id"] for item in doc["credentials"] if item["enabled"]]
    return result


def ingest_edge_credentials() -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for customer_dir in sorted((DESIRED / "customers").iterdir()):
        if not customer_dir.is_dir():
            continue
        credential_doc = read_yaml(customer_dir / "credentials.yml")
        allowlist_doc = read_yaml(customer_dir / "allowlist.yml")
        allowed_cidrs = [entry["cidr"] for entry in allowlist_doc["entries"]]
        for item in credential_doc["credentials"]:
            result[item["id"]] = {
                "customerSlug": credential_doc["customer"],
                "enabled": item["enabled"],
                "secretRef": item["secretRef"],
                "allowedCidrs": allowed_cidrs,
            }
    return result


def render() -> None:
    validate_all()
    customers = load_customers()
    retention_names = load_retention_policy_names()
    sources = load_sources(customers, retention_names)
    credentials = credential_ids_by_customer()

    env = Environment(
        loader=FileSystemLoader(str(REPO_ROOT)),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
    )

    customer_auth = env.get_template("logstash/templates/customer-auth.yml.j2").render(
        customers=customers.values(),
        credentials=credentials,
    )
    source_routing = env.get_template("logstash/templates/source-routing.yml.j2").render(sources=sources)

    streams = []
    for source in sources:
        streams.append(f"logs-{source.customer}-{source.dataset}")
        streams.append(f"logs-{source.customer}-{source.dataset}-quarantine")
    for customer in customers.values():
        streams.append(f"logs-{customer.slug}-unknown-quarantine")
        streams.append(f"alerts-{customer.slug}")

    role = env.get_template("opensearch/base/security/logstash-writer-role.json.j2").render(streams=sorted(streams))

    write_text(REPO_ROOT / "gitops/rendered/logstash/customer-auth.yml", customer_auth)
    write_text(REPO_ROOT / "gitops/rendered/logstash/source-routing.yml", source_routing)
    write_text(
        REPO_ROOT / "gitops/rendered/ingest-edge/customer-auth.yml",
        yaml.safe_dump({"credentials": ingest_edge_credentials()}, sort_keys=True),
    )
    write_text(REPO_ROOT / "gitops/rendered/opensearch/security/logstash-writer-role.json", role)
    write_text(
        REPO_ROOT / "gitops/rendered/opensearch/streams.yml",
        yaml.safe_dump({"streams": sorted(streams)}, sort_keys=True),
    )
    for source in sources:
        stream = f"logs-{source.customer}-{source.dataset}"
        write_json(
            REPO_ROOT / f"gitops/rendered/opensearch/index-templates/{stream}-template.json",
            {
                "index_patterns": [stream, f"{stream}-*"],
                "data_stream": {},
                "template": {
                    "settings": {
                        "index.number_of_shards": 1,
                        "index.number_of_replicas": 0,
                        "plugins.index_state_management.policy_id": source.retention_policy,
                    },
                    "mappings": {
                        "dynamic": True,
                        "properties": {
                            "@timestamp": {"type": "date"},
                            "customer": {"properties": {"slug": {"type": "keyword"}}},
                            "source": {"properties": {"id": {"type": "keyword"}}},
                            "event": {
                                "properties": {
                                    "dataset": {"type": "keyword"},
                                    "original": {"type": "wildcard"},
                                }
                            },
                        },
                    },
                },
                "priority": 300,
            },
        )
        write_json(
            REPO_ROOT / f"gitops/rendered/opensearch/index-templates/{stream}-quarantine-template.json",
            {
                "index_patterns": [f"{stream}-quarantine", f"{stream}-quarantine-*"],
                "data_stream": {},
                "template": {
                    "settings": {
                        "index.number_of_shards": 1,
                        "index.number_of_replicas": 0,
                        "plugins.index_state_management.policy_id": "quarantine-7d",
                    }
                },
                "priority": 300,
            },
        )
    for customer in customers.values():
        unknown_stream = f"logs-{customer.slug}-unknown-quarantine"
        write_json(
            REPO_ROOT / f"gitops/rendered/opensearch/index-templates/{unknown_stream}-template.json",
            {
                "index_patterns": [unknown_stream, f"{unknown_stream}-*"],
                "data_stream": {},
                "template": {
                    "settings": {
                        "index.number_of_shards": 1,
                        "index.number_of_replicas": 0,
                        "plugins.index_state_management.policy_id": "quarantine-7d",
                    }
                },
                "priority": 300,
            },
        )


def main() -> None:
    render()
    print("rendered gitops config")


if __name__ == "__main__":
    main()
```

- [ ] **Step 6: Run renderer**

Run: `python3 scripts/render-gitops-config.py`

Expected: PASS with `rendered gitops config`.

- [ ] **Step 7: Commit generated artifacts**

```bash
git add logstash/templates opensearch/base/security scripts/render-gitops-config.py scripts/test-rendered-gitops-config.sh gitops/rendered
git commit -m "feat: render gitops runtime artifacts"
```

- [ ] **Step 8: Verify stale-render guard passes after commit**

Run: `bash scripts/test-rendered-gitops-config.sh`

Expected: PASS with `rendered gitops config is current`.

## Task 5: Add Authenticated Ingest Edge And Logstash Runtime Config

**Files:**
- Create: `ingest-edge/Dockerfile`
- Create: `ingest-edge/app.py`
- Create: `ingest-edge/requirements.txt`
- Create: `docker-compose.yml`
- Create: `logstash/config/logstash.yml`
- Create: `logstash/config/pipelines.yml`
- Create: `logstash/pipeline/00-relay-input.conf`
- Create: `logstash/pipeline/10-route-and-enrich.conf`
- Create: `logstash/pipeline/20-normalize.conf`
- Create: `logstash/pipeline/90-opensearch-output.conf`
- Create: `scripts/test-ingest-edge.py`
- Create: `scripts/test-ingest-edge.sh`
- Create: `scripts/test-target-compose.sh`
- Create: `scripts/test-logstash-config.sh`

- [ ] **Step 1: Create Compose regression test**

Create `scripts/test-target-compose.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

docker compose config --quiet

rendered="$(docker compose config)"
if grep -q "opensearch-node2" <<<"$rendered"; then
  echo "target architecture must not define opensearch-node2" >&2
  exit 1
fi

if ! grep -q "opensearch:" <<<"$rendered"; then
  echo "missing single opensearch service" >&2
  exit 1
fi

if ! grep -q "central-logstash:" <<<"$rendered"; then
  echo "missing central-logstash service" >&2
  exit 1
fi

if ! grep -q "ingest-edge:" <<<"$rendered"; then
  echo "missing ingest-edge service" >&2
  exit 1
fi

if grep -q "5044:9601" <<<"$rendered"; then
  echo "central-logstash input must not be host-published" >&2
  exit 1
fi

if ! grep -q "INGEST_EDGE_TLS_CERT" <<<"$rendered"; then
  echo "ingest-edge must be configured for TLS" >&2
  exit 1
fi

if ! grep -q "INGEST_EDGE_MAX_BODY_BYTES" <<<"$rendered"; then
  echo "ingest-edge must set a request body limit" >&2
  exit 1
fi

echo "target compose config passed"
```

- [ ] **Step 2: Create Logstash config regression test**

Create `scripts/test-logstash-config.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

docker compose run --rm --no-deps central-logstash \
  logstash --path.settings /usr/share/logstash/config --config.test_and_exit

echo "logstash target config passed"
```

- [ ] **Step 3: Create ingest-edge requirements**

Create `ingest-edge/requirements.txt`:

```text
PyYAML==6.0.2
requests==2.32.3
```

- [ ] **Step 4: Create ingest-edge app**

Create `ingest-edge/app.py`:

```python
#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import secrets
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

import requests
import yaml


CONFIG_PATH = Path(os.environ.get("INGEST_EDGE_CONFIG", "/app/config/customer-auth.yml"))
SECRET_ROOT = Path(os.environ.get("INGEST_EDGE_SECRET_ROOT", "/run/siem-secrets"))
LOGSTASH_URL = os.environ.get("LOGSTASH_URL", "http://central-logstash:9601")
TLS_CERT_PATH = Path(os.environ.get("INGEST_EDGE_TLS_CERT", "/run/siem-certs/central.crt"))
TLS_KEY_PATH = Path(os.environ.get("INGEST_EDGE_TLS_KEY", "/run/siem-certs/central.key"))
MAX_BODY_BYTES = int(os.environ.get("INGEST_EDGE_MAX_BODY_BYTES", str(1024 * 1024)))
TRUSTED_PROXY_CIDRS = [
    item.strip()
    for item in os.environ.get("TRUSTED_PROXY_CIDRS", "").split(",")
    if item.strip()
]


def load_config() -> dict[str, Any]:
    with CONFIG_PATH.open("r", encoding="utf-8") as handle:
        doc = yaml.safe_load(handle)
    if not isinstance(doc, dict) or "credentials" not in doc:
        raise ValueError(f"{CONFIG_PATH}: expected credentials mapping")
    return doc


def parse_basic_auth(header: str | None) -> tuple[str, str] | None:
    if not header or not header.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(header.removeprefix("Basic ").strip()).decode("utf-8")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    username, password = decoded.split(":", 1)
    return username, password


def secret_value(secret_ref: str) -> str:
    path = SECRET_ROOT / Path(secret_ref).name
    return path.read_text(encoding="utf-8").strip()


def ip_allowed(client_ip: str, cidrs: list[str]) -> bool:
    address = ip_address(client_ip)
    return any(address in ip_network(cidr, strict=False) for cidr in cidrs)


def client_ip_for_request(peer_ip: str, forwarded_for: str | None) -> str:
    if not TRUSTED_PROXY_CIDRS:
        return peer_ip
    if not ip_allowed(peer_ip, TRUSTED_PROXY_CIDRS):
        return peer_ip
    if not forwarded_for:
        return peer_ip
    return forwarded_for.split(",", 1)[0].strip()


def content_length(headers: Any) -> int | None:
    value = headers.get("Content-Length")
    if value is None:
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    if parsed < 0:
        return None
    return parsed


class Handler(BaseHTTPRequestHandler):
    server_version = "OpenSearchSIEMIngestEdge/1.0"

    def do_POST(self) -> None:
        config = load_config()
        auth = parse_basic_auth(self.headers.get("Authorization"))
        if auth is None:
            self.reject(401, "missing basic auth")
            return

        username, password = auth
        credential = config["credentials"].get(username)
        if credential is None or not credential.get("enabled", False):
            self.reject(403, "unknown credential")
            return

        expected = secret_value(credential["secretRef"])
        if not secrets.compare_digest(password, expected):
            self.reject(403, "invalid credential")
            return

        client_ip = client_ip_for_request(self.client_address[0], self.headers.get("X-Forwarded-For"))
        if not ip_allowed(client_ip, credential.get("allowedCidrs", [])):
            self.reject(403, "source ip not allowed")
            return

        length = content_length(self.headers)
        if length is None:
            self.reject(400, "invalid content length")
            return
        if length > MAX_BODY_BYTES:
            self.reject(413, "request too large")
            return

        raw_body = self.rfile.read(length)
        try:
            event = json.loads(raw_body)
        except json.JSONDecodeError:
            self.reject(400, "invalid json")
            return

        if not isinstance(event, dict):
            self.reject(400, "event must be a json object")
            return

        event["customer"] = {"slug": credential["customerSlug"]}
        event["siem"] = {
            **event.get("siem", {}),
            "credential_id": username,
            "ingest_edge_client_ip": client_ip,
        }

        try:
            response = requests.post(LOGSTASH_URL, json=event, timeout=10)
        except requests.RequestException:
            self.reject(503, "upstream logstash unavailable")
            return
        self.send_response(response.status_code)
        self.send_header("Content-Length", str(len(response.content)))
        self.end_headers()
        self.wfile.write(response.content)

    def reject(self, status: int, message: str) -> None:
        body = json.dumps({"error": message}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    host = os.environ.get("INGEST_EDGE_HOST", "0.0.0.0")
    port = int(os.environ.get("INGEST_EDGE_PORT", "5044"))
    server = ThreadingHTTPServer((host, port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=TLS_CERT_PATH, keyfile=TLS_KEY_PATH)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
```

- [ ] **Step 5: Create ingest-edge Dockerfile**

Create `ingest-edge/Dockerfile`:

```dockerfile
FROM python:3.12-alpine
WORKDIR /app
COPY ingest-edge/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY ingest-edge/app.py /app/app.py
USER 1000:1000
EXPOSE 5044
CMD ["python", "/app/app.py"]
```

- [ ] **Step 6: Create ingest-edge behavior tests**

Create `scripts/test-ingest-edge.py`:

```python
from __future__ import annotations

import base64
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ingest_edge_app", ROOT / "ingest-edge" / "app.py")
assert SPEC and SPEC.loader
app = importlib.util.module_from_spec(SPEC)
sys.modules["ingest_edge_app"] = app
SPEC.loader.exec_module(app)


def basic(username: str, password: str) -> str:
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {encoded}"


def test_parse_basic_auth_accepts_valid_header() -> None:
    assert app.parse_basic_auth(basic("acme-primary", "secret")) == ("acme-primary", "secret")


def test_parse_basic_auth_rejects_missing_or_malformed_header() -> None:
    assert app.parse_basic_auth(None) is None
    assert app.parse_basic_auth("Bearer token") is None
    assert app.parse_basic_auth("Basic not-base64") is None


def test_ip_allowed_matches_cidr() -> None:
    assert app.ip_allowed("203.0.113.10", ["203.0.113.10/32"])
    assert not app.ip_allowed("203.0.113.11", ["203.0.113.10/32"])


def test_client_ip_ignores_forwarded_for_without_trusted_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app, "TRUSTED_PROXY_CIDRS", [])
    assert app.client_ip_for_request("10.0.0.10", "203.0.113.10") == "10.0.0.10"


def test_client_ip_uses_forwarded_for_from_trusted_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app, "TRUSTED_PROXY_CIDRS", ["10.0.0.0/24"])
    assert app.client_ip_for_request("10.0.0.10", "203.0.113.10, 10.0.0.10") == "203.0.113.10"


def test_content_length_rejects_missing_negative_and_non_numeric() -> None:
    assert app.content_length({}) is None
    assert app.content_length({"Content-Length": "-1"}) is None
    assert app.content_length({"Content-Length": "abc"}) is None
    assert app.content_length({"Content-Length": "42"}) == 42


def test_upstream_failure_returns_503(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[int, str]] = []

    def raise_request_error(*args, **kwargs):
        raise requests.RequestException("boom")

    handler = object.__new__(app.Handler)
    handler.headers = {"Authorization": basic("acme-primary", "secret"), "Content-Length": "2"}
    handler.client_address = ("203.0.113.10", 12345)
    handler.rfile = SimpleNamespace(read=lambda length: b"{}")
    handler.wfile = SimpleNamespace(write=lambda body: None)
    handler.send_response = lambda status: calls.append((status, "response"))
    handler.send_header = lambda key, value: None
    handler.end_headers = lambda: None

    monkeypatch.setattr(app, "load_config", lambda: {
        "credentials": {
            "acme-primary": {
                "enabled": True,
                "secretRef": "secrets/local/customer-acme-password",
                "customerSlug": "acme",
                "allowedCidrs": ["203.0.113.10/32"],
            }
        }
    })
    monkeypatch.setattr(app, "secret_value", lambda secret_ref: "secret")
    monkeypatch.setattr(app.requests, "post", raise_request_error)

    handler.do_POST()
    assert calls[0] == (503, "response")
```

- [ ] **Step 7: Create ingest-edge smoke test**

Create `scripts/test-ingest-edge.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 -m py_compile ingest-edge/app.py
python3 -m pytest scripts/test-ingest-edge.py -q

tmp_dir="$(mktemp -d)"
trap 'kill ${edge_pid:-} ${upstream_pid:-} 2>/dev/null || true; rm -rf "$tmp_dir"' EXIT

mkdir -p "$tmp_dir/config" "$tmp_dir/secrets" "$tmp_dir/certs"
printf 'secret\n' > "$tmp_dir/secrets/customer-acme-password"
cat > "$tmp_dir/config/customer-auth.yml" <<'YAML'
credentials:
  acme-primary:
    customerSlug: acme
    enabled: true
    secretRef: secrets/local/customer-acme-password
    allowedCidrs:
      - 127.0.0.1/32
YAML

openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "$tmp_dir/certs/central.key" \
  -out "$tmp_dir/certs/central.crt" \
  -days 1 \
  -subj "/CN=localhost" >/dev/null 2>&1

python3 -m http.server 19601 >/dev/null 2>&1 &
upstream_pid="$!"

INGEST_EDGE_CONFIG="$tmp_dir/config/customer-auth.yml" \
INGEST_EDGE_SECRET_ROOT="$tmp_dir/secrets" \
INGEST_EDGE_TLS_CERT="$tmp_dir/certs/central.crt" \
INGEST_EDGE_TLS_KEY="$tmp_dir/certs/central.key" \
LOGSTASH_URL="http://127.0.0.1:19601" \
INGEST_EDGE_HOST="127.0.0.1" \
INGEST_EDGE_PORT="15044" \
python3 ingest-edge/app.py >/dev/null 2>&1 &
edge_pid="$!"

for _ in $(seq 1 20); do
  if curl -sk https://127.0.0.1:15044 >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

status="$(curl -sk -o /dev/null -w '%{http_code}' \
  -u acme-primary:secret \
  -H 'Content-Type: application/json' \
  -d '{"siem":{"source_id":"firewall"},"message":"test"}' \
  https://127.0.0.1:15044)"
if [[ "$status" != "501" ]]; then
  echo "expected HTTPS ingest edge to forward to dummy upstream and return 501, got $status" >&2
  exit 1
fi

docker build -f ingest-edge/Dockerfile -t opensearch-siem-ingest-edge:test .

echo "ingest-edge tests and build passed"
```

- [ ] **Step 8: Create Logstash settings**

Create `logstash/config/logstash.yml`:

```yaml
http.host: "0.0.0.0"
pipeline.ecs_compatibility: v8
queue.type: persisted
queue.max_bytes: 8gb
path.queue: /usr/share/logstash/data/queue
dead_letter_queue.enable: true
dead_letter_queue.max_bytes: 512mb
```

Create `logstash/config/pipelines.yml`:

```yaml
- pipeline.id: relay-input
  path.config: /usr/share/logstash/pipeline/00-relay-input.conf
- pipeline.id: route-and-enrich
  path.config: /usr/share/logstash/pipeline/10-route-and-enrich.conf
- pipeline.id: normalize
  path.config: /usr/share/logstash/pipeline/20-normalize.conf
- pipeline.id: opensearch-output
  path.config: /usr/share/logstash/pipeline/90-opensearch-output.conf
```

- [ ] **Step 9: Create Logstash pipelines**

Create `logstash/pipeline/00-relay-input.conf`:

```ruby
input {
  http {
    id => "ingest-edge-http"
    host => "0.0.0.0"
    port => 9601
    codec => "json"
  }
}

filter {
  mutate {
    add_field => {
      "[@metadata][ingest_stage]" => "relay-input"
    }
  }
}

output {
  pipeline {
    send_to => "route-and-enrich"
  }
}
```

Create `logstash/pipeline/10-route-and-enrich.conf`:

```ruby
input {
  pipeline {
    address => "route-and-enrich"
  }
}

filter {
  ruby {
    init => '
      require "yaml"
      routing_yaml = File.read("/usr/share/logstash/gitops/source-routing.yml")
      @sources = YAML.safe_load(routing_yaml, permitted_classes: [], permitted_symbols: [], aliases: false).fetch("sources")
    '
    code => '
      customer = event.get("[customer][slug]")
      source_id = event.get("[siem][source_id]")

      if customer.nil? || customer.empty?
        event.set("[siem][quarantine_reason]", "missing_customer_slug_from_ingest_edge")
        event.set("[@metadata][target_stream]", "logs-unknown-quarantine")
      elsif source_id.nil? || source_id.empty?
        event.set("[siem][quarantine_reason]", "missing_source_id")
        event.set("[@metadata][target_stream]", "logs-#{customer}-unknown-quarantine")
      else
        route = @sources["#{customer}:#{source_id}"]
        if route.nil? || route["enabled"] != true
          event.set("[siem][quarantine_reason]", "unknown_or_disabled_source")
          event.set("[@metadata][target_stream]", "logs-#{customer}-unknown-quarantine")
        else
          event.set("[event][dataset]", route["dataset"])
          event.set("[data_stream][type]", "logs")
          event.set("[data_stream][dataset]", route["dataset"])
          event.set("[data_stream][namespace]", customer)
          event.set("[@metadata][target_stream]", route["stream"])
        end
      end
    '
  }
}

output {
  pipeline {
    send_to => "normalize"
  }
}
```

Create `logstash/pipeline/20-normalize.conf`:

```ruby
input {
  pipeline {
    address => "normalize"
  }
}

filter {
  if ![event][original] and [message] {
    mutate {
      copy => {
        "message" => "[event][original]"
      }
    }
  }
}

output {
  pipeline {
    send_to => "opensearch-output"
  }
}
```

Create `logstash/pipeline/90-opensearch-output.conf`:

```ruby
input {
  pipeline {
    address => "opensearch-output"
  }
}

output {
  opensearch {
    hosts => ["https://opensearch:9200"]
    index => "%{[@metadata][target_stream]}"
    action => "create"
    user => "${LOGSTASH_WRITER_USER}"
    password => "${LOGSTASH_WRITER_PASSWORD}"
    ssl => true
    ssl_certificate_verification => false
    manage_template => false
  }
}
```

- [ ] **Step 10: Create target Compose file**

Create `docker-compose.yml`:

```yaml
version: "3.8"

services:
  opensearch:
    image: opensearchproject/opensearch:3.6.0
    container_name: opensearch
    restart: unless-stopped
    environment:
      - cluster.name=opensearch-siem
      - node.name=opensearch
      - discovery.type=single-node
      - bootstrap.memory_lock=true
      - OPENSEARCH_JAVA_OPTS=-Xms12g -Xmx12g
      - OPENSEARCH_INITIAL_ADMIN_PASSWORD=${OPENSEARCH_ADMIN_PASSWORD}
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - ./data/opensearch:/usr/share/opensearch/data
    ports:
      - "127.0.0.1:9200:9200"
    networks:
      - siem-net
    healthcheck:
      test: ["CMD-SHELL", "curl -sku admin:${OPENSEARCH_ADMIN_PASSWORD} https://localhost:9200/_cluster/health | grep -qE '\"status\":\"(green|yellow)\"'"]
      interval: 20s
      timeout: 10s
      retries: 12
      start_period: 120s

  opensearch-dashboards:
    image: opensearchproject/opensearch-dashboards:3.6.0
    container_name: opensearch-dashboards
    restart: unless-stopped
    environment:
      - OPENSEARCH_HOSTS=["https://opensearch:9200"]
      - OPENSEARCH_USERNAME=admin
      - OPENSEARCH_PASSWORD=${OPENSEARCH_ADMIN_PASSWORD}
      - DATA_SOURCE_ENABLED=true
      - WORKSPACE_ENABLED=true
      - EXPLORE_ENABLED=true
    ports:
      - "127.0.0.1:5601:5601"
    networks:
      - siem-net
    depends_on:
      opensearch:
        condition: service_healthy

  central-logstash:
    image: opensearchproject/logstash-oss-with-opensearch-output-plugin:8.9.0
    container_name: central-logstash
    restart: unless-stopped
    environment:
      - LS_JAVA_OPTS=-Xms2g -Xmx2g
      - LOGSTASH_WRITER_USER=${LOGSTASH_WRITER_USER}
      - LOGSTASH_WRITER_PASSWORD=${LOGSTASH_WRITER_PASSWORD}
    volumes:
      - ./logstash/config:/usr/share/logstash/config:ro
      - ./logstash/pipeline:/usr/share/logstash/pipeline:ro
      - ./gitops/rendered/logstash:/usr/share/logstash/gitops:ro
      - ./data/logstash:/usr/share/logstash/data
    expose:
      - "9601"
    networks:
      - siem-net
    depends_on:
      opensearch:
        condition: service_healthy

  ingest-edge:
    build:
      context: .
      dockerfile: ingest-edge/Dockerfile
    container_name: ingest-edge
    restart: unless-stopped
    environment:
      - LOGSTASH_URL=http://central-logstash:9601
      - INGEST_EDGE_CONFIG=/app/config/customer-auth.yml
      - INGEST_EDGE_SECRET_ROOT=/run/siem-secrets
      - INGEST_EDGE_TLS_CERT=/run/siem-certs/central.crt
      - INGEST_EDGE_TLS_KEY=/run/siem-certs/central.key
      - INGEST_EDGE_MAX_BODY_BYTES=1048576
      - TRUSTED_PROXY_CIDRS=${TRUSTED_PROXY_CIDRS:-}
    volumes:
      - ./gitops/rendered/ingest-edge:/app/config:ro
      - ./secrets/local:/run/siem-secrets:ro
      - ./secrets/certs:/run/siem-certs:ro
    ports:
      - "5044:5044/tcp"
    networks:
      - siem-net
    depends_on:
      - central-logstash

networks:
  siem-net:
    driver: bridge
```

- [ ] **Step 11: Run ingest-edge validation**

Run: `bash scripts/test-ingest-edge.sh`

Expected: PASS with `ingest-edge tests and build passed`.

- [ ] **Step 12: Run Compose validation**

Run: `bash scripts/test-target-compose.sh`

Expected: PASS with `target compose config passed`.

- [ ] **Step 13: Run Logstash config validation**

Run: `bash scripts/test-logstash-config.sh`

Expected: PASS with `Configuration OK` from Logstash and `logstash target config passed`.

- [ ] **Step 14: Commit**

```bash
git add ingest-edge docker-compose.yml logstash/config logstash/pipeline scripts/test-ingest-edge.py scripts/test-ingest-edge.sh scripts/test-target-compose.sh scripts/test-logstash-config.sh
git commit -m "feat: add authenticated ingest edge and logstash pipelines"
```

## Task 6: Add OpenSearch Templates, ISM Policies, And Reconciler

**Files:**
- Create: `opensearch/base/index-templates/logs-template.json`
- Create: `opensearch/base/index-templates/alerts-template.json`
- Create: `opensearch/base/ism/critical-30d.json`
- Create: `opensearch/base/ism/standard-7d.json`
- Create: `opensearch/base/ism/noisy-3d.json`
- Create: `opensearch/base/ism/quarantine-7d.json`
- Create: `scripts/reconcile-opensearch-gitops.py`
- Create: `scripts/test-opensearch-reconciler.sh`

- [ ] **Step 1: Create reconciler test**

Create `scripts/test-opensearch-reconciler.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

python3 scripts/reconcile-opensearch-gitops.py --dry-run
echo "opensearch reconciler dry-run passed"
```

- [ ] **Step 2: Create logs index template**

Create `opensearch/base/index-templates/logs-template.json`:

```json
{
  "index_patterns": ["logs-*"],
  "data_stream": {},
  "template": {
    "settings": {
      "index.number_of_shards": 1,
      "index.number_of_replicas": 0
    },
    "mappings": {
      "dynamic": true,
      "properties": {
        "@timestamp": { "type": "date" },
        "customer": {
          "properties": {
            "slug": { "type": "keyword" }
          }
        },
        "source": {
          "properties": {
            "id": { "type": "keyword" }
          }
        },
        "event": {
          "properties": {
            "dataset": { "type": "keyword" },
            "original": { "type": "wildcard" }
          }
        }
      }
    }
  },
  "priority": 200
}
```

- [ ] **Step 3: Create alerts template**

Create `opensearch/base/index-templates/alerts-template.json`:

```json
{
  "index_patterns": ["alerts-*"],
  "template": {
    "settings": {
      "index.number_of_shards": 1,
      "index.number_of_replicas": 0
    },
    "mappings": {
      "dynamic": true,
      "properties": {
        "@timestamp": { "type": "date" },
        "customer.slug": { "type": "keyword" },
        "alert.id": { "type": "keyword" },
        "alert.severity": { "type": "keyword" }
      }
    }
  },
  "priority": 200
}
```

- [ ] **Step 4: Create ISM policies**

Create `opensearch/base/ism/critical-30d.json`:

```json
{
  "policy": {
    "description": "Critical logs retained for 30 days",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [
          { "rollover": { "min_index_age": "1d", "min_size": "30gb" } }
        ],
        "transitions": [
          { "state_name": "delete", "conditions": { "min_index_age": "30d" } }
        ]
      },
      {
        "name": "delete",
        "actions": [{ "delete": {} }],
        "transitions": []
      }
    ]
  }
}
```

Create `opensearch/base/ism/standard-7d.json`:

```json
{
  "policy": {
    "description": "Standard logs retained for 7 days",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [
          { "rollover": { "min_index_age": "1d", "min_size": "20gb" } }
        ],
        "transitions": [
          { "state_name": "delete", "conditions": { "min_index_age": "7d" } }
        ]
      },
      {
        "name": "delete",
        "actions": [{ "delete": {} }],
        "transitions": []
      }
    ]
  }
}
```

Create `opensearch/base/ism/noisy-3d.json`:

```json
{
  "policy": {
    "description": "Noisy logs retained for 3 days",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [
          { "rollover": { "min_index_age": "1d", "min_size": "10gb" } }
        ],
        "transitions": [
          { "state_name": "delete", "conditions": { "min_index_age": "3d" } }
        ]
      },
      {
        "name": "delete",
        "actions": [{ "delete": {} }],
        "transitions": []
      }
    ]
  }
}
```

Create `opensearch/base/ism/quarantine-7d.json`:

```json
{
  "policy": {
    "description": "Quarantine logs retained for 7 days",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [
          { "rollover": { "min_index_age": "1d", "min_size": "5gb" } }
        ],
        "transitions": [
          { "state_name": "delete", "conditions": { "min_index_age": "7d" } }
        ]
      },
      {
        "name": "delete",
        "actions": [{ "delete": {} }],
        "transitions": []
      }
    ]
  }
}
```

- [ ] **Step 5: Create dry-run/apply reconciler**

Create `scripts/reconcile-opensearch-gitops.py`:

```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import requests


REPO_ROOT = Path(__file__).resolve().parents[1]


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def put_json(base_url: str, path: str, body: dict, dry_run: bool) -> None:
    if dry_run:
        print(f"DRY-RUN PUT {path}")
        return
    response = requests.put(
        f"{base_url}{path}",
        auth=(os.environ["OPENSEARCH_USER"], os.environ["OPENSEARCH_PASSWORD"]),
        json=body,
        verify=False,
        timeout=30,
    )
    response.raise_for_status()
    print(f"applied {path}")


def reconcile(dry_run: bool) -> None:
    base_url = os.environ.get("OPENSEARCH_URL", "https://localhost:9200")

    for path in sorted((REPO_ROOT / "opensearch/base/index-templates").glob("*.json")):
        name = path.stem
        put_json(base_url, f"/_index_template/{name}", load_json(path), dry_run)

    for path in sorted((REPO_ROOT / "gitops/rendered/opensearch/index-templates").glob("*.json")):
        name = path.stem
        put_json(base_url, f"/_index_template/{name}", load_json(path), dry_run)

    for path in sorted((REPO_ROOT / "opensearch/base/ism").glob("*.json")):
        name = path.stem
        put_json(base_url, f"/_plugins/_ism/policies/{name}", load_json(path), dry_run)

    role_path = REPO_ROOT / "gitops/rendered/opensearch/security/logstash-writer-role.json"
    if role_path.exists():
        put_json(base_url, "/_plugins/_security/api/roles/logstash_writer", load_json(role_path), dry_run)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    reconcile(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
```

- [ ] **Step 6: Run reconciler dry-run**

Run: `bash scripts/test-opensearch-reconciler.sh`

Expected: PASS with `DRY-RUN PUT` lines and `opensearch reconciler dry-run passed`.

- [ ] **Step 7: Commit**

```bash
git add opensearch/base scripts/reconcile-opensearch-gitops.py scripts/test-opensearch-reconciler.sh
git commit -m "feat: add opensearch gitops reconciler"
```

## Task 7: Generate Customer Relay Bundles

**Files:**
- Create: `relay/templates/logstash.yml.j2`
- Create: `relay/templates/pipeline.conf.j2`
- Create: `scripts/generate-relay-bundle.sh`
- Create: `scripts/test-relay-bundle.sh`

- [ ] **Step 1: Create relay bundle test**

Create `scripts/test-relay-bundle.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

bash scripts/generate-relay-bundle.sh acme
test -f relay/bundles/acme/logstash.yml
test -f relay/bundles/acme/pipeline.conf
grep -q "https://siem.example.com:5044" relay/bundles/acme/pipeline.conf

echo "relay bundle test passed"
```

- [ ] **Step 2: Create relay templates**

Create `relay/templates/logstash.yml.j2`:

```jinja
http.host: "0.0.0.0"
pipeline.ecs_compatibility: v8
queue.type: persisted
queue.max_bytes: 4gb
path.queue: /usr/share/logstash/data/queue
```

Create `relay/templates/pipeline.conf.j2`:

```jinja
input {
  syslog {
    port => 5514
    type => "syslog"
  }
}

filter {
  mutate {
    add_field => {
      "[customer][slug]" => "{{ customer_slug }}"
      "[siem][source_id]" => "firewall"
      "[event][dataset]" => "firewall"
    }
  }
}

output {
  http {
    url => "{{ central_url }}"
    http_method => "post"
    format => "json"
    content_type => "application/json"
    user => "{{ credential_id }}"
    password => "${CUSTOMER_FORWARDER_PASSWORD}"
    ssl_verification_mode => "full"
    ssl_certificate_authorities => ["/usr/share/logstash/config/certs/central-ca.crt"]
  }
}
```

- [ ] **Step 3: Create relay bundle script**

Create `scripts/generate-relay-bundle.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 customer-slug" >&2
  exit 2
fi

customer_slug="$1"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bundle_dir="$repo_root/relay/bundles/$customer_slug"

customer_file="$repo_root/gitops/desired/customers/$customer_slug/customer.yml"
credential_file="$repo_root/gitops/desired/customers/$customer_slug/credentials.yml"

if [[ ! -f "$customer_file" || ! -f "$credential_file" ]]; then
  echo "unknown customer: $customer_slug" >&2
  exit 1
fi

credential_id="$(python3 - "$credential_file" <<'PY'
from pathlib import Path
import sys
import yaml
doc = yaml.safe_load(Path(sys.argv[1]).read_text())
enabled = [item["id"] for item in doc["credentials"] if item["enabled"]]
if not enabled:
    raise SystemExit("no enabled credential")
print(enabled[0])
PY
)"

mkdir -p "$bundle_dir"

python3 - "$repo_root" "$customer_slug" "$credential_id" <<'PY'
from pathlib import Path
import sys
from jinja2 import Environment, FileSystemLoader

repo = Path(sys.argv[1])
customer_slug = sys.argv[2]
credential_id = sys.argv[3]
env = Environment(loader=FileSystemLoader(str(repo)), autoescape=False)
bundle = repo / "relay" / "bundles" / customer_slug
bundle.mkdir(parents=True, exist_ok=True)
(bundle / "logstash.yml").write_text(
    env.get_template("relay/templates/logstash.yml.j2").render(),
    encoding="utf-8",
)
(bundle / "pipeline.conf").write_text(
    env.get_template("relay/templates/pipeline.conf.j2").render(
        customer_slug=customer_slug,
        credential_id=credential_id,
        central_url="https://siem.example.com:5044",
    ),
    encoding="utf-8",
)
(bundle / "README.md").write_text(
    "Install central-ca.crt at /usr/share/logstash/config/certs/central-ca.crt and set CUSTOMER_FORWARDER_PASSWORD before starting the relay.\n",
    encoding="utf-8",
)
PY

echo "relay bundle written to $bundle_dir"
```

- [ ] **Step 4: Run relay bundle test**

Run: `bash scripts/test-relay-bundle.sh`

Expected: PASS with `relay bundle test passed`.

- [ ] **Step 5: Commit**

```bash
git add relay/templates scripts/generate-relay-bundle.sh scripts/test-relay-bundle.sh
git commit -m "feat: generate customer relay bundles"
```

## Task 8: Add Optional Backup Jobs

**Files:**
- Create: `backup/Dockerfile`
- Create: `backup/backup-opensearch.sh`
- Create: `backup/backup-gitops-repo.sh`
- Modify: `docker-compose.yml`

- [ ] **Step 1: Create backup scripts**

Create `backup/backup-opensearch.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

if [[ "${BACKUP_ENABLED:-false}" != "true" ]]; then
  echo "backup disabled"
  exit 0
fi

snapshot_name="snapshot-$(date -u +%Y%m%dT%H%M%SZ)"
curl -sku "$OPENSEARCH_USER:$OPENSEARCH_PASSWORD" \
  -XPUT "$OPENSEARCH_URL/_snapshot/$SNAPSHOT_REPOSITORY/$snapshot_name?wait_for_completion=false"
echo "started OpenSearch snapshot $snapshot_name"
```

Create `backup/backup-gitops-repo.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

output="/backup/gitops-$(date -u +%Y%m%dT%H%M%SZ).bundle"
git -C /repo bundle create "$output" --all
echo "wrote Git bundle $output"
```

- [ ] **Step 2: Create backup image**

Create `backup/Dockerfile`:

```dockerfile
FROM alpine:3.20
RUN apk add --no-cache bash curl git
COPY backup/backup-opensearch.sh /usr/local/bin/backup-opensearch.sh
COPY backup/backup-gitops-repo.sh /usr/local/bin/backup-gitops-repo.sh
RUN chmod +x /usr/local/bin/backup-opensearch.sh /usr/local/bin/backup-gitops-repo.sh
```

- [ ] **Step 3: Add backup profile to Compose**

Modify `docker-compose.yml` and add this service under `services`:

```yaml
  backup-job:
    build:
      context: .
      dockerfile: backup/Dockerfile
    profiles:
      - backup
    environment:
      - BACKUP_ENABLED=${BACKUP_ENABLED:-false}
      - OPENSEARCH_URL=https://opensearch:9200
      - OPENSEARCH_USER=${BACKUP_USER:-admin}
      - OPENSEARCH_PASSWORD=${BACKUP_PASSWORD:-}
      - SNAPSHOT_REPOSITORY=${SNAPSHOT_REPOSITORY:-siem-snapshots}
    volumes:
      - ./:/repo:ro
      - ./data/backups:/backup
    networks:
      - siem-net
    depends_on:
      opensearch:
        condition: service_healthy
```

- [ ] **Step 4: Validate Compose after adding backup profile**

Run: `bash scripts/test-target-compose.sh`

Expected: PASS with `target compose config passed`.

- [ ] **Step 5: Commit**

```bash
git add backup docker-compose.yml
git commit -m "feat: add optional backup jobs"
```

## Task 9: Add Local Secret Bootstrap

**Files:**
- Create: `scripts/setup-local-secrets.sh`

- [ ] **Step 1: Create bootstrap script**

Create `scripts/setup-local-secrets.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

mkdir -p secrets/local secrets/certs data/opensearch data/logstash data/backups
chmod 700 secrets secrets/local secrets/certs

write_secret() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    openssl rand -base64 32 > "$path"
    chmod 600 "$path"
  fi
}

write_secret secrets/local/opensearch-admin-password
write_secret secrets/local/logstash-writer-password
write_secret secrets/local/customer-acme-password

if [[ ! -f secrets/certs/central.key || ! -f secrets/certs/central.crt ]]; then
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout secrets/certs/central.key \
    -out secrets/certs/central.crt \
    -days 365 \
    -subj "/CN=opensearch-siem-central-logstash"
  chmod 600 secrets/certs/central.key
  chmod 644 secrets/certs/central.crt
fi

cat > .env <<EOF
OPENSEARCH_ADMIN_PASSWORD=$(cat secrets/local/opensearch-admin-password)
LOGSTASH_WRITER_USER=logstash_writer
LOGSTASH_WRITER_PASSWORD=$(cat secrets/local/logstash-writer-password)
BACKUP_ENABLED=false
TRUSTED_PROXY_CIDRS=
EOF
chmod 600 .env

echo "local secrets initialized"
```

- [ ] **Step 2: Run bootstrap**

Run: `bash scripts/setup-local-secrets.sh`

Expected: PASS with `local secrets initialized`.

- [ ] **Step 3: Verify secrets remain untracked**

Run: `bash scripts/test-secret-ignore.sh`

Expected: PASS with `secret ignore checks passed`.

- [ ] **Step 4: Commit**

```bash
git add scripts/setup-local-secrets.sh
git commit -m "feat: add local secret bootstrap"
```

## Task 10: Add Operator Documentation

**Files:**
- Create: `docs/opensearch-siem-operations.md`

- [ ] **Step 1: Create operations guide**

Create `docs/opensearch-siem-operations.md`:

```markdown
# OpenSearch SIEM Operations

## Host Prerequisites

Set `vm.max_map_count=262144` on the Docker host before starting OpenSearch.

## First Start

Run:

```bash
bash scripts/setup-local-secrets.sh
python3 scripts/validate-gitops-config.py
python3 scripts/render-gitops-config.py
docker compose config --quiet
docker compose up -d opensearch
docker compose up -d opensearch-dashboards central-logstash
```

## GitOps Change Flow

1. Edit `gitops/desired/**`.
2. Run `python3 scripts/validate-gitops-config.py`.
3. Run `python3 scripts/render-gitops-config.py`.
4. Review changes under `gitops/rendered/**`.
5. Run `python3 scripts/reconcile-opensearch-gitops.py --dry-run`.
6. Run `python3 scripts/reconcile-opensearch-gitops.py` when ready to apply.

## Retention Defaults

Default searchable retention is 7 days. Critical selected datasets can retain up to 30 days. Quarantine retains 3-7 days.

## Customer Separation

Customer streams use readable slugs, for example `logs-acme-firewall`. Customer slugs must not change after data is written.

## Ingest Edge TLS And IP Allowlists

Customer relays send HTTPS traffic to the central ingest edge on TCP 5044. The ingest edge mounts `secrets/certs/central.crt` and `secrets/certs/central.key`.

IP allowlisting must be enforced where the real customer source IP is visible. The preferred version-one deployment enforces customer allowlists at the host firewall before traffic reaches Docker. If a trusted reverse proxy sits in front of `ingest-edge`, set `TRUSTED_PROXY_CIDRS` to the proxy CIDR only; `ingest-edge` then accepts `X-Forwarded-For` only from those proxy addresses. Do not accept `X-Forwarded-For` directly from the public internet.

## Backup Warning

External S3-compatible object storage is optional in version one. Until it is configured, VM or disk loss can destroy SIEM data.
```

- [ ] **Step 2: Commit**

```bash
git add docs/opensearch-siem-operations.md
git commit -m "docs: add opensearch siem operations guide"
```

## Task 11: Run Full Local Validation

**Files:**
- No new files.

- [ ] **Step 1: Run GitOps validation**

Run: `bash scripts/test-gitops-config.sh`

Expected: PASS with `gitops config validation passed`.

- [ ] **Step 2: Run render validation**

Run: `bash scripts/test-rendered-gitops-config.sh`

Expected: PASS with `rendered gitops config is current`.

- [ ] **Step 3: Run Compose validation**

Run: `bash scripts/test-target-compose.sh`

Expected: PASS with `target compose config passed`.

- [ ] **Step 4: Run Logstash config validation**

Run: `bash scripts/test-logstash-config.sh`

Expected: PASS with `Configuration OK` and `logstash target config passed`.

- [ ] **Step 5: Run OpenSearch reconciler dry-run**

Run: `bash scripts/test-opensearch-reconciler.sh`

Expected: PASS with `opensearch reconciler dry-run passed`.

- [ ] **Step 6: Run relay bundle validation**

Run: `bash scripts/test-relay-bundle.sh`

Expected: PASS with `relay bundle test passed`.

- [ ] **Step 7: Run ignore validation**

Run: `bash scripts/test-secret-ignore.sh`

Expected: PASS with `secret ignore checks passed`.

- [ ] **Step 8: Check generated and ignored state**

Run: `git status --short`

Expected: no uncommitted tracked-file changes. Ignored local secrets, data directories, and relay bundles may exist.

- [ ] **Step 9: Commit validation fixes if needed**

If validation rewrote generated GitOps artifacts:

```bash
git add gitops/rendered
git commit -m "test: align single-vm siem validation"
```

## Implementation Notes

- Keep OpenSearch at one node for version one.
- Keep Dashboards bound to loopback or internal network access.
- Keep customer direct ingest out of scope.
- Keep broker names and pipeline boundaries future-friendly, but do not add broker services.
- Keep customer slugs immutable once data exists.
- Keep plaintext secrets out of Git.
- Treat external object storage as the point where disaster recovery becomes real.
