# Customer Forwarder Logstash Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a static reusable customer-side Logstash forwarder package with a central `source_id` catalog, v1 Windows AD/Sysmon/syslog parser paths, persistent queueing, and validation that keeps customer forwarder config aligned with central GitOps.

**Architecture:** The main repo owns `source-catalog/sources.yml` as the canonical source vocabulary. Central GitOps validates customer source records against that catalog, while `customer-forwarder/` ships a copied catalog snapshot plus local validation/render scripts that generate the enabled Logstash input pipeline and queue settings. Input templates write configured source metadata only to Logstash `@metadata`; an early parser stage removes spoofable routing fields from the event body and then writes canonical `siem.source_id`, `event.dataset`, and `observer.name` from that trusted metadata. The forwarder sends normalized JSON objects to central `ingest-edge`; central `ingest-edge` remains responsible for trusted customer identity. Version one intentionally keeps object-per-request delivery and adds conservative Logstash pipeline sizing, disk-headroom validation, container resource guardrails, and validation so the static package is predictable on small customer hosts.

**Tech Stack:** Python 3.11, PyYAML, jsonschema, pytest, Docker Compose, Logstash OSS with HTTP/syslog inputs and HTTP output.

---

## File Structure

Create or modify these files:

- Create `source-catalog/sources.yml`: canonical allowed source IDs.
- Create `source-catalog/sources.schema.json`: schema for the canonical catalog.
- Modify `scripts/lib/gitops_config.py`: load and validate the catalog, enforce catalog matches for central GitOps source records.
- Modify `scripts/render-gitops-config.py`: load the source catalog and remove stale managed rendered index templates when desired sources change.
- Create `scripts/test-source-catalog.py`: pytest coverage for catalog uniqueness and central GitOps catalog enforcement.
- Modify `scripts/test-gitops-config.sh`: include `scripts/test-source-catalog.py`.
- Modify `gitops/schemas/source.schema.json`: keep the parser field syntactically safe while exact parser values are enforced by `source-catalog/sources.yml`.
- Replace sample sources under `gitops/desired/customers/acme/sources/`: migrate from `firewall`/`windows` to `generic-syslog`, `windows-ad`, and `windows-sysmon`.
- Update generated files under `gitops/rendered/**` by running `scripts/render-gitops-config.py`.
- Modify `scripts/generate-relay-bundle.sh` and `scripts/test-relay-bundle.sh`: keep the legacy relay bundle syslog-only and prove non-syslog catalog inputs are excluded.
- Create `customer-forwarder/**`: static customer-side package, local config, rendered Logstash config, parser pipelines, scripts, tests, fixtures, and README.
- Create `scripts/test-customer-forwarder.sh`: top-level wrapper for forwarder validation/tests.
- Modify `.gitignore`: ignore `customer-forwarder/data/`, `customer-forwarder/logs/`, `customer-forwarder/tmp/`, and customer-local secret/cert material.
- Modify `scripts/test-secret-ignore.sh`: assert customer-forwarder runtime/secret paths stay ignored.
- Modify `README.md`: document the controlled source catalog and point operators to `customer-forwarder/`.

Do not remove the existing `relay/` bundle generator in this implementation. It remains a compatibility/simple-relay path for catalog entries whose `input` is `syslog`; Windows AD and Sysmon use the new `customer-forwarder/` HTTP JSON inputs instead of being represented as legacy syslog relay listeners.

---

### Task 1: Add The Central Source Catalog And GitOps Enforcement

**Files:**
- Create: `source-catalog/sources.yml`
- Create: `source-catalog/sources.schema.json`
- Modify: `gitops/schemas/source.schema.json`
- Modify: `scripts/lib/gitops_config.py`
- Create: `scripts/test-source-catalog.py`
- Modify: `scripts/test-gitops-config.sh`

- [ ] **Step 1: Write failing source catalog tests**

Create `scripts/test-source-catalog.py`:

```python
from __future__ import annotations

import copy
import importlib
from pathlib import Path

import pytest

from scripts.lib import gitops_config


def test_source_catalog_contains_v1_sources() -> None:
    catalog = gitops_config.load_source_catalog()
    assert sorted(catalog) == ["generic-syslog", "windows-ad", "windows-sysmon"]
    assert catalog["windows-ad"].dataset == "windows-ad"
    assert catalog["windows-ad"].parser == "windows-ad-json"
    assert catalog["windows-sysmon"].dataset == "windows-sysmon"
    assert catalog["windows-sysmon"].parser == "windows-sysmon-json"
    assert catalog["generic-syslog"].dataset == "generic-syslog"
    assert catalog["generic-syslog"].parser == "generic-syslog"


def test_catalog_rejects_duplicate_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    original = gitops_config.read_yaml

    def fake_read_yaml(path: Path) -> dict:
        doc = original(path)
        if path.name == "sources.yml" and path.parent.name == "source-catalog":
            doc = copy.deepcopy(doc)
            doc["sources"].append(copy.deepcopy(doc["sources"][0]))
        return doc

    monkeypatch.setattr(gitops_config, "read_yaml", fake_read_yaml)
    with pytest.raises(ValueError, match="duplicate source catalog id"):
        gitops_config.load_source_catalog()


def test_catalog_rejects_duplicate_datasets(monkeypatch: pytest.MonkeyPatch) -> None:
    original = gitops_config.read_yaml

    def fake_read_yaml(path: Path) -> dict:
        doc = original(path)
        if path.name == "sources.yml" and path.parent.name == "source-catalog":
            doc = copy.deepcopy(doc)
            doc["sources"][1]["dataset"] = doc["sources"][0]["dataset"]
        return doc

    monkeypatch.setattr(gitops_config, "read_yaml", fake_read_yaml)
    with pytest.raises(ValueError, match="duplicate source catalog dataset"):
        gitops_config.load_source_catalog()


def test_gitops_source_must_match_catalog(monkeypatch: pytest.MonkeyPatch) -> None:
    catalog = gitops_config.load_source_catalog()
    customers = gitops_config.load_customers()
    retention_names = gitops_config.load_retention_policy_names()
    original = gitops_config.read_yaml

    def fake_read_yaml(path: Path) -> dict:
        doc = original(path)
        if path.name == "generic-syslog.yml":
            doc = copy.deepcopy(doc)
            doc["dataset"] = "firewall"
        return doc

    monkeypatch.setattr(gitops_config, "read_yaml", fake_read_yaml)
    with pytest.raises(ValueError, match="catalog dataset"):
        gitops_config.load_sources(customers, retention_names, catalog)
```

- [ ] **Step 2: Run the new test and verify it fails**

Run:

```bash
.venv/bin/python -m pytest scripts/test-source-catalog.py -q
```

Expected: FAIL because `load_source_catalog` does not exist.

- [ ] **Step 3: Add the catalog files**

Create `source-catalog/sources.yml`:

```yaml
sources:
  - id: windows-ad
    dataset: windows-ad
    parser: windows-ad-json
    input: winlogbeat-json
    description: Windows Active Directory security/domain controller events

  - id: windows-sysmon
    dataset: windows-sysmon
    parser: windows-sysmon-json
    input: winlogbeat-json
    description: Windows Sysmon process, network, file, registry, and driver events

  - id: generic-syslog
    dataset: generic-syslog
    parser: generic-syslog
    input: syslog
    description: Generic RFC3164/RFC5424 syslog from network, Linux, and appliances
```

Create `source-catalog/sources.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["sources"],
  "additionalProperties": false,
  "properties": {
    "sources": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "required": ["id", "dataset", "parser", "input", "description"],
        "additionalProperties": false,
        "properties": {
          "id": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,40}$" },
          "dataset": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,40}$" },
          "parser": {
            "type": "string",
            "enum": ["generic-syslog", "windows-ad-json", "windows-sysmon-json"]
          },
          "input": {
            "type": "string",
            "enum": ["syslog", "winlogbeat-json"]
          },
          "description": { "type": "string", "minLength": 1 }
        }
      }
    }
  }
}
```

- [ ] **Step 4: Update the central source schema parser field**

In `gitops/schemas/source.schema.json`, replace the duplicated `parser` enum
with a safe string pattern:

```json
"parser": { "type": "string", "pattern": "^[a-z][a-z0-9-]{1,40}$" },
```

Do not duplicate the parser enum in this GitOps source schema. Exact parser
membership is enforced by `load_source_catalog()` plus the per-source catalog
match in `load_sources()`, so adding a future parser requires changing the
catalog once instead of updating two enums.

- [ ] **Step 5: Implement catalog loading and enforcement**

In `scripts/lib/gitops_config.py`, add this dataclass after `Source`:

```python
@dataclass(frozen=True)
class SourceCatalogEntry:
    id: str
    dataset: str
    parser: str
    input: str
    description: str
```

Add constants near `DESIRED` and `SCHEMAS`:

```python
SOURCE_CATALOG = REPO_ROOT / "source-catalog" / "sources.yml"
SOURCE_CATALOG_SCHEMA = REPO_ROOT / "source-catalog" / "sources.schema.json"
```

Replace the existing `validate_schema` helper with a path-capable pair:

```python
def validate_schema_file(document: dict[str, Any], schema_path: Path, path: Path) -> None:
    schema = read_json(schema_path)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    if errors:
        rendered = "; ".join(f"{'/'.join(map(str, error.path))}: {error.message}" for error in errors)
        raise ValueError(f"{path}: {rendered}")


def validate_schema(document: dict[str, Any], schema_name: str, path: Path) -> None:
    validate_schema_file(document, SCHEMAS / schema_name, path)
```

Add this function after `load_retention_policy_names`:

```python
def load_source_catalog() -> dict[str, SourceCatalogEntry]:
    doc = read_yaml(SOURCE_CATALOG)
    validate_schema_file(doc, SOURCE_CATALOG_SCHEMA, SOURCE_CATALOG)

    result: dict[str, SourceCatalogEntry] = {}
    seen_datasets: set[str] = set()
    for item in doc["sources"]:
        sid = item["id"]
        dataset = item["dataset"]
        if sid in result:
            raise ValueError(f"{SOURCE_CATALOG}: duplicate source catalog id {sid}")
        if dataset in seen_datasets:
            raise ValueError(f"{SOURCE_CATALOG}: duplicate source catalog dataset {dataset}")
        seen_datasets.add(dataset)
        result[sid] = SourceCatalogEntry(
            id=sid,
            dataset=dataset,
            parser=item["parser"],
            input=item["input"],
            description=item["description"],
        )
    return result
```

Change the signature of `load_sources`:

```python
def load_sources(
    customers: dict[str, Customer],
    retention_names: set[str],
    source_catalog: dict[str, SourceCatalogEntry],
) -> list[Source]:
```

Inside `load_sources`, after `customer = doc["customer"]`, add:

```python
            catalog_entry = source_catalog.get(doc["id"])
            if catalog_entry is None:
                raise ValueError(f"{path}: source id {doc['id']} is not in source catalog")
            if doc["dataset"] != catalog_entry.dataset:
                raise ValueError(
                    f"{path}: catalog dataset for {doc['id']} is {catalog_entry.dataset}, got {doc['dataset']}"
                )
            if doc["parser"] != catalog_entry.parser:
                raise ValueError(
                    f"{path}: catalog parser for {doc['id']} is {catalog_entry.parser}, got {doc['parser']}"
                )
```

Update `validate_all`:

```python
def validate_all() -> None:
    validate_global_files()
    source_catalog = load_source_catalog()
    customers = load_customers()
    retention_names = load_retention_policy_names()
    validate_customer_sidecars(customers)
    load_sources(customers, retention_names, source_catalog)
```

- [ ] **Step 6: Update render caller**

In `scripts/render-gitops-config.py`, import `load_source_catalog` and change:

```python
sources = load_sources(customers, retention_names)
```

to:

```python
source_catalog = load_source_catalog()
sources = load_sources(customers, retention_names, source_catalog)
```

- [ ] **Step 7: Add source catalog test to GitOps test wrapper**

In `scripts/test-gitops-config.sh`, replace:

```bash
"${PYTHON:-python3}" scripts/validate-gitops-config.py
echo "gitops config validation passed"
```

with:

```bash
"${PYTHON:-python3}" scripts/validate-gitops-config.py
"${PYTHON:-python3}" -m pytest scripts/test-source-catalog.py -q
echo "gitops config validation passed"
```

- [ ] **Step 8: Run the focused test**

Run:

```bash
.venv/bin/python -m pytest scripts/test-source-catalog.py -q
```

Expected: FAIL until Task 2 migrates the existing sample `firewall`/`windows` sources into catalog IDs.

Do not commit yet.

---

### Task 2: Migrate The Sample Customer Sources To Catalog IDs

**Files:**
- Delete: `gitops/desired/customers/acme/sources/firewall.yml`
- Delete: `gitops/desired/customers/acme/sources/windows.yml`
- Create: `gitops/desired/customers/acme/sources/generic-syslog.yml`
- Create: `gitops/desired/customers/acme/sources/windows-ad.yml`
- Create: `gitops/desired/customers/acme/sources/windows-sysmon.yml`
- Modify generated: `gitops/rendered/**`
- Modify: `scripts/render-gitops-config.py`
- Modify: `scripts/test-rendered-gitops-config.sh`
- Modify: `scripts/generate-relay-bundle.sh`
- Modify: `scripts/test-relay-bundle.sh`
- Modify: `README.md`

- [ ] **Step 1: Replace the desired source files**

Delete `gitops/desired/customers/acme/sources/firewall.yml` and `gitops/desired/customers/acme/sources/windows.yml`.

Create `gitops/desired/customers/acme/sources/generic-syslog.yml`:

```yaml
apiVersion: siem.local/v1
kind: Source
customer: acme
id: generic-syslog
name: Acme generic syslog
dataset: generic-syslog
parser: generic-syslog
retentionPolicy: critical-30d
priority: critical
dailyVolumeBudgetGb: 2
enabled: true
```

Create `gitops/desired/customers/acme/sources/windows-ad.yml`:

```yaml
apiVersion: siem.local/v1
kind: Source
customer: acme
id: windows-ad
name: Acme Windows Active Directory events
dataset: windows-ad
parser: windows-ad-json
retentionPolicy: standard-7d
priority: standard
dailyVolumeBudgetGb: 2
enabled: true
```

Create `gitops/desired/customers/acme/sources/windows-sysmon.yml`:

```yaml
apiVersion: siem.local/v1
kind: Source
customer: acme
id: windows-sysmon
name: Acme Windows Sysmon events
dataset: windows-sysmon
parser: windows-sysmon-json
retentionPolicy: standard-7d
priority: standard
dailyVolumeBudgetGb: 1
enabled: true
```

- [ ] **Step 2: Render generated GitOps artifacts**

First update `scripts/render-gitops-config.py` so stale managed index templates
are removed before new current-source templates are written. Add this helper
after `write_json`:

```python
def remove_stale_index_templates(expected_names: set[str]) -> None:
    template_dir = REPO_ROOT / "gitops/rendered/opensearch/index-templates"
    template_dir.mkdir(parents=True, exist_ok=True)
    for path in sorted(template_dir.glob("*.json")):
        if path.name not in expected_names:
            path.unlink()
```

Inside `render()`, before the loop that writes per-source templates, compute and
clean the expected generated template names:

```python
    expected_template_names: set[str] = set()
    for source in sources:
        stream = f"logs-{source.customer}-{source.dataset}"
        expected_template_names.add(f"{stream}-template.json")
        expected_template_names.add(f"{stream}-quarantine-template.json")
    for customer in customers.values():
        unknown_stream = f"logs-{customer.slug}-unknown-quarantine"
        expected_template_names.add(f"{unknown_stream}-template.json")
    remove_stale_index_templates(expected_template_names)
```

Then render:

Run:

```bash
.venv/bin/python scripts/render-gitops-config.py
```

Expected output:

```text
rendered gitops config
```

Expected generated stream names now include:

```text
logs-acme-generic-syslog
logs-acme-windows-ad
logs-acme-windows-sysmon
logs-acme-unknown-quarantine
alerts-acme
```

Expected old generated files for `logs-acme-firewall*` and `logs-acme-windows*` are removed from git.

- [ ] **Step 3: Update rendered GitOps assertions**

In `scripts/test-rendered-gitops-config.sh`, replace the old firewall template
existence check:

```bash
test -f gitops/rendered/opensearch/index-templates/logs-acme-firewall-template.json
```

with:

```bash
test -f gitops/rendered/opensearch/index-templates/logs-acme-generic-syslog-template.json
test -f gitops/rendered/opensearch/index-templates/logs-acme-windows-ad-template.json
test -f gitops/rendered/opensearch/index-templates/logs-acme-windows-sysmon-template.json
test ! -e gitops/rendered/opensearch/index-templates/logs-acme-firewall-template.json
test ! -e gitops/rendered/opensearch/index-templates/logs-acme-windows-template.json
```

- [ ] **Step 4: Keep the legacy relay bundle syslog-only**

Update `scripts/lib/gitops_config.py` so `enabled_sources_for_customer()`
filters by the canonical catalog input type. The relay bundle must render only
sources with `input: syslog`; non-syslog sources are handled by
`customer-forwarder/` and must not silently become syslog listeners.

Replace `enabled_sources_for_customer()` with:

```python
def enabled_sources_for_customer(customer_slug: str) -> list[dict[str, str]]:
    """Return enabled syslog-compatible sources for the legacy relay bundle."""
    source_dir = DESIRED / "customers" / customer_slug / "sources"
    source_catalog = load_source_catalog()
    result: list[dict[str, str]] = []
    for path in sorted(source_dir.glob("*.yml")):
        doc = read_yaml(path)
        if not doc.get("enabled", False):
            continue
        catalog_entry = source_catalog.get(doc["id"])
        if catalog_entry is None:
            raise ValueError(f"{path}: source id {doc['id']} is not in source catalog")
        if catalog_entry.input != "syslog":
            continue
        result.append({"id": doc["id"], "dataset": doc["dataset"]})
    return result
```

In `scripts/generate-relay-bundle.sh`, change the no-source error from:

```python
if not sources:
    raise SystemExit(f"no enabled sources for customer {customer_slug}")
```

to:

```python
if not sources:
    raise SystemExit(f"no enabled syslog-compatible sources for customer {customer_slug}")
```

In `scripts/test-relay-bundle.sh`, replace the final source assertions with:

```bash
bundle_dir="relay/bundles/acme"
grep -q 'port => 5514' "$bundle_dir/pipeline.conf" || { echo "missing generic-syslog port"; exit 1; }
grep -q '\[siem\]\[source_id\]" => "generic-syslog"' "$bundle_dir/pipeline.conf" || { echo "missing generic-syslog source_id"; exit 1; }
! grep -q 'port => 5515' "$bundle_dir/pipeline.conf" || { echo "unexpected windows-ad syslog port"; exit 1; }
! grep -q 'port => 5516' "$bundle_dir/pipeline.conf" || { echo "unexpected windows-sysmon syslog port"; exit 1; }
! grep -q '\[siem\]\[source_id\]" => "windows-ad"' "$bundle_dir/pipeline.conf" || { echo "unexpected windows-ad source_id in relay"; exit 1; }
! grep -q '\[siem\]\[source_id\]" => "windows-sysmon"' "$bundle_dir/pipeline.conf" || { echo "unexpected windows-sysmon source_id in relay"; exit 1; }
```

Also assert the generated relay README contains only `generic-syslog: udp/tcp
5514` from the v1 catalog sample.

- [ ] **Step 5: Update README examples**

In `README.md`, update sample source references so they name `generic-syslog`,
`windows-ad`, and `windows-sysmon`.

Replace the stream examples block under "Validate And Render GitOps Config" with:

```text
logs-acme-generic-syslog
logs-acme-windows-ad
logs-acme-windows-sysmon
logs-acme-unknown-quarantine
alerts-acme
```

Replace the sample event shape with:

```json
{
  "siem": {
    "source_id": "generic-syslog"
  },
  "message": "test event"
}
```

Replace the sample curl body with:

```bash
  -d '{"siem":{"source_id":"generic-syslog"},"message":"test event"}'
```

Add a short source catalog subsection after the stream examples:

```markdown
## Source Catalog

`source-catalog/sources.yml` is the controlled list of `siem.source_id` values.
Central GitOps source records and customer forwarder local config must use these
IDs exactly. Version one supports `generic-syslog`, `windows-ad`, and
`windows-sysmon`.
```

- [ ] **Step 6: Run focused central validation**

Run:

```bash
PYTHON=.venv/bin/python bash scripts/test-gitops-config.sh
PYTHON=.venv/bin/python bash scripts/test-rendered-gitops-config.sh
RELAY_CENTRAL_URL=https://siem.example.com:5044 PYTHON=.venv/bin/python bash scripts/test-relay-bundle.sh
```

Expected:

```text
gitops config validation passed
rendered gitops config is current
relay bundle test passed
```

- [ ] **Step 7: Commit central catalog and sample migration**

Run:

```bash
git add source-catalog gitops scripts README.md
git commit -m "feat(gitops): enforce source catalog"
```

---

### Task 3: Add Customer Forwarder Config Validation And Local Rendering

**Files:**
- Create: `customer-forwarder/requirements.txt`
- Create: `customer-forwarder/config/source-catalog.yml`
- Create: `customer-forwarder/config/source-catalog.schema.json`
- Create: `customer-forwarder/config/forwarder.yml`
- Create: `customer-forwarder/config/forwarder.schema.json`
- Create: `customer-forwarder/templates/config/logstash.yml.j2`
- Create: `customer-forwarder/templates/pipeline/00-inputs.conf.j2`
- Create: `customer-forwarder/scripts/forwarder_config.py`
- Create: `customer-forwarder/scripts/validate-config.py`
- Create: `customer-forwarder/scripts/render-config.py`
- Create: `customer-forwarder/test/test_forwarder_config.py`

- [ ] **Step 1: Create the package dependency file**

Create `customer-forwarder/requirements.txt`:

```text
Jinja2==3.1.6
jsonschema==4.23.0
PyYAML==6.0.2
pytest==8.3.3
```

Do not pin Jinja2 below `3.1.6`; the customer-distributed package should not
start with an avoidably stale template dependency. If implementation time has a
newer patched 3.1.x baseline, use that version and keep the pin in the 3.1
series unless compatibility is deliberately re-tested.

- [ ] **Step 2: Copy the central source catalog and schema**

Copy `source-catalog/sources.yml` to `customer-forwarder/config/source-catalog.yml`.
Copy `source-catalog/sources.schema.json` to `customer-forwarder/config/source-catalog.schema.json`.

Run:

```bash
cmp source-catalog/sources.yml customer-forwarder/config/source-catalog.yml
cmp source-catalog/sources.schema.json customer-forwarder/config/source-catalog.schema.json
```

Expected: both commands exit with status `0`.

- [ ] **Step 3: Create default forwarder config**

Create `customer-forwarder/config/forwarder.yml`:

```yaml
forwarder_name: customer-forwarder-01
queue:
  max_bytes: 8gb
  dlq_max_bytes: 512mb
sources:
  generic-syslog:
    enabled: true
    listen_host: 0.0.0.0
    port: 5514
  windows-ad:
    enabled: true
    listen_host: 0.0.0.0
    port: 8081
  windows-sysmon:
    enabled: true
    listen_host: 0.0.0.0
    port: 8082
```

- [ ] **Step 4: Create forwarder config schema**

Create `customer-forwarder/config/forwarder.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["forwarder_name", "queue", "sources"],
  "additionalProperties": false,
  "properties": {
    "forwarder_name": {
      "type": "string",
      "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$"
    },
    "queue": {
      "type": "object",
      "required": ["max_bytes", "dlq_max_bytes"],
      "additionalProperties": false,
      "properties": {
        "max_bytes": { "type": "string", "pattern": "^[1-9][0-9]*(mb|gb)$" },
        "dlq_max_bytes": { "type": "string", "pattern": "^[1-9][0-9]*(mb|gb)$" }
      }
    },
    "sources": {
      "type": "object",
      "minProperties": 1,
      "additionalProperties": {
        "type": "object",
        "required": ["enabled", "listen_host", "port"],
        "additionalProperties": false,
        "properties": {
          "enabled": { "type": "boolean" },
          "listen_host": { "type": "string", "pattern": "^[A-Za-z0-9._:-]+$" },
          "port": { "type": "integer", "minimum": 1, "maximum": 65535 }
        }
      }
    }
  }
}
```

- [ ] **Step 5: Write failing forwarder config tests**

Create `customer-forwarder/test/test_forwarder_config.py`:

```python
from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "forwarder_config",
    ROOT / "scripts" / "forwarder_config.py",
)
assert SPEC and SPEC.loader
forwarder_config = importlib.util.module_from_spec(SPEC)
sys.modules["forwarder_config"] = forwarder_config
SPEC.loader.exec_module(forwarder_config)


def test_load_valid_config() -> None:
    config = forwarder_config.load_validated_config(ROOT)
    assert sorted(config.enabled_source_ids()) == ["generic-syslog", "windows-ad", "windows-sysmon"]
    assert config.catalog["windows-ad"]["parser"] == "windows-ad-json"


def test_unknown_source_id_rejected(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    doc = forwarder_config.read_yaml(tmp_path / "config" / "forwarder.yml")
    doc["sources"]["not-real"] = {"enabled": True, "listen_host": "0.0.0.0", "port": 9999}
    forwarder_config.write_yaml(tmp_path / "config" / "forwarder.yml", doc)

    with pytest.raises(ValueError, match="unknown source id not-real; supported source IDs: generic-syslog, windows-ad, windows-sysmon"):
        forwarder_config.load_validated_config(tmp_path)


def test_duplicate_enabled_ports_rejected(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    doc = forwarder_config.read_yaml(tmp_path / "config" / "forwarder.yml")
    doc["sources"]["windows-ad"]["port"] = doc["sources"]["generic-syslog"]["port"]
    forwarder_config.write_yaml(tmp_path / "config" / "forwarder.yml", doc)

    with pytest.raises(ValueError, match="duplicate enabled port"):
        forwarder_config.load_validated_config(tmp_path)


def test_malicious_listen_host_rejected(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    doc = forwarder_config.read_yaml(tmp_path / "config" / "forwarder.yml")
    doc["sources"]["generic-syslog"]["listen_host"] = '0.0.0.0" } output { stdout {}'
    forwarder_config.write_yaml(tmp_path / "config" / "forwarder.yml", doc)

    with pytest.raises(ValueError, match="listen_host"):
        forwarder_config.load_validated_config(tmp_path)


def test_catalog_schema_is_validated(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    catalog = forwarder_config.read_yaml(tmp_path / "config" / "source-catalog.yml")
    del catalog["sources"][0]["parser"]
    forwarder_config.write_yaml(tmp_path / "config" / "source-catalog.yml", catalog)

    with pytest.raises(ValueError, match="parser"):
        forwarder_config.load_validated_config(tmp_path)


def test_catalog_rejects_duplicate_datasets(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    catalog = forwarder_config.read_yaml(tmp_path / "config" / "source-catalog.yml")
    catalog["sources"][1]["dataset"] = catalog["sources"][0]["dataset"]
    forwarder_config.write_yaml(tmp_path / "config" / "source-catalog.yml", catalog)

    with pytest.raises(ValueError, match="duplicate source catalog dataset"):
        forwarder_config.load_validated_config(tmp_path)


def test_queue_size_validation_rejects_oversized_dlq(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    doc = forwarder_config.read_yaml(tmp_path / "config" / "forwarder.yml")
    doc["queue"]["max_bytes"] = "512mb"
    doc["queue"]["dlq_max_bytes"] = "1gb"
    forwarder_config.write_yaml(tmp_path / "config" / "forwarder.yml", doc)

    with pytest.raises(ValueError, match="dlq_max_bytes must be less than or equal to max_bytes"):
        forwarder_config.load_validated_config(tmp_path)


def test_disk_headroom_uses_queue_and_dlq_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    config = forwarder_config.load_validated_config(tmp_path)

    class Usage:
        free = 1

    monkeypatch.setattr(forwarder_config.shutil, "disk_usage", lambda _path: Usage())
    with pytest.raises(ValueError, match="insufficient free disk"):
        forwarder_config.check_disk_headroom(tmp_path, config)


def test_render_inputs_omits_disabled_source(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    forwarder_config.copy_tree(ROOT / "templates", tmp_path / "templates")
    doc = forwarder_config.read_yaml(tmp_path / "config" / "forwarder.yml")
    doc["sources"]["windows-sysmon"]["enabled"] = False
    forwarder_config.write_yaml(tmp_path / "config" / "forwarder.yml", doc)

    config = forwarder_config.load_validated_config(tmp_path)
    rendered = forwarder_config.render_inputs(tmp_path, config)
    assert "windows-ad" in rendered
    assert "generic-syslog" in rendered
    assert "windows-sysmon" not in rendered


def test_render_logstash_uses_queue_settings(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    forwarder_config.copy_tree(ROOT / "templates", tmp_path / "templates")
    doc = forwarder_config.read_yaml(tmp_path / "config" / "forwarder.yml")
    doc["queue"]["max_bytes"] = "16gb"
    doc["queue"]["dlq_max_bytes"] = "1gb"
    forwarder_config.write_yaml(tmp_path / "config" / "forwarder.yml", doc)

    config = forwarder_config.load_validated_config(tmp_path)
    rendered = forwarder_config.render_logstash(tmp_path, config)
    assert "queue.max_bytes: 16gb" in rendered
    assert "dead_letter_queue.max_bytes: 1gb" in rendered


def test_render_inputs_uses_canonical_metadata_and_observer_name(tmp_path: Path) -> None:
    forwarder_config.copy_tree(ROOT / "config", tmp_path / "config")
    forwarder_config.copy_tree(ROOT / "templates", tmp_path / "templates")

    config = forwarder_config.load_validated_config(tmp_path)
    rendered = forwarder_config.render_inputs(tmp_path, config)
    assert '"[@metadata][forwarder][source_id]" => "windows-ad"' in rendered
    assert '"[siem][source_id]" => "windows-ad"' not in rendered
    assert '"[@metadata][forwarder][observer_name]" => "customer-forwarder-01"' in rendered
```

- [ ] **Step 6: Run the new tests and verify they fail**

Run:

```bash
PYTHONPATH=customer-forwarder .venv/bin/python -m pytest customer-forwarder/test/test_forwarder_config.py -q
```

Expected: FAIL because `customer-forwarder/scripts/forwarder_config.py` does not exist.

- [ ] **Step 7: Implement forwarder config helpers**

Create `customer-forwarder/scripts/forwarder_config.py`:

```python
from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader
from jsonschema import Draft202012Validator


SAFE_LOGSTASH_STRING = re.compile(r"^[A-Za-z0-9._:-]+$")
SIZE_RE = re.compile(r"^(?P<amount>[1-9][0-9]*)(?P<unit>mb|gb)$")
MIN_QUEUE_BYTES = 64 * 1024 * 1024
MAX_QUEUE_BYTES = 1024 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class ForwarderConfig:
    root: Path
    raw: dict[str, Any]
    catalog: dict[str, dict[str, Any]]

    def enabled_source_ids(self) -> list[str]:
        return [
            source_id
            for source_id, settings in self.raw["sources"].items()
            if settings.get("enabled") is True
        ]

    def enabled_sources(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for source_id in self.enabled_source_ids():
            settings = self.raw["sources"][source_id]
            catalog_entry = self.catalog[source_id]
            result.append({
                "id": source_id,
                "dataset": catalog_entry["dataset"],
                "parser": catalog_entry["parser"],
                "input": catalog_entry["input"],
                "forwarder_name": self.raw["forwarder_name"],
                "listen_host": settings["listen_host"],
                "port": settings["port"],
            })
        return result

    def queue_settings(self) -> dict[str, str]:
        return {
            "max_bytes": self.raw["queue"]["max_bytes"],
            "dlq_max_bytes": self.raw["queue"]["dlq_max_bytes"],
        }


def read_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected YAML mapping")
    return value


def write_yaml(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(value, handle, sort_keys=False)


def copy_tree(src: Path, dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def validate_schema(document: dict[str, Any], schema: dict[str, Any], path: Path) -> None:
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    if errors:
        rendered = "; ".join(f"{'/'.join(map(str, error.path))}: {error.message}" for error in errors)
        raise ValueError(f"{path}: {rendered}")


def parse_size_bytes(value: str) -> int:
    match = SIZE_RE.fullmatch(value)
    if not match:
        raise ValueError(f"invalid size {value!r}; expected values like 512mb or 8gb")
    amount = int(match.group("amount"))
    multiplier = 1024 * 1024 if match.group("unit") == "mb" else 1024 * 1024 * 1024
    return amount * multiplier


def load_catalog(root: Path) -> dict[str, dict[str, Any]]:
    catalog_path = root / "config" / "source-catalog.yml"
    schema_path = root / "config" / "source-catalog.schema.json"
    doc = read_yaml(catalog_path)
    schema = yaml.safe_load(schema_path.read_text(encoding="utf-8"))
    validate_schema(doc, schema, catalog_path)
    entries = doc.get("sources")
    if not isinstance(entries, list):
        raise ValueError(f"{catalog_path}: sources must be a list")
    result: dict[str, dict[str, Any]] = {}
    seen_datasets: set[str] = set()
    for entry in entries:
        source_id = entry["id"]
        dataset = entry["dataset"]
        if source_id in result:
            raise ValueError(f"{catalog_path}: duplicate source id {source_id}")
        if dataset in seen_datasets:
            raise ValueError(f"{catalog_path}: duplicate source catalog dataset {dataset}")
        seen_datasets.add(dataset)
        result[source_id] = entry
    return result


def load_validated_config(root: Path) -> ForwarderConfig:
    schema_path = root / "config" / "forwarder.schema.json"
    config_path = root / "config" / "forwarder.yml"
    schema = yaml.safe_load(schema_path.read_text(encoding="utf-8"))
    config = read_yaml(config_path)
    validate_schema(config, schema, config_path)
    catalog = load_catalog(root)

    queue_max = parse_size_bytes(config["queue"]["max_bytes"])
    dlq_max = parse_size_bytes(config["queue"]["dlq_max_bytes"])
    if queue_max < MIN_QUEUE_BYTES:
        raise ValueError(f"{config_path}: queue.max_bytes must be at least 64mb")
    if queue_max > MAX_QUEUE_BYTES:
        raise ValueError(f"{config_path}: queue.max_bytes must be 1024gb or less")
    if dlq_max > queue_max:
        raise ValueError(f"{config_path}: queue.dlq_max_bytes must be less than or equal to max_bytes")

    enabled_ports: dict[int, str] = {}
    for source_id, settings in config["sources"].items():
        if source_id not in catalog:
            supported = ", ".join(sorted(catalog))
            raise ValueError(f"{config_path}: unknown source id {source_id}; supported source IDs: {supported}")
        if not SAFE_LOGSTASH_STRING.fullmatch(settings["listen_host"]):
            raise ValueError(f"{config_path}: listen_host for {source_id} contains unsafe characters")
        if settings["enabled"]:
            port = settings["port"]
            if port in enabled_ports:
                raise ValueError(
                    f"{config_path}: duplicate enabled port {port} for {enabled_ports[port]} and {source_id}"
                )
            enabled_ports[port] = source_id
    return ForwarderConfig(root=root, raw=config, catalog=catalog)


def jinja_env(root: Path) -> Environment:
    return Environment(
        loader=FileSystemLoader(str(root)),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
    )


def render_inputs(root: Path, config: ForwarderConfig) -> str:
    template = jinja_env(root).get_template("templates/pipeline/00-inputs.conf.j2")
    return template.render(sources=config.enabled_sources()).rstrip() + "\n"


def render_logstash(root: Path, config: ForwarderConfig) -> str:
    template = jinja_env(root).get_template("templates/config/logstash.yml.j2")
    return template.render(queue=config.queue_settings()).rstrip() + "\n"


def required_queue_disk_bytes(config: ForwarderConfig) -> int:
    queue_max = parse_size_bytes(config.raw["queue"]["max_bytes"])
    dlq_max = parse_size_bytes(config.raw["queue"]["dlq_max_bytes"])
    return int((queue_max + dlq_max) * 1.2)


def check_disk_headroom(root: Path, config: ForwarderConfig) -> None:
    data_dir = root / "data" / "logstash"
    probe_dir = data_dir if data_dir.exists() else root
    free = shutil.disk_usage(probe_dir).free
    required = required_queue_disk_bytes(config)
    if free < required:
        raise ValueError(
            f"{data_dir}: insufficient free disk for persistent queue and DLQ; "
            f"need at least {required} bytes with 20% headroom, have {free}"
        )


def write_rendered_inputs(root: Path, config: ForwarderConfig) -> Path:
    path = root / "pipeline" / "00-inputs.conf"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_inputs(root, config), encoding="utf-8")
    return path


def write_rendered_logstash(root: Path, config: ForwarderConfig) -> Path:
    path = root / "config" / "logstash.yml"
    path.write_text(render_logstash(root, config), encoding="utf-8")
    return path
```

- [ ] **Step 8: Create CLI wrappers**

Create `customer-forwarder/scripts/validate-config.py`:

```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from forwarder_config import check_disk_headroom, load_validated_config


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--skip-disk-check", action="store_true")
    args = parser.parse_args()
    root = args.root
    config = load_validated_config(root)
    if not args.skip_disk_check:
        check_disk_headroom(root, config)
    print(f"customer forwarder config valid ({len(config.enabled_source_ids())} enabled sources)")


if __name__ == "__main__":
    main()
```

Create `customer-forwarder/scripts/render-config.py`:

```python
#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from forwarder_config import load_validated_config, write_rendered_inputs, write_rendered_logstash


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    config = load_validated_config(root)
    logstash_path = write_rendered_logstash(root, config)
    inputs_path = write_rendered_inputs(root, config)
    print(f"rendered {logstash_path.relative_to(root)}")
    print(f"rendered {inputs_path.relative_to(root)}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 9: Create the input template**

Create `customer-forwarder/templates/config/logstash.yml.j2`:

```yaml
http.host: "0.0.0.0"
pipeline.ecs_compatibility: v8
queue.type: persisted
queue.max_bytes: {{ queue.max_bytes }}
path.queue: /usr/share/logstash/data/queue
dead_letter_queue.enable: true
dead_letter_queue.max_bytes: {{ queue.dlq_max_bytes }}
```

Create `customer-forwarder/templates/pipeline/00-inputs.conf.j2`:

```text
{% for source in sources %}
{% if source.input == "syslog" %}
input {
  syslog {
    id => "input-{{ source.id }}"
    host => "{{ source.listen_host }}"
    port => {{ source.port }}
    ecs_compatibility => "v8"
    add_field => {
      "[@metadata][forwarder][source_id]" => "{{ source.id }}"
      "[@metadata][forwarder][dataset]" => "{{ source.dataset }}"
      "[@metadata][forwarder][observer_name]" => "{{ source.forwarder_name }}"
    }
  }
}
{% elif source.input == "winlogbeat-json" %}
input {
  http {
    id => "input-{{ source.id }}"
    host => "{{ source.listen_host }}"
    port => {{ source.port }}
    codec => "json"
    max_content_length => 1048576
    add_field => {
      "[@metadata][forwarder][source_id]" => "{{ source.id }}"
      "[@metadata][forwarder][dataset]" => "{{ source.dataset }}"
      "[@metadata][forwarder][observer_name]" => "{{ source.forwarder_name }}"
    }
  }
}
{% endif %}
{% endfor %}
output {
  pipeline {
    send_to => "parse-and-normalize"
  }
}
```

- [ ] **Step 10: Run config tests and render default inputs**

Run:

```bash
PYTHONPATH=customer-forwarder/scripts .venv/bin/python -m pytest customer-forwarder/test/test_forwarder_config.py -q
PYTHONPATH=customer-forwarder/scripts .venv/bin/python customer-forwarder/scripts/validate-config.py
PYTHONPATH=customer-forwarder/scripts .venv/bin/python customer-forwarder/scripts/render-config.py
```

Expected:

```text
11 passed
customer forwarder config valid (3 enabled sources)
rendered config/logstash.yml
rendered pipeline/00-inputs.conf
```

- [ ] **Step 11: Commit forwarder validation and rendering**

Run:

```bash
git add customer-forwarder
git commit -m "feat(forwarder): add local config validation"
```

---

### Task 4: Add Customer Forwarder Runtime Config And Parser Pipelines

**Files:**
- Create: `customer-forwarder/.env.example`
- Create: `customer-forwarder/docker-compose.yml`
- Ensure generated: `customer-forwarder/config/logstash.yml`
- Create: `customer-forwarder/config/pipelines.yml`
- Ensure generated: `customer-forwarder/pipeline/00-inputs.conf`
- Create: `customer-forwarder/pipeline/10-parse-input.conf`
- Create: `customer-forwarder/pipeline/20-parse-windows-ad.conf`
- Create: `customer-forwarder/pipeline/21-parse-windows-sysmon.conf`
- Create: `customer-forwarder/pipeline/30-parse-generic-syslog.conf`
- Create: `customer-forwarder/pipeline/80-normalize-common.conf`
- Create: `customer-forwarder/pipeline/90-output-ingest-edge.conf`
- Create: `customer-forwarder/scripts/validate-env.py`
- Create: `customer-forwarder/scripts/test-logstash-config.sh`
- Create: `customer-forwarder/test/test_forwarder_env.py`

- [ ] **Step 1: Add `.env.example`**

Create `customer-forwarder/.env.example`:

```text
CENTRAL_INGEST_URL=https://siem.example.com:5044/
CUSTOMER_FORWARDER_USERNAME=<credential-id-from-central-gitops>
CUSTOMER_FORWARDER_PASSWORD=<credential-password>
CENTRAL_CA_CERT=/usr/share/logstash/config/certs/central-ca.crt
LS_JAVA_OPTS="-Xms512m -Xmx512m"
FORWARDER_MEM_LIMIT=1g
```

- [ ] **Step 2: Add Docker Compose**

Create `customer-forwarder/docker-compose.yml`:

```yaml
x-logging: &default-logging
  driver: json-file
  options:
    max-size: "10m"
    max-file: "5"

services:
  customer-forwarder:
    image: opensearchproject/logstash-oss-with-opensearch-output-plugin:8.9.0
    container_name: customer-forwarder
    restart: unless-stopped
    mem_limit: ${FORWARDER_MEM_LIMIT:-1g}
    logging: *default-logging
    env_file:
      - .env
    environment:
      LS_JAVA_OPTS: ${LS_JAVA_OPTS:--Xms512m -Xmx512m}
      CENTRAL_INGEST_URL: ${CENTRAL_INGEST_URL}
      CUSTOMER_FORWARDER_USERNAME: ${CUSTOMER_FORWARDER_USERNAME}
      CUSTOMER_FORWARDER_PASSWORD: ${CUSTOMER_FORWARDER_PASSWORD}
      CENTRAL_CA_CERT: ${CENTRAL_CA_CERT:-/usr/share/logstash/config/certs/central-ca.crt}
    volumes:
      - ./config:/usr/share/logstash/config:ro
      - ./pipeline:/usr/share/logstash/pipeline:ro
      - ./data/logstash:/usr/share/logstash/data
      - ./certs:/usr/share/logstash/config/certs:ro
    ports:
      - "5514:5514/tcp"
      - "5514:5514/udp"
      - "8081:8081/tcp"
      - "8082:8082/tcp"
      - "127.0.0.1:9600:9600/tcp"
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:9600/_node/stats/pipelines >/dev/null 2>&1"]
      interval: 20s
      timeout: 10s
      retries: 12
      start_period: 60s
```

- [ ] **Step 3: Add pipeline settings**

Verify `customer-forwarder/config/logstash.yml` was generated by Task 3 and
contains the queue values from `customer-forwarder/config/forwarder.yml`:

```yaml
http.host: "0.0.0.0"
pipeline.ecs_compatibility: v8
queue.type: persisted
queue.max_bytes: 8gb
path.queue: /usr/share/logstash/data/queue
dead_letter_queue.enable: true
dead_letter_queue.max_bytes: 512mb
```

Create `customer-forwarder/config/pipelines.yml`:

```yaml
- pipeline.id: inputs
  path.config: /usr/share/logstash/pipeline/00-inputs.conf
  pipeline.workers: 1
  pipeline.batch.size: 125
  pipeline.batch.delay: 50
- pipeline.id: parse-and-normalize
  path.config:
    - /usr/share/logstash/pipeline/10-parse-input.conf
    - /usr/share/logstash/pipeline/20-parse-windows-ad.conf
    - /usr/share/logstash/pipeline/21-parse-windows-sysmon.conf
    - /usr/share/logstash/pipeline/30-parse-generic-syslog.conf
    - /usr/share/logstash/pipeline/80-normalize-common.conf
  pipeline.workers: 2
  pipeline.batch.size: 125
  pipeline.batch.delay: 50
- pipeline.id: output-ingest-edge
  path.config: /usr/share/logstash/pipeline/90-output-ingest-edge.conf
  pipeline.workers: 1
  pipeline.batch.size: 125
  pipeline.batch.delay: 50
```

- [ ] **Step 4: Add parser pipelines**

Create `customer-forwarder/pipeline/10-parse-input.conf`:

```text
input {
  pipeline {
    address => "parse-and-normalize"
  }
}

filter {
  mutate {
    remove_field => [
      "[siem]",
      "[customer]",
      "[data_stream]",
      "[@metadata][target_index]",
      "[@metadata][target_stream]"
    ]
  }

  mutate {
    replace => {
      "[siem][source_id]" => "%{[@metadata][forwarder][source_id]}"
      "[event][dataset]" => "%{[@metadata][forwarder][dataset]}"
      "[observer][type]" => "customer-forwarder"
      "[observer][name]" => "%{[@metadata][forwarder][observer_name]}"
    }
  }
}
```

This file is the canonicalization boundary. It deliberately discards
client-supplied routing fields before parser branching so a sender on one local
collector port cannot spoof another `siem.source_id`, `customer`,
`data_stream`, or output-routing metadata value.

Create `customer-forwarder/pipeline/20-parse-windows-ad.conf`:

```text
filter {
  if [siem][source_id] == "windows-ad" {
    mutate {
      add_tag => ["_source_catalog_validated"]
      add_field => {
        "[event][kind]" => "event"
        "[event][category]" => "authentication"
      }
    }
    if [winlog][event_id] {
      mutate { copy => { "[winlog][event_id]" => "[event][code]" } }
    }
    if [event][code] in ["4624", "4634"] {
      mutate {
        replace => { "[event][action]" => "logon" }
        add_field => { "[event][type]" => "start" }
      }
    } else if [event][code] == "4625" {
      mutate {
        replace => { "[event][action]" => "logon-failed" }
        add_field => { "[event][type]" => "denied" }
        replace => { "[event][outcome]" => "failure" }
      }
    } else {
      mutate {
        replace => { "[event][action]" => "windows-ad-event" }
        add_field => { "[event][type]" => "info" }
      }
    }
  }
}
```

Create `customer-forwarder/pipeline/21-parse-windows-sysmon.conf`:

```text
filter {
  if [siem][source_id] == "windows-sysmon" {
    mutate {
      add_tag => ["_source_catalog_validated"]
      add_field => {
        "[event][kind]" => "event"
        "[event][category]" => "process"
      }
    }
    if [winlog][event_id] {
      mutate { copy => { "[winlog][event_id]" => "[event][code]" } }
    }
    if [event][code] == "1" {
      mutate {
        replace => { "[event][action]" => "process-created" }
        add_field => { "[event][type]" => "start" }
      }
    } else if [event][code] == "3" {
      mutate {
        replace => { "[event][action]" => "network-connection" }
        replace => { "[event][category]" => "network" }
        add_field => { "[event][type]" => "connection" }
      }
    } else {
      mutate {
        replace => { "[event][action]" => "sysmon-event" }
        add_field => { "[event][type]" => "info" }
      }
    }
  }
}
```

Create `customer-forwarder/pipeline/30-parse-generic-syslog.conf`:

```text
filter {
  if [siem][source_id] == "generic-syslog" {
    mutate {
      add_tag => ["_source_catalog_validated"]
      add_field => {
        "[event][kind]" => "event"
        "[event][category]" => "host"
        "[event][type]" => "info"
      }
    }
  }
}
```

Create `customer-forwarder/pipeline/80-normalize-common.conf`:

```text
filter {
  if ![event][original] and [message] {
    mutate {
      copy => {
        "message" => "[event][original]"
      }
    }
  }

  if ![siem][source_id] {
    mutate {
      add_tag => ["_parser_failure"]
      add_field => { "[siem][forwarder_error]" => "missing_source_id" }
    }
  }

  ruby {
    code => 'event.set("[event][ingested]", Time.now.utc.iso8601(3))'
  }
}

output {
  pipeline {
    send_to => "output-ingest-edge"
  }
}
```

Create `customer-forwarder/pipeline/90-output-ingest-edge.conf`:

```text
input {
  pipeline {
    address => "output-ingest-edge"
  }
}

output {
  http {
    url => "${CENTRAL_INGEST_URL}"
    http_method => "post"
    format => "json"
    content_type => "application/json"
    user => "${CUSTOMER_FORWARDER_USERNAME}"
    password => "${CUSTOMER_FORWARDER_PASSWORD}"
    ssl_verification_mode => "full"
    ssl_certificate_authorities => ["${CENTRAL_CA_CERT}"]
    retry_failed => true
    automatic_retries => 3
    pool_max => 16
    pool_max_per_route => 16
    connect_timeout => 10
    socket_timeout => 30
    request_timeout => 30
  }
}
```

- [ ] **Step 5: Add environment validation**

Create `customer-forwarder/scripts/validate-env.py`:

```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import ipaddress
import re
import ssl
from pathlib import Path
from urllib.parse import urlparse


CERT_PREFIX = "/usr/share/logstash/config/certs/"
KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
SIZE_RE = re.compile(r"^(?P<amount>[1-9][0-9]*)(?P<unit>m|g)$")
HEAP_RE = re.compile(r"^-Xms(?P<xms>[1-9][0-9]*[mg])\s+-Xmx(?P<xmx>[1-9][0-9]*[mg])$")
ALLOWED_KEYS = {
    "CENTRAL_INGEST_URL",
    "CUSTOMER_FORWARDER_USERNAME",
    "CUSTOMER_FORWARDER_PASSWORD",
    "CENTRAL_CA_CERT",
    "LS_JAVA_OPTS",
    "FORWARDER_MEM_LIMIT",
}
def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for lineno, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            fail(f"{path}:{lineno}: export syntax is not supported")
        if "=" not in line:
            fail(f"{path}:{lineno}: expected KEY=value")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not KEY_RE.fullmatch(key):
            fail(f"{path}:{lineno}: invalid environment key {key!r}")
        if key not in ALLOWED_KEYS:
            fail(f"{path}:{lineno}: unsupported environment key {key}")
        if value.startswith(("'", '"')):
            quote = value[0]
            if len(value) < 2 or value[-1] != quote:
                fail(f"{path}:{lineno}: unmatched quote for {key}")
            value = value[1:-1]
        if "$(" in value or "`" in value:
            fail(f"{path}:{lineno}: command substitution is not allowed in {key}")
        values[key] = value
    return values


def require(values: dict[str, str], name: str) -> str:
    value = values.get(name, "")
    if not value:
        fail(f"{name} is required")
    if CONTROL_RE.search(value):
        fail(f"{name} contains control characters")
    return value


def parse_size_bytes(value: str) -> int:
    match = SIZE_RE.fullmatch(value.lower())
    if not match:
        fail(f"invalid size {value!r}; expected values like 512m or 1g")
    amount = int(match.group("amount"))
    multiplier = 1024 * 1024 if match.group("unit") == "m" else 1024 * 1024 * 1024
    return amount * multiplier


def validate_url(value: str) -> None:
    if any(ch.isspace() for ch in value):
        fail("CENTRAL_INGEST_URL must not contain whitespace")
    parsed = urlparse(value)
    if parsed.scheme != "https":
        fail("CENTRAL_INGEST_URL must use https")
    if not parsed.netloc or not parsed.hostname:
        fail("CENTRAL_INGEST_URL must include a host")
    if parsed.username or parsed.password:
        fail("CENTRAL_INGEST_URL must not include username or password")
    try:
        parsed.port
    except ValueError as exc:
        fail("CENTRAL_INGEST_URL port must be a number between 0 and 65535")
    host = parsed.hostname.rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if (
            not labels
            or any(not label for label in labels)
            or any(len(label) > 63 for label in labels)
            or len(host) > 253
            or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label) for label in labels)
        ):
            fail("CENTRAL_INGEST_URL host must be a valid DNS name or IP address")


def host_ca_path(root: Path, container_path: str) -> Path:
    if not container_path.startswith(CERT_PREFIX):
        fail(f"CENTRAL_CA_CERT must be under {CERT_PREFIX}")
    relative = container_path.removeprefix(CERT_PREFIX)
    if not relative or ".." in Path(relative).parts:
        fail("CENTRAL_CA_CERT must not contain path traversal")
    certs_root = (root / "certs").resolve()
    ca_path = (certs_root / relative).resolve()
    if not ca_path.is_relative_to(certs_root):
        fail("CENTRAL_CA_CERT must resolve under customer-forwarder/certs")
    return ca_path


def validate_ca(root: Path, container_path: str) -> None:
    ca_path = host_ca_path(root, container_path)
    if not ca_path.is_file():
        fail(f"CENTRAL_CA_CERT host file is missing: {ca_path}")
    content = ca_path.read_text(encoding="utf-8", errors="replace").strip()
    if not content.startswith("-----BEGIN CERTIFICATE-----"):
        fail("CENTRAL_CA_CERT must be a non-empty PEM certificate")
    try:
        ssl.PEM_cert_to_DER_cert(content)
    except ValueError as exc:
        fail(f"CENTRAL_CA_CERT is not parseable PEM: {exc}")


def validate_heap(values: dict[str, str]) -> None:
    heap = values.get("LS_JAVA_OPTS", "-Xms512m -Xmx512m")
    match = HEAP_RE.fullmatch(heap)
    if not match:
        fail('LS_JAVA_OPTS must look like "-Xms512m -Xmx512m"')
    xms = parse_size_bytes(match.group("xms"))
    xmx = parse_size_bytes(match.group("xmx"))
    if xms != xmx:
        fail("LS_JAVA_OPTS must use matching Xms and Xmx for predictable sizing")
    mem_limit = parse_size_bytes(values.get("FORWARDER_MEM_LIMIT", "1g"))
    if xmx > int(mem_limit * 0.75):
        fail("LS_JAVA_OPTS Xmx must be no more than 75% of FORWARDER_MEM_LIMIT")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--env-file", type=Path)
    args = parser.parse_args()

    values = {key: value for key, value in os.environ.items() if key in ALLOWED_KEYS}
    env_file = args.env_file if args.env_file else args.root / ".env"
    if env_file.exists():
        values.update(parse_env_file(env_file))

    url = require(values, "CENTRAL_INGEST_URL")
    username = require(values, "CUSTOMER_FORWARDER_USERNAME")
    password = require(values, "CUSTOMER_FORWARDER_PASSWORD")
    ca_cert = require(values, "CENTRAL_CA_CERT")
    validate_url(url)
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", username):
        fail("CUSTOMER_FORWARDER_USERNAME contains unsupported characters")
    if username.startswith("<") or username == "customer-primary":
        fail("CUSTOMER_FORWARDER_USERNAME must be replaced with a real central credential id")
    if password.startswith("<") or password in {"change-me", "changeme"}:
        fail("CUSTOMER_FORWARDER_PASSWORD must be replaced")
    validate_ca(args.root, ca_cert)
    validate_heap(values)
    print("customer forwarder environment valid")


if __name__ == "__main__":
    main()
```

Add negative tests to a new `customer-forwarder/test/test_forwarder_env.py`:

```python
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate-env.py"
PEM = """-----BEGIN CERTIFICATE-----
QUJD
-----END CERTIFICATE-----
"""


def run_validator(root: Path, env_file: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(root), "--env-file", str(env_file)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def write_valid_env(tmp_path: Path, **overrides: str) -> Path:
    ca = tmp_path / "certs" / "central-ca.crt"
    ca.parent.mkdir(parents=True, exist_ok=True)
    ca.write_text(PEM, encoding="utf-8")
    values = {
        "CENTRAL_INGEST_URL": "https://siem.example.com:5044/",
        "CUSTOMER_FORWARDER_USERNAME": "acme-primary",
        "CUSTOMER_FORWARDER_PASSWORD": "not-a-placeholder",
        "CENTRAL_CA_CERT": "/usr/share/logstash/config/certs/central-ca.crt",
        "LS_JAVA_OPTS": '"-Xms512m -Xmx512m"',
        "FORWARDER_MEM_LIMIT": "1g",
    }
    values.update(overrides)
    env_file = tmp_path / ".env"
    env_file.write_text("\n".join(f"{key}={value}" for key, value in values.items()) + "\n", encoding="utf-8")
    return env_file


def test_env_validation_accepts_safe_values(tmp_path: Path) -> None:
    result = run_validator(tmp_path, write_valid_env(tmp_path))
    assert result.returncode == 0, result.stdout
    assert "customer forwarder environment valid" in result.stdout


def test_env_validation_rejects_http(tmp_path: Path) -> None:
    result = run_validator(tmp_path, write_valid_env(tmp_path, CENTRAL_INGEST_URL="http://siem.example.com:5044/"))
    assert result.returncode != 0
    assert "must use https" in result.stdout


def test_env_validation_rejects_placeholder_password(tmp_path: Path) -> None:
    result = run_validator(tmp_path, write_valid_env(tmp_path, CUSTOMER_FORWARDER_PASSWORD="change-me"))
    assert result.returncode != 0
    assert "must be replaced" in result.stdout


def test_env_validation_rejects_command_substitution_without_executing(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    env_file = write_valid_env(tmp_path, CUSTOMER_FORWARDER_PASSWORD=f"$(touch {marker})")
    result = run_validator(tmp_path, env_file)
    assert result.returncode != 0
    assert "command substitution is not allowed" in result.stdout
    assert not marker.exists()


def test_env_validation_rejects_ca_path_outside_mounted_cert_dir(tmp_path: Path) -> None:
    outside_ca = tmp_path / "outside-ca.crt"
    outside_ca.write_text(PEM, encoding="utf-8")
    result = run_validator(tmp_path, write_valid_env(tmp_path, CENTRAL_CA_CERT=str(outside_ca)))
    assert result.returncode != 0
    assert "must be under /usr/share/logstash/config/certs/" in result.stdout


def test_env_validation_rejects_non_pem_ca(tmp_path: Path) -> None:
    env_file = write_valid_env(tmp_path)
    (tmp_path / "certs" / "central-ca.crt").write_text("test ca\n", encoding="utf-8")
    result = run_validator(tmp_path, env_file)
    assert result.returncode != 0
    assert "must be a non-empty PEM certificate" in result.stdout
```

- [ ] **Step 6: Add Logstash config validation wrapper**

Create `customer-forwarder/scripts/test-logstash-config.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

PYTHONPATH="$repo_root/scripts" "${PYTHON:-python3}" scripts/validate-config.py
PYTHONPATH="$repo_root/scripts" "${PYTHON:-python3}" scripts/render-config.py

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

mkdir -p "$tmp_dir/certs"
cat > "$tmp_dir/certs/central-ca.crt" <<'PEM'
-----BEGIN CERTIFICATE-----
QUJD
-----END CERTIFICATE-----
PEM

cat > "$tmp_dir/test.env" <<'ENV'
CENTRAL_INGEST_URL=https://siem.example.com:5044/
CUSTOMER_FORWARDER_USERNAME=test-forwarder
CUSTOMER_FORWARDER_PASSWORD=test-password
CENTRAL_CA_CERT=/usr/share/logstash/config/certs/central-ca.crt
LS_JAVA_OPTS="-Xms512m -Xmx512m"
FORWARDER_MEM_LIMIT=1g
ENV

env_file="${CUSTOMER_FORWARDER_ENV_FILE:-}"
env_root="$repo_root"
if [[ -z "$env_file" ]]; then
  if [[ -f .env ]]; then
    env_file="$repo_root/.env"
  else
    env_file="$tmp_dir/test.env"
    env_root="$tmp_dir"
  fi
fi

PYTHONPATH="$repo_root/scripts" "${PYTHON:-python3}" scripts/validate-env.py \
  --root "$env_root" \
  --env-file "$env_file"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "docker unavailable; skipped customer forwarder live logstash config validation"
  exit 0
fi

mkdir -p "$tmp_dir/config" "$tmp_dir/data"
cp config/pipelines.yml "$tmp_dir/config/pipelines.yml"
sed 's#^path.queue:.*#path.queue: /tmp/customer-forwarder-test-data/queue#' \
  config/logstash.yml > "$tmp_dir/config/logstash.yml"
printf 'path.data: /tmp/customer-forwarder-test-data\n' >> "$tmp_dir/config/logstash.yml"

cat > "$tmp_dir/docker-compose.override.yml" <<YAML
services:
  customer-forwarder:
    env_file:
      - $tmp_dir/test.env
    volumes:
      - $tmp_dir/config:/usr/share/logstash/config:ro
      - $repo_root/pipeline:/usr/share/logstash/pipeline:ro
      - $tmp_dir/data:/tmp/customer-forwarder-test-data
      - $tmp_dir/certs:/usr/share/logstash/config/certs:ro
YAML

docker compose -f docker-compose.yml -f "$tmp_dir/docker-compose.override.yml" run --rm --no-deps \
  -e CENTRAL_INGEST_URL=https://siem.example.com:5044/ \
  -e CUSTOMER_FORWARDER_USERNAME=test-forwarder \
  -e CUSTOMER_FORWARDER_PASSWORD=test-password \
  -e CENTRAL_CA_CERT=/usr/share/logstash/config/certs/central-ca.crt \
  customer-forwarder \
  logstash --path.settings /usr/share/logstash/config --config.test_and_exit

echo "customer forwarder logstash config passed"
```

Run:

```bash
chmod +x customer-forwarder/scripts/test-logstash-config.sh
```

- [ ] **Step 7: Run focused runtime validation**

Run:

```bash
PYTHON=.venv/bin/python bash customer-forwarder/scripts/test-logstash-config.sh
```

Expected with Docker available:

```text
customer forwarder config valid (3 enabled sources)
rendered config/logstash.yml
rendered pipeline/00-inputs.conf
customer forwarder environment valid
customer forwarder logstash config passed
```

Expected without Docker:

```text
customer forwarder config valid (3 enabled sources)
rendered config/logstash.yml
rendered pipeline/00-inputs.conf
customer forwarder environment valid
docker unavailable; skipped customer forwarder live logstash config validation
```

- [ ] **Step 8: Commit runtime package**

Run:

```bash
git add customer-forwarder
git commit -m "feat(forwarder): add logstash runtime package"
```

---

### Task 5: Add Fixture Tests, Repo Wrapper, Ignore Rules, And Docs

**Files:**
- Create: `customer-forwarder/test/fixtures/windows-ad.json`
- Create: `customer-forwarder/test/fixtures/windows-sysmon.json`
- Create: `customer-forwarder/test/fixtures/generic-syslog.log`
- Create: `customer-forwarder/test/test_catalog_copy.py`
- Create: `customer-forwarder/test/test_compose_config.py`
- Create: `customer-forwarder/scripts/parser-smoke.py`
- Create: `customer-forwarder/scripts/load-smoke.py`
- Create: `scripts/test-customer-forwarder.sh`
- Modify: `.gitignore`
- Modify: `scripts/test-secret-ignore.sh`
- Create: `customer-forwarder/README.md`
- Modify: `README.md`

- [ ] **Step 1: Add fixture files**

Create `customer-forwarder/test/fixtures/windows-ad.json`:

```json
{
  "@timestamp": "2026-06-10T10:00:00.000Z",
  "host": { "name": "dc01" },
  "winlog": {
    "channel": "Security",
    "event_id": "4625",
    "provider_name": "Microsoft-Windows-Security-Auditing"
  },
  "user": { "name": "alice", "domain": "ACME" },
  "source": { "ip": "203.0.113.10" },
  "message": "An account failed to log on."
}
```

Create `customer-forwarder/test/fixtures/windows-sysmon.json`:

```json
{
  "@timestamp": "2026-06-10T10:01:00.000Z",
  "host": { "name": "workstation01" },
  "winlog": { "event_id": "1", "provider_name": "Microsoft-Windows-Sysmon" },
  "process": {
    "name": "powershell.exe",
    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "command_line": "powershell.exe -NoProfile",
    "pid": 4242
  },
  "message": "Process Create"
}
```

Create `customer-forwarder/test/fixtures/generic-syslog.log`:

```text
<134>Jun 10 10:02:00 firewall01 filterlog: allow tcp 192.0.2.10 198.51.100.20 443
```

- [ ] **Step 2: Add catalog copy test**

Create `customer-forwarder/test/test_catalog_copy.py`:

```python
from __future__ import annotations

from pathlib import Path


def test_customer_forwarder_catalog_matches_main_catalog() -> None:
    repo = Path(__file__).resolve().parents[2]
    assert (
        repo / "source-catalog" / "sources.yml"
    ).read_text(encoding="utf-8") == (
        repo / "customer-forwarder" / "config" / "source-catalog.yml"
    ).read_text(encoding="utf-8")


def test_customer_forwarder_catalog_schema_matches_main_catalog_schema() -> None:
    repo = Path(__file__).resolve().parents[2]
    assert (
        repo / "source-catalog" / "sources.schema.json"
    ).read_text(encoding="utf-8") == (
        repo / "customer-forwarder" / "config" / "source-catalog.schema.json"
    ).read_text(encoding="utf-8")
```

- [ ] **Step 3: Add Compose and pipeline config tests**

Create `customer-forwarder/test/test_compose_config.py`:

```python
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "forwarder_config",
    ROOT / "scripts" / "forwarder_config.py",
)
assert SPEC and SPEC.loader
forwarder_config = importlib.util.module_from_spec(SPEC)
sys.modules["forwarder_config"] = forwarder_config
SPEC.loader.exec_module(forwarder_config)


def test_compose_ports_match_enabled_forwarder_sources() -> None:
    config = forwarder_config.load_validated_config(ROOT)
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    ports = set(compose["services"]["customer-forwarder"]["ports"])
    for source in config.enabled_sources():
        assert f"{source['port']}:{source['port']}/tcp" in ports
        if source["input"] == "syslog":
            assert f"{source['port']}:{source['port']}/udp" in ports
    assert "127.0.0.1:9600:9600/tcp" in ports


def test_pipelines_have_explicit_worker_and_batch_settings() -> None:
    pipelines = yaml.safe_load((ROOT / "config" / "pipelines.yml").read_text(encoding="utf-8"))
    for pipeline in pipelines:
        assert "pipeline.workers" in pipeline
        assert "pipeline.batch.size" in pipeline
        assert "pipeline.batch.delay" in pipeline


def test_parse_pipeline_has_receiver() -> None:
    receiver = (ROOT / "pipeline" / "10-parse-input.conf").read_text(encoding="utf-8")
    assert 'address => "parse-and-normalize"' in receiver
    assert 'remove_field => [' in receiver
    assert '"[siem][source_id]" => "%{[@metadata][forwarder][source_id]}"' in receiver


def test_compose_has_runtime_guardrails() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    service = compose["services"]["customer-forwarder"]
    assert service["mem_limit"] == "${FORWARDER_MEM_LIMIT:-1g}"
    assert service["logging"]["options"]["max-size"] == "10m"
    assert service["logging"]["options"]["max-file"] == "5"
    assert service["environment"]["LS_JAVA_OPTS"] == "${LS_JAVA_OPTS:--Xms512m -Xmx512m}"
```

- [ ] **Step 4: Add Docker-backed parser fixture smoke**

Create `customer-forwarder/scripts/parser-smoke.py`:

```python
#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def docker_available() -> bool:
    return shutil.which("docker") is not None and subprocess.run(
        ["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
    ).returncode == 0


def post_json(url: str, path: Path) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status >= 300:
            raise RuntimeError(f"unexpected HTTP status {response.status}")


def send_syslog(host: str, port: int, message: str) -> None:
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.sendall(message.encode("utf-8") + b"\n")


def main() -> None:
    if not docker_available():
        print("docker unavailable; skipped customer forwarder parser smoke")
        return

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        config = tmp_path / "config"
        pipeline = tmp_path / "pipeline"
        output = tmp_path / "out"
        data = tmp_path / "data"
        shutil.copytree(ROOT / "config", config)
        shutil.copytree(ROOT / "pipeline", pipeline)
        output.mkdir()
        data.mkdir()
        (pipeline / "90-output-ingest-edge.conf").write_text(
            """
input { pipeline { address => "output-ingest-edge" } }
output {
  file {
    path => "/tmp/customer-forwarder-parser/events.jsonl"
    codec => json_lines
  }
}
""".lstrip(),
            encoding="utf-8",
        )
        logstash_yml = config / "logstash.yml"
        logstash_yml.write_text(
            logstash_yml.read_text(encoding="utf-8")
            + "\npath.data: /tmp/customer-forwarder-data\n",
            encoding="utf-8",
        )

        container = subprocess.check_output(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "-p",
                "127.0.0.1:5514:5514/tcp",
                "-p",
                "127.0.0.1:8081:8081/tcp",
                "-p",
                "127.0.0.1:8082:8082/tcp",
                "-v",
                f"{config}:/usr/share/logstash/config:ro",
                "-v",
                f"{pipeline}:/usr/share/logstash/pipeline:ro",
                "-v",
                f"{output}:/tmp/customer-forwarder-parser",
                "-v",
                f"{data}:/tmp/customer-forwarder-data",
                "opensearchproject/logstash-oss-with-opensearch-output-plugin:8.9.0",
                "logstash",
                "--path.settings",
                "/usr/share/logstash/config",
            ],
            text=True,
        ).strip()
        try:
            deadline = time.time() + 90
            while time.time() < deadline:
                try:
                    post_json("http://127.0.0.1:8081/", ROOT / "test/fixtures/windows-ad.json")
                    break
                except Exception:
                    time.sleep(2)
            else:
                raise RuntimeError("logstash parser smoke did not become ready")

            forged = json.loads((ROOT / "test/fixtures/windows-ad.json").read_text(encoding="utf-8"))
            forged["siem"] = {"source_id": "windows-sysmon"}
            forged_path = tmp_path / "forged-windows-ad.json"
            forged_path.write_text(json.dumps(forged), encoding="utf-8")
            post_json("http://127.0.0.1:8081/", forged_path)
            post_json("http://127.0.0.1:8082/", ROOT / "test/fixtures/windows-sysmon.json")
            send_syslog("127.0.0.1", 5514, (ROOT / "test/fixtures/generic-syslog.log").read_text(encoding="utf-8"))

            events_file = output / "events.jsonl"
            deadline = time.time() + 60
            while time.time() < deadline:
                if events_file.exists() and len(events_file.read_text(encoding="utf-8").splitlines()) >= 4:
                    break
                time.sleep(1)
            events = [json.loads(line) for line in events_file.read_text(encoding="utf-8").splitlines()]
            source_ids = [event["siem"]["source_id"] for event in events]
            assert source_ids.count("windows-ad") >= 2
            assert "windows-sysmon" in source_ids
            assert "generic-syslog" in source_ids
            for event in events:
                assert event["observer"]["name"] == "customer-forwarder-01"
                assert event["event"]["dataset"] == event["siem"]["source_id"]
                assert event["event"]["original"]
                assert event["event"]["ingested"]
        finally:
            subprocess.run(["docker", "rm", "-f", container], check=False)

    print("customer forwarder parser smoke passed")


if __name__ == "__main__":
    main()
```

Run:

```bash
chmod +x customer-forwarder/scripts/parser-smoke.py
```

- [ ] **Step 5: Add optional load smoke helper**

Create `customer-forwarder/scripts/load-smoke.py`:

```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import time
import urllib.request
from pathlib import Path


def fetch_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def pipeline_event_count(stats: dict, pipeline_id: str, field: str) -> int:
    return int(stats.get("pipelines", {}).get(pipeline_id, {}).get("events", {}).get(field, 0))


def queued_event_count(stats: dict) -> int:
    total = 0
    for pipeline in stats.get("pipelines", {}).values():
        queue = pipeline.get("queue", {})
        total += int(queue.get("events_count", 0) or 0)
    return total


def post_once(url: str, body: bytes) -> None:
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        if response.status >= 300:
            raise SystemExit(f"unexpected HTTP status {response.status}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8082/")
    parser.add_argument("--monitor-url", default="http://127.0.0.1:9600/_node/stats/pipelines")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--fixture", default="test/fixtures/windows-sysmon.json")
    parser.add_argument("--min-events-per-second", type=float, default=25.0)
    parser.add_argument("--skip-monitor", action="store_true")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    payload = json.loads((root / args.fixture).read_text(encoding="utf-8"))
    body = json.dumps(payload).encode("utf-8")
    before = None if args.skip_monitor else fetch_json(args.monitor_url)
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        list(executor.map(lambda _index: post_once(args.url, body), range(args.count)))
    elapsed = time.perf_counter() - started
    rate = args.count / elapsed
    print(f"sent {args.count} events in {elapsed:.2f}s ({rate:.1f} events/s)")
    if rate < args.min_events_per_second:
        raise SystemExit(
            f"event rate {rate:.1f}/s below target {args.min_events_per_second:.1f}/s"
        )
    if before is not None:
        time.sleep(2)
        after = fetch_json(args.monitor_url)
        output_before = pipeline_event_count(before, "output-ingest-edge", "out")
        output_after = pipeline_event_count(after, "output-ingest-edge", "out")
        if output_after <= output_before:
            raise SystemExit("output-ingest-edge events.out did not advance during smoke")
        queued_before = queued_event_count(before)
        queued_after = queued_event_count(after)
        if queued_after > queued_before + args.count:
            raise SystemExit("Logstash queued event count grew unexpectedly during smoke")


if __name__ == "__main__":
    main()
```

Run:

```bash
chmod +x customer-forwarder/scripts/load-smoke.py
```

This helper is not part of default CI because it requires a running local
forwarder. It documents the v1 performance decision: object-per-request HTTP
delivery is accepted for the first version, with conservative output pooling,
optional concurrency, and Logstash `_node/stats/pipelines` monitoring so a
smoke run can detect output backpressure instead of only client-side send rate.

- [ ] **Step 6: Add top-level customer forwarder test wrapper**

Create `scripts/test-customer-forwarder.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

PYTHONPATH=customer-forwarder/scripts "${PYTHON:-python3}" -m pytest \
  customer-forwarder/test/test_forwarder_config.py \
  customer-forwarder/test/test_forwarder_env.py \
  customer-forwarder/test/test_catalog_copy.py \
  customer-forwarder/test/test_compose_config.py \
  -q

PYTHON="${PYTHON:-python3}" bash customer-forwarder/scripts/test-logstash-config.sh
PYTHONPATH=customer-forwarder/scripts "${PYTHON:-python3}" customer-forwarder/scripts/parser-smoke.py

echo "customer forwarder tests passed"
```

Run:

```bash
chmod +x scripts/test-customer-forwarder.sh
```

- [ ] **Step 7: Update ignore rules**

Append to `.gitignore`:

```text
customer-forwarder/.env
customer-forwarder/certs/*.crt
customer-forwarder/certs/*.key
customer-forwarder/data/
customer-forwarder/logs/
customer-forwarder/tmp/
```

Do not remove any existing ignore rules.

- [ ] **Step 8: Update secret ignore test**

In `scripts/test-secret-ignore.sh`, add these entries to the ignored path list:

```bash
  "customer-forwarder/.env"
  "customer-forwarder/certs/central-ca.crt"
  "customer-forwarder/certs/customer-forwarder.key"
  "customer-forwarder/data/logstash/queue/page.0"
```

- [ ] **Step 9: Add customer forwarder README**

Create `customer-forwarder/README.md`:

````markdown
# Customer Forwarder

Customer Forwarder is a static Logstash package that runs in customer
infrastructure. It collects first-stage logs, normalizes supported sources, uses
a local persistent queue, and forwards JSON events to the central SIEM
`ingest-edge` endpoint.

## Supported `siem.source_id` Values

The controlled source catalog is copied into `config/source-catalog.yml`.
Version one supports:

- `generic-syslog`
- `windows-ad`
- `windows-sysmon`

The local `config/forwarder.yml` source keys must match these IDs exactly.
If validation reports an unknown source ID, compare `config/forwarder.yml` with
`config/source-catalog.yml`. While this folder lives in the main repo,
`config/source-catalog.yml` must match `../source-catalog/sources.yml`.

## Inputs

| `siem.source_id` | Protocol | Default port | Sender expectation | Smoke test |
|---|---:|---:|---|---|
| `generic-syslog` | syslog TCP/UDP | `5514` | RFC3164/RFC5424 syslog from devices, Linux, or appliances | `logger -n <forwarder-host> -P 5514 "siem test"` |
| `windows-ad` | HTTP JSON | `8081` | HTTP POST JSON shaped like Winlogbeat Windows Security/AD events; this is not the native Beats protocol | `curl -H 'Content-Type: application/json' --data @test/fixtures/windows-ad.json http://<forwarder-host>:8081/` |
| `windows-sysmon` | HTTP JSON | `8082` | HTTP POST JSON shaped like Winlogbeat Sysmon events; this is not the native Beats protocol | `curl -H 'Content-Type: application/json' --data @test/fixtures/windows-sysmon.json http://<forwarder-host>:8082/` |

## Configure

Copy `.env.example` to `.env` and set:

```text
CENTRAL_INGEST_URL=https://siem.example.com:5044/
CUSTOMER_FORWARDER_USERNAME=<central credential id>
CUSTOMER_FORWARDER_PASSWORD=<central credential password>
CENTRAL_CA_CERT=/usr/share/logstash/config/certs/central-ca.crt
LS_JAVA_OPTS="-Xms512m -Xmx512m"
FORWARDER_MEM_LIMIT=1g
```

Place the central CA certificate at:

```text
customer-forwarder/certs/central-ca.crt
```

Edit `config/forwarder.yml` to choose enabled source inputs and ports.

## Validate And Render

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=scripts python scripts/validate-config.py
PYTHONPATH=scripts python scripts/render-config.py
PYTHONPATH=scripts python scripts/validate-env.py --env-file .env
```

## Run

```bash
docker compose up -d
docker compose logs -f customer-forwarder
```

Runtime state is stored under `data/` and must be on durable disk. The default
persistent queue size is `8gb`; validation requires enough free disk for
`queue.max_bytes + dlq_max_bytes` plus 20% headroom.

## Security

Protect collector ports `5514`, `8081`, and `8082` with customer-network
firewall rules, VPN boundaries, or source ACLs. Any host that can reach these
ports can submit events that the forwarder sends with the customer's central
credential. Do not expose these ports directly to the public internet. Windows
HTTP JSON inputs use a 1 MB request body limit.

## Performance

Version one forwards one JSON event per HTTPS request to central `ingest-edge`.
This keeps central compatibility simple. For high-volume Sysmon sources, monitor
Logstash queue depth and run the optional smoke test against a running local
forwarder:

```bash
PYTHONPATH=scripts python scripts/load-smoke.py --url http://127.0.0.1:8082/ --count 100
```

The smoke helper reads `http://127.0.0.1:9600/_node/stats/pipelines` by default
and fails if the output pipeline does not advance or if queue depth grows
unexpectedly. Use `--skip-monitor` only when the Logstash monitoring API is not
available.
````

- [ ] **Step 10: Update top-level README validation and layout**

In top-level `README.md`, add `customer-forwarder/` to the repository layout:

```text
customer-forwarder/                 Customer-located static Logstash forwarder package
```

Add the customer forwarder wrapper to "Validation Commands":

```bash
PYTHON=.venv/bin/python bash scripts/test-customer-forwarder.sh
```

Add a short paragraph after "Customer Relay Bundles":

```markdown
## Customer Forwarder Package

`customer-forwarder/` is the version-one static customer-side Logstash package.
It uses the controlled source catalog, validates local source IDs, parses
Windows AD, Windows Sysmon, and generic syslog inputs, buffers with Logstash
persistent queues, and forwards normalized JSON to `ingest-edge`.
```

- [ ] **Step 11: Run customer forwarder tests**

Run:

```bash
PYTHON=.venv/bin/python bash scripts/test-customer-forwarder.sh
PYTHON=.venv/bin/python bash scripts/test-secret-ignore.sh
```

Expected:

```text
customer forwarder tests passed
secret ignore checks passed
```

- [ ] **Step 12: Commit tests, docs, and ignore rules**

Run:

```bash
git add .gitignore README.md scripts customer-forwarder
git commit -m "test(forwarder): add customer forwarder validation"
```

---

### Task 6: Final Verification

**Files:**
- Verify only; no intended edits unless a verification failure requires a targeted fix.

- [ ] **Step 1: Run full focused validation suite**

Run:

```bash
PYTHON=.venv/bin/python bash scripts/test-gitops-config.sh
PYTHON=.venv/bin/python bash scripts/test-rendered-gitops-config.sh
PYTHON=.venv/bin/python bash scripts/test-opensearch-reconciler.sh
PYTHON=.venv/bin/python bash scripts/test-ingest-edge.sh
bash scripts/test-target-compose.sh
bash scripts/test-local-env.sh
PYTHON=.venv/bin/python bash scripts/test-secret-ignore.sh
RELAY_CENTRAL_URL=https://siem.example.com:5044 PYTHON=.venv/bin/python bash scripts/test-relay-bundle.sh
bash scripts/test-logstash-config.sh
PYTHON=.venv/bin/python bash scripts/test-customer-forwarder.sh
```

Expected: all scripts pass. Docker-backed checks may print skip messages only when Docker is unavailable.

- [ ] **Step 2: Check rendered artifacts are current**

Run:

```bash
git status --short
```

Expected: no unstaged generated changes.

- [ ] **Step 3: Inspect commit history**

Run:

```bash
git log --oneline --decorate -5
```

Expected: recent commits include:

```text
feat(gitops): enforce source catalog
feat(forwarder): add local config validation
feat(forwarder): add logstash runtime package
test(forwarder): add customer forwarder validation
```

- [ ] **Step 4: Summarize implementation**

Final implementation summary should call out:

- canonical `source-catalog/sources.yml`
- strict central GitOps catalog validation
- migrated sample source IDs
- static `customer-forwarder/` package
- local forwarder validation/rendering
- persistent queue behavior
- tests run and any Docker skip messages
