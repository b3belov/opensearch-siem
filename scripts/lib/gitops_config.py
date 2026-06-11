from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network
from pathlib import Path
from typing import Any

import json
import yaml
from jinja2 import Environment, FileSystemLoader
from jsonschema import Draft202012Validator


REPO_ROOT = Path(__file__).resolve().parents[2]
DESIRED = REPO_ROOT / "gitops" / "desired"
SCHEMAS = REPO_ROOT / "gitops" / "schemas"
SOURCE_CATALOG = REPO_ROOT / "source-catalog" / "sources.yml"
SOURCE_CATALOG_SCHEMA = REPO_ROOT / "source-catalog" / "sources.schema.json"


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


@dataclass(frozen=True)
class SourceCatalogEntry:
    id: str
    dataset: str
    parser: str
    input: str
    description: str


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


def validate_schema_file(document: dict[str, Any], schema_path: Path, path: Path) -> None:
    schema = read_json(schema_path)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.path))
    if errors:
        rendered = "; ".join(f"{'/'.join(map(str, error.path))}: {error.message}" for error in errors)
        raise ValueError(f"{path}: {rendered}")


def validate_schema(document: dict[str, Any], schema_name: str, path: Path) -> None:
    validate_schema_file(document, SCHEMAS / schema_name, path)


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


def load_sources(
    customers: dict[str, Customer],
    retention_names: set[str],
    source_catalog: dict[str, SourceCatalogEntry],
) -> list[Source]:
    sources: list[Source] = []
    seen_streams: set[tuple[str, str]] = set()
    for customer_dir in customer_dirs():
        source_dir = customer_dir / "sources"
        for path in sorted(source_dir.glob("*.yml")):
            doc = read_yaml(path)
            validate_schema(doc, "source.schema.json", path)
            customer = doc["customer"]
            dataset = doc["dataset"]
            catalog_entry = source_catalog.get(doc["id"])
            if catalog_entry is None:
                supported = ", ".join(sorted(source_catalog))
                raise ValueError(f"{path}: source id {doc['id']} is not in source catalog; supported source IDs: {supported}")
            if doc["dataset"] != catalog_entry.dataset:
                raise ValueError(
                    f"{path}: catalog dataset for {doc['id']} is {catalog_entry.dataset}, got {doc['dataset']}"
                )
            if doc["parser"] != catalog_entry.parser:
                raise ValueError(
                    f"{path}: catalog parser for {doc['id']} is {catalog_entry.parser}, got {doc['parser']}"
                )
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
    source_catalog = load_source_catalog()
    customers = load_customers()
    retention_names = load_retention_policy_names()
    validate_customer_sidecars(customers)
    load_sources(customers, retention_names, source_catalog)


def enabled_sources_for_customer(customer_slug: str) -> list[dict[str, str]]:
    """Return enabled syslog-compatible sources for the legacy relay bundle."""
    source_catalog = load_source_catalog()
    customers = load_customers()
    retention_names = load_retention_policy_names()
    if customer_slug not in customers:
        raise ValueError(f"unknown customer: {customer_slug}")
    sources = load_sources(customers, retention_names, source_catalog)

    result: list[dict[str, str]] = []
    for source in sources:
        if source.customer != customer_slug or not source.enabled:
            continue
        catalog_entry = source_catalog[source.id]
        if catalog_entry.input != "syslog":
            continue
        result.append({"id": source.id, "dataset": source.dataset})
    return result


def make_jinja_env(repo_root: Path) -> Environment:
    """Canonical Jinja environment for rendering repo templates.

    Single definition reused by render-gitops-config.py and the relay-bundle
    generator so the trim/lstrip/autoescape settings can never drift.
    """
    return Environment(
        loader=FileSystemLoader(str(repo_root)),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
    )
