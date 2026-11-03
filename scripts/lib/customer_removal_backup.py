from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
from tempfile import mkstemp
from uuid import uuid4

import yaml

from .gitops_config import DESIRED, REPO_ROOT, read_yaml, validate_schema


LEDGER_PREFIX = b"SIEM-FORWARDER-V1:"
LEDGER_MEMBERS = {"logstash.yml", "pipeline.conf", "central-ca.crt", "README.md"}
MAX_LEDGER_BYTES = 1024 * 1024


def _customer_document(path: Path, schema: str, customer_key: str, slug: str) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Expected a regular customer configuration file: {path.name}")
    try:
        document = read_yaml(path)
        validate_schema(document, schema, path)
    except (ValueError, yaml.YAMLError):
        raise ValueError(f"Invalid customer configuration in {path.name}") from None
    if document[customer_key] != slug:
        raise ValueError(f"Customer ownership does not match in {path.name}")
    return document


def _read_ledger(path: Path) -> bytes | None:
    if any(candidate.is_symlink() for candidate in (path, *tuple(path.parents)[:3])):
        raise ValueError("The forwarder ledger and its parent directories must not be symbolic links")
    if not path.exists():
        return None
    if not path.is_file() or path.stat().st_size > MAX_LEDGER_BYTES:
        raise ValueError("Expected a regular generated forwarder ledger")
    with path.open("rb") as source:
        contents = source.read(MAX_LEDGER_BYTES + 1)
    prefix, separator, payload = contents.rstrip(b"\n").partition(b":")
    if prefix + separator != LEDGER_PREFIX or len(contents) > MAX_LEDGER_BYTES:
        raise ValueError("Could not verify the generated forwarder ledger")
    try:
        data = base64.b64decode(payload, validate=True)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r|gz") as archive:
            seen = set()
            for member in archive:
                if (
                    member.name not in LEDGER_MEMBERS or member.name in seen
                    or not member.isreg() or member.size > MAX_LEDGER_BYTES
                ):
                    raise ValueError("Unexpected forwarder ledger entry")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("Unreadable forwarder ledger entry")
                with stream:
                    content = stream.read()
                if re.search(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----", content):
                    raise ValueError("Private key material in forwarder ledger")
                if member.name == "pipeline.conf":
                    passwords = re.findall(rb'^\s*password\s*=>\s*(.+)$', content, re.MULTILINE)
                    if passwords != [b'"${CUSTOMER_FORWARDER_PASSWORD}"']:
                        raise ValueError("Unexpected password binding in forwarder ledger")
                seen.add(member.name)
            if seen != LEDGER_MEMBERS:
                raise ValueError("Incomplete forwarder ledger")
    except (ValueError, binascii.Error, EOFError, tarfile.TarError):
        raise ValueError("Could not verify a secret-free generated forwarder ledger") from None
    return contents


def _backup_directory() -> Path:
    output = REPO_ROOT / "data/backups/customer-removals"
    for directory in (output.parent.parent, output.parent, output):
        if directory.is_symlink():
            raise ValueError(f"Backup directory must not be a symbolic link: {directory.name}")
        directory.mkdir(mode=0o700, exist_ok=True)
    if stat.S_IMODE(output.stat().st_mode) != 0o700:
        raise ValueError("Customer backup directory must have mode 0700")
    return output


def _add_file(archive: tarfile.TarFile, name: str, contents: bytes) -> None:
    entry = tarfile.TarInfo(name)
    entry.mode = 0o600
    entry.size = len(contents)
    archive.addfile(entry, io.BytesIO(contents))


def write_customer_backup(
    directory: Path, ledger: Path, templates: dict[str, dict] | None = None,
) -> Path:
    """Publish a private archive containing only the customer's configuration artifacts."""
    slug = directory.name
    if directory.parent not in {DESIRED / "customers", REPO_ROOT / "tmp/customer-deletions"}:
        raise ValueError("Customer configuration is outside the managed directories")
    relative = directory.relative_to(REPO_ROOT)
    if any(path.is_symlink() for path in (directory, *tuple(directory.parents)[:len(relative.parts) - 1])):
        raise ValueError("Customer configuration path must not contain symbolic links")
    if not directory.is_dir():
        raise ValueError("Expected a regular customer configuration directory")
    if ledger != REPO_ROOT / "relay/bundles" / slug / "handoff.txt":
        raise ValueError("Forwarder ledger path does not match the customer")

    documents = {
        "customer.yml": _customer_document(directory / "customer.yml", "customer.schema.json", "slug", slug),
        "credentials.yml": _customer_document(
            directory / "credentials.yml", "customer-credential.schema.json", "customer", slug,
        ),
        "allowlist.yml": _customer_document(
            directory / "allowlist.yml", "allowlist.schema.json", "customer", slug,
        ),
    }
    source_directory = directory / "sources"
    if source_directory.is_symlink():
        raise ValueError("Source directory must not be a symbolic link")
    streams = {f"logs-{slug}-unknown-quarantine"}
    for path in sorted(source_directory.glob("*.yml")):
        document = _customer_document(path, "source.schema.json", "customer", slug)
        documents[f"sources/{path.name}"] = document
        stream = f"logs-{slug}-{document['dataset']}"
        streams.update((stream, f"{stream}-quarantine"))
    template_files = templates or {}
    for name, template in template_files.items():
        stream = name.removesuffix("-template")
        if (
            stream not in streams or name != f"{stream}-template"
            or not isinstance(template, dict) or template.get("index_patterns") != [stream]
            or not isinstance(template.get("data_stream"), dict)
        ):
            raise ValueError("Index template does not match the customer's configuration")
    ledger_contents = _read_ledger(ledger)

    output = _backup_directory()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = output / f"{slug}-{timestamp}-{uuid4().hex}.tar.gz"
    fd, temporary_name = mkstemp(dir=output, prefix=".backup-")
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as destination:
            os.fchmod(destination.fileno(), 0o600)
            with tarfile.open(fileobj=destination, mode="w:gz") as archive:
                for name, document in documents.items():
                    _add_file(archive, f"customer/{name}", yaml.safe_dump(document, sort_keys=False).encode("utf-8"))
                if ledger_contents is not None:
                    _add_file(archive, "forwarder/handoff.txt", ledger_contents)
                for name, template in sorted(template_files.items()):
                    _add_file(
                        archive, f"opensearch/index-templates/{name}.json",
                        (json.dumps(template, indent=2, sort_keys=True) + "\n").encode("utf-8"),
                    )
            destination.flush()
            os.fsync(destination.fileno())
        os.link(temporary, target)
    finally:
        temporary.unlink()
    return target
