#!/usr/bin/env python3
from __future__ import annotations

from contextlib import ExitStack
import fcntl
from ipaddress import ip_network
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit

import yaml

from lib.endpoint_validation import validate_https_endpoint
from lib.gitops_config import DESIRED, REPO_ROOT, customer_dirs, read_yaml


CUSTOMERS = DESIRED / "customers"
SOURCE_ID = "generic-syslog"
DEFAULT_CA = "secrets/certs/central-ca.crt"
CERTIFICATE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----"
)


def read_public_ca(path: Path) -> str:
    pem = path.read_text(encoding="ascii")
    if not CERTIFICATE.search(pem) or CERTIFICATE.sub("", pem).strip():
        raise ValueError("Ingest CA file must contain only PEM certificates")
    ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=pem)
    return pem


def write_customer(directory: Path, name: str, slug: str, cidrs: list[str]) -> None:
    documents = {
        "customer.yml": {"kind": "Customer", "slug": slug, "name": name, "enabled": True},
        "credentials.yml": {
            "kind": "CustomerCredentialList",
            "customer": slug,
            "credentials": [{
                "id": f"{slug}-primary",
                "enabled": True,
                "secretRef": f"secrets/local/customer-{slug}-password",
            }],
        },
        "allowlist.yml": {
            "kind": "CustomerAllowlist",
            "customer": slug,
            "entries": [{"cidr": cidr, "description": "Relay egress network"} for cidr in cidrs],
        },
        f"sources/{SOURCE_ID}.yml": {
            "kind": "Source",
            "customer": slug,
            "id": SOURCE_ID,
            "name": f"{name} generic syslog",
            "dataset": SOURCE_ID,
            "parser": SOURCE_ID,
            "retentionPolicy": "standard-7d",
            "priority": "standard",
            "enabled": True,
        },
    }
    (directory / "sources").mkdir(parents=True)
    for filename, document in documents.items():
        document = {"apiVersion": "siem.local/v1", **document}
        (directory / filename).write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def stage_handoff(stage: Path, slug: str, url: str, ca: str) -> Path:
    subprocess.run(
        ["bash", "scripts/generate-relay-bundle.sh", slug],
        cwd=stage,
        env={**os.environ, "PYTHON": sys.executable, "RELAY_CENTRAL_URL": url},
        check=True,
        stdout=subprocess.DEVNULL,
    )

    bundle = stage / "relay/bundles" / slug
    (bundle / "central-ca.crt").write_text(ca, encoding="ascii")
    readme = bundle / "README.md"
    listener_table = readme.read_text(encoding="utf-8")
    health_url = urlsplit(url)._replace(path="/health", query="", fragment="").geturl()
    readme.write_text(
        f"# Forwarder setup for {slug}\n\n"
        f"- Central ingest endpoint `{url}`\n"
        f"- Credential username `{slug}-primary`\n\n"
        "1. Install logstash.yml and pipeline.conf in the relay's active Logstash configuration.\n"
        "2. Install central-ca.crt at /usr/share/logstash/config/certs/central-ca.crt. "
        "The central ingest certificate must match the endpoint hostname.\n"
        "3. Set CUSTOMER_FORWARDER_PASSWORD in the Logstash service environment using the "
        "password shared separately. Ensure /usr/share/logstash/data/queue is writable "
        "and persistent, then start Logstash.\n"
        "4. Point devices at the corresponding relay listener.\n\n"
        f"{listener_table}\n"
        "## Verify the forwarder\n\n"
        "```sh\n"
        "curl --fail --show-error --cacert /usr/share/logstash/config/certs/central-ca.crt "
        f"'{health_url}'\n"
        'marker="customer-onboarding-$(date -u +%Y%m%dT%H%M%SZ)"\n'
        'logger --rfc3164 --tcp --server 127.0.0.1 --port 5514 -- "$marker"\n'
        'printf "%s\\n" "$marker"\n'
        "```\n\n"
        "Run the logger command on Linux with util-linux installed. Ask the SIEM operator "
        f"to confirm the marker in logs-{slug}-{SOURCE_ID}.\n",
        encoding="utf-8",
    )
    archive = bundle / "handoff.tar.gz"
    with tarfile.open(archive, "w:gz") as handoff:
        for filename in ("logstash.yml", "pipeline.conf", "central-ca.crt", "README.md"):
            handoff.add(bundle / filename, arcname=filename)
    return archive


def check_credential_available(credential_id: str, secret_ref: str) -> None:
    for directory in customer_dirs():
        credentials = read_yaml(directory / "credentials.yml")["credentials"]
        for credential in credentials:
            if credential["id"] == credential_id:
                raise ValueError(f"Credential ID already exists: {credential_id}")
            if credential["secretRef"] == secret_ref:
                raise ValueError(f"Secret reference already in use: {secret_ref}")
    accounts = read_yaml(DESIRED / "global/service-accounts.yml")["accounts"]
    if any(account["secretRef"] == secret_ref for account in accounts):
        raise ValueError(f"Secret reference already in use: {secret_ref}")


def onboard(name: str, slug: str, cidrs: list[str], url: str, ca: str) -> None:
    customer = CUSTOMERS / slug
    secret = REPO_ROOT / "secrets/local" / f"customer-{slug}-password"
    handoff = REPO_ROOT / "relay/bundles" / slug

    # Lock the existing directory so concurrent wizard runs check the same live state.
    lock_fd = os.open(CUSTOMERS, os.O_RDONLY)
    with ExitStack() as resources:
        resources.callback(os.close, lock_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        for path in (customer, secret, handoff):
            if path.exists() or path.is_symlink():
                raise ValueError(f"Path already exists: {path.relative_to(REPO_ROOT)}")

        staging_root = REPO_ROOT / "tmp"
        staging_root.mkdir(exist_ok=True)
        with TemporaryDirectory(prefix="customer-onboarding-", dir=staging_root) as temp:
            stage = Path(temp)
            for directory in (
                "gitops/desired", "gitops/schemas", "source-catalog", "relay/templates", "scripts/lib",
            ):
                shutil.copytree(
                    REPO_ROOT / directory, stage / directory, ignore=shutil.ignore_patterns("__pycache__"),
                )
            for filename in ("__init__.py", "validate-gitops-config.py", "generate-relay-bundle.sh"):
                shutil.copyfile(REPO_ROOT / "scripts" / filename, stage / "scripts" / filename)

            candidate = stage / "gitops/desired/customers" / slug
            write_customer(candidate, name, slug, cidrs)
            subprocess.run(
                [sys.executable, "scripts/validate-gitops-config.py"], cwd=stage, check=True,
            )
            check_credential_available(f"{slug}-primary", secret.relative_to(REPO_ROOT).as_posix())
            archive = stage_handoff(stage, slug, url, ca)

            secret.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            handoff.parent.mkdir(parents=True, exist_ok=True)
            with ExitStack() as rollback:
                handoff.mkdir(mode=0o700)
                rollback.callback(shutil.rmtree, handoff)
                shutil.move(archive, handoff / archive.name)

                fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                rollback.callback(secret.unlink)
                with os.fdopen(fd, "w", encoding="ascii") as password_file:
                    os.fchmod(password_file.fileno(), 0o600)
                    password_file.write(secrets.token_urlsafe(32) + "\n")

                # Publish the complete customer directory last.
                if customer.exists() or customer.is_symlink():
                    raise ValueError(f"Customer already exists: {slug}")
                candidate.rename(customer)
                rollback.pop_all()

    print(f"\nCustomer configuration written to {customer.relative_to(REPO_ROOT)}")
    print(f"Forwarder archive written to {(handoff / 'handoff.tar.gz').relative_to(REPO_ROOT)}")
    print(f"Share the password separately from {secret.relative_to(REPO_ROOT)}.")
    print("If the central host uses another checkout, securely install the same password")
    print("file there at that path with mode 0600 before deploying the GitOps change.")
    print("""
Run from the central SIEM repository to deploy the change:

  .venv/bin/python scripts/render-gitops-config.py
  git status --short -- gitops/desired gitops/rendered

Review and deploy the desired and rendered GitOps changes. On the central host,
set OPENSEARCH_URL, OPENSEARCH_USER, OPENSEARCH_PASSWORD and OPENSEARCH_CA for
your deployment, then run:

  .venv/bin/python scripts/reconcile-opensearch-gitops.py --dry-run
  .venv/bin/python scripts/reconcile-opensearch-gitops.py
  docker compose restart central-logstash ingest-edge
""")


def main() -> int:
    try:
        name = input("Customer name: ").strip()
        if not name:
            raise ValueError("Customer name is required")
        slug = input("Customer slug: ").strip()
        if not re.fullmatch(r"[a-z][a-z0-9-]{1,30}[a-z0-9]", slug):
            raise ValueError("Slug must be 3–32 lowercase letters, digits or hyphens, "
                             "start with a letter and end with a letter or digit")
        entered_cidrs = input("Relay egress CIDRs (comma-separated): ").split(",")
        cidrs = list(dict.fromkeys(str(ip_network(cidr.strip())) for cidr in entered_cidrs))
        url = input("Central ingest HTTPS URL: ").strip()
        validate_https_endpoint(url)
        if re.search(r"""["'\\\x00-\x1f\x7f]|\$\{""", url):
            raise ValueError("Central ingest URL contains characters unsafe for the relay configuration")
        ca_path = Path(input(f"Public ingest CA path [{DEFAULT_CA}]: ").strip() or DEFAULT_CA).expanduser()
        if not ca_path.is_absolute():
            ca_path = REPO_ROOT / ca_path
        ca = read_public_ca(ca_path)

        print(f"\nCustomer {name} ({slug})")
        print(f"Source {SOURCE_ID} with standard-7d retention")
        print(f"Credential {slug}-primary")
        print(f"Allowed relay networks {', '.join(cidrs)}")
        print(f"Ingest endpoint {url}")
        print(f"Public ingest CA {ca_path}")
        if input("Create customer and handoff? [y/N]: ").strip().lower() not in {"y", "yes"}:
            print("Cancelled.")
            return 0
        onboard(name, slug, cidrs, url, ca)
    except (EOFError, KeyboardInterrupt):
        print("\nOnboarding cancelled.", file=sys.stderr)
        return 130
    except (OSError, ValueError, subprocess.CalledProcessError, yaml.YAMLError) as error:
        print(f"Onboarding failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
