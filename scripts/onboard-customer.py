#!/usr/bin/env python3
from __future__ import annotations

from base64 import b64encode
from contextlib import ExitStack, contextmanager
import fcntl
from io import BytesIO
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
from typing import Callable, Iterator, TypeVar
from urllib.parse import urlsplit

import yaml

from lib.endpoint_validation import validate_https_endpoint
from lib.gitops_config import (
    Customer, DESIRED, REPO_ROOT, customer_dirs, load_customers, read_yaml, validate_schema,
)


CUSTOMERS = DESIRED / "customers"
SOURCE_ID = "generic-syslog"
DEFAULT_CA = "secrets/certs/central-ca.crt"
LEDGER_FILENAME = "handoff.txt"
LEDGER_PREFIX = "SIEM-FORWARDER-V1:"
CERTIFICATE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----"
)
Answer = TypeVar("Answer")


def ask(prompt: str, validate: Callable[[str], Answer]) -> Answer:
    while True:
        answer = input(prompt).strip()
        try:
            return validate(answer)
        except (ValueError, OSError) as error:
            print(f"Invalid input: {error}", file=sys.stderr)


def confirm(prompt: str) -> bool:
    def parse(answer: str) -> bool:
        if answer.lower() in {"y", "yes"}:
            return True
        if answer.lower() in {"", "n", "no"}:
            return False
        raise ValueError("Enter yes or no")

    return ask(prompt, parse)


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
    credentials = read_yaml(stage / "gitops/desired/customers" / slug / "credentials.yml")
    username = next(item["id"] for item in credentials["credentials"] if item["enabled"])
    health_url = urlsplit(url)._replace(path="/health", query="", fragment="").geturl()
    readme.write_text(
        f"# Forwarder setup for {slug}\n\n"
        f"- Central ingest endpoint `{url}`\n"
        f"- Credential username `{username}`\n\n"
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
        "# Set the port to the listener for the source you want to verify.\n"
        "port=5514\n"
        'logger --rfc3164 --tcp --server 127.0.0.1 --port "$port" -- "$marker"\n'
        'printf "%s\\n" "$marker"\n'
        "```\n\n"
        "Run the logger command on Linux with util-linux installed. Ask the SIEM operator "
        f"to confirm the marker in the logs-{slug}-<dataset> stream for that source.\n",
        encoding="utf-8",
    )
    archive = BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as handoff:
        for filename in ("logstash.yml", "pipeline.conf", "central-ca.crt", "README.md"):
            handoff.add(bundle / filename, arcname=filename)
    ledger = bundle / LEDGER_FILENAME
    payload = b64encode(archive.getvalue()).decode("ascii")
    ledger.write_text(f"{LEDGER_PREFIX}{payload}\n", encoding="ascii")
    return ledger


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


def stage_gitops(stage: Path, directories: tuple[str, ...], scripts: tuple[str, ...]) -> None:
    for directory in ("gitops/desired", "gitops/schemas", "source-catalog", "scripts/lib", *directories):
        shutil.copytree(
            REPO_ROOT / directory, stage / directory, ignore=shutil.ignore_patterns("__pycache__"),
        )
    for filename in ("__init__.py", *scripts):
        shutil.copyfile(REPO_ROOT / "scripts" / filename, stage / "scripts" / filename)


@contextmanager
def lock_customers() -> Iterator[None]:
    # Serialize wizard writes while checking the live desired state.
    lock_fd = os.open(CUSTOMERS, os.O_RDONLY)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(lock_fd)


def onboard(name: str, slug: str, cidrs: list[str], url: str, ca: str) -> None:
    customer = CUSTOMERS / slug
    secret = REPO_ROOT / "secrets/local" / f"customer-{slug}-password"
    handoff = REPO_ROOT / "relay/bundles" / slug

    with lock_customers():
        for path in (customer, secret, handoff):
            if path.exists() or path.is_symlink():
                raise ValueError(f"Path already exists: {path.relative_to(REPO_ROOT)}")
        customer_name(name, load_customers())

        staging_root = REPO_ROOT / "tmp"
        staging_root.mkdir(exist_ok=True)
        with TemporaryDirectory(prefix="customer-onboarding-", dir=staging_root) as temp:
            stage = Path(temp)
            stage_gitops(
                stage, ("relay/templates",), ("validate-gitops-config.py", "generate-relay-bundle.sh"),
            )

            candidate = stage / "gitops/desired/customers" / slug
            write_customer(candidate, name, slug, cidrs)
            subprocess.run(
                [sys.executable, "scripts/validate-gitops-config.py"], cwd=stage, check=True,
            )
            check_credential_available(f"{slug}-primary", secret.relative_to(REPO_ROOT).as_posix())
            ledger = stage_handoff(stage, slug, url, ca)

            secret.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            handoff.parent.mkdir(parents=True, exist_ok=True)
            with ExitStack() as rollback:
                handoff.mkdir(mode=0o700)
                rollback.callback(shutil.rmtree, handoff)
                shutil.move(ledger, handoff / LEDGER_FILENAME)

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
    ledger_path = handoff / LEDGER_FILENAME
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
    print_ledger(ledger_path)


def print_ledger(path: Path) -> None:
    print(f"Forwarder ledger written to {path.relative_to(REPO_ROOT)}")
    print("Copy the full forwarder ledger line below. Share the password separately.")
    print(path.read_text(encoding="ascii"), end="")


def deploy_customer() -> None:
    print(
        "\nDeployment is optional. Continue only from the checkout used by the central SIEM.\n"
        "Preview renders in staging and queries OpenSearch for drift.\n"
        "Applying replaces live rendered configuration, including any pending GitOps changes.\n"
        "The receiver can reload credentials and allowlists as soon as those files change.\n"
        "Applying reconciles all desired OpenSearch objects, including shared security configuration.\n"
        "Restarting central-logstash and ingest-edge can briefly interrupt ingestion for all customers.\n"
        "OpenSearch updates can apply partially if a step fails. Review the output before retrying."
    )
    try:
        if not confirm("Preview deployment? [y/N]: "):
            return
    except EOFError:
        return

    env = os.environ.copy()
    env.setdefault("OPENSEARCH_URL", "https://127.0.0.1:9200")
    env.setdefault("OPENSEARCH_USER", "admin")
    env.setdefault("OPENSEARCH_CA", "secrets/certs/root-ca.crt")
    if env["OPENSEARCH_USER"] == "admin":
        env.setdefault("OPENSEARCH_PASSWORD", env.get("OPENSEARCH_ADMIN_PASSWORD", ""))
    if not env.get("OPENSEARCH_PASSWORD"):
        raise ValueError("Export OPENSEARCH_PASSWORD before deployment. For local admin, "
                         "you can load OPENSEARCH_ADMIN_PASSWORD from .env as documented in the README.")
    ca_path = REPO_ROOT / env["OPENSEARCH_CA"]
    if not ca_path.is_file():
        raise ValueError("Set OPENSEARCH_CA to the OpenSearch CA certificate file")
    env["OPENSEARCH_CA"] = str(ca_path)
    validate_https_endpoint(env["OPENSEARCH_URL"], field_name="OPENSEARCH_URL")

    subprocess.run(
        ["git", "status", "--short", "--", "gitops/desired", "gitops/rendered"],
        cwd=REPO_ROOT, check=True,
    )
    render = [sys.executable, "scripts/render-gitops-config.py"]
    reconcile = [sys.executable, "scripts/reconcile-opensearch-gitops.py"]
    with TemporaryDirectory(prefix="customer-preview-", dir=REPO_ROOT / "tmp") as temp:
        stage = Path(temp)
        stage_gitops(
            stage, ("logstash/templates", "opensearch/base"),
            ("render-gitops-config.py", "reconcile-opensearch-gitops.py"),
        )
        subprocess.run(render, cwd=stage, check=True)
        subprocess.run([*reconcile, "--dry-run"], cwd=stage, env=env, check=True)
    if not confirm("Apply OpenSearch changes and restart both ingest services? [y/N]: "):
        print("Deployment skipped. The wizard changes are saved.")
        return

    for variable, default in (
        ("OPENSEARCH_ADMIN_CERT", "secrets/certs/admin.crt"),
        ("OPENSEARCH_ADMIN_KEY", "secrets/certs/admin.key"),
    ):
        if not (REPO_ROOT / env.get(variable, default)).is_file():
            raise ValueError(f"Set {variable} to a readable file before applying")
    compose = ["docker", "compose"]
    subprocess.run([*compose, "config", "--quiet"], cwd=REPO_ROOT, check=True)
    services = ["central-logstash", "ingest-edge"]
    running = subprocess.run(
        [*compose, "ps", "--status", "running", "--services", *services],
        cwd=REPO_ROOT, check=True, capture_output=True, text=True,
    )
    if not set(services).issubset(running.stdout.splitlines()):
        raise ValueError("Start central-logstash and ingest-edge in this checkout before applying")

    subprocess.run(render, cwd=REPO_ROOT, check=True)
    subprocess.run(reconcile, cwd=REPO_ROOT, env=env, check=True)
    subprocess.run([*compose, "restart", *services], cwd=REPO_ROOT, check=True)
    subprocess.run([*compose, "ps", *services], cwd=REPO_ROOT, check=True)
    print("Wait for both ingest services to be healthy before sending forwarder traffic.")


def customer_name(answer: str, customers: dict[str, Customer], current_slug: str = "") -> str:
    if not answer:
        raise ValueError("Customer name is required")
    normalized = " ".join(answer.split()).casefold()
    for customer in customers.values():
        if customer.slug != current_slug and " ".join(customer.name.split()).casefold() == normalized:
            raise ValueError(f"Customer name already exists under slug {customer.slug!r}")
    return answer


def customer_slug(answer: str) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,30}[a-z0-9]", answer):
        raise ValueError("Slug must be 3–32 lowercase letters, digits or hyphens, "
                         "start with a letter and end with a letter or digit")
    if os.path.lexists(CUSTOMERS / answer):
        raise ValueError("Customer slug already exists")
    return answer


def relay_cidrs(answer: str) -> list[str]:
    networks = []
    for value in answer.split(","):
        cidr = value.strip()
        if "/" not in cidr:
            raise ValueError(f"Expected a CIDR with a prefix length, got {cidr!r}")
        networks.append(str(ip_network(cidr)))
    return list(dict.fromkeys(networks))


def configured_ingest_url() -> str:
    result = subprocess.run(
        ["bash", "-ec", 'if [[ -f .env ]]; then . ./.env >/dev/null; fi; '
         'printf "%s" "${RELAY_CENTRAL_URL:-}"'],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    if result.returncode:
        raise ValueError("Could not load the repository .env. Check its shell syntax")
    url = result.stdout
    if not url:
        raise ValueError("Set RELAY_CENTRAL_URL in the repository .env before generating a ledger")
    validate_https_endpoint(url, field_name="RELAY_CENTRAL_URL")
    if re.search(r"""["'\\\x00-\x1f\x7f]|\$\{""", url):
        raise ValueError("RELAY_CENTRAL_URL contains characters unsafe for the relay configuration")
    return url


def ingest_ca(answer: str) -> tuple[Path, str]:
    path = REPO_ROOT / Path(answer or DEFAULT_CA).expanduser()
    return path, read_public_ca(path)


def select_customer(customers: dict[str, Customer]) -> Customer | None:
    choices = sorted(customers.values(), key=lambda customer: (customer.name.casefold(), customer.slug))
    print("Select a customer:")
    print("  0. New")
    for index, customer in enumerate(choices, 1):
        state = "" if customer.enabled else " [disabled]"
        print(f"  {index}. {customer.name} ({customer.slug}){state}")

    def parse(answer: str) -> Customer | None:
        if answer.lower() in {"0", "new"}:
            return None
        if re.fullmatch(r"[0-9]+", answer) and 1 <= int(answer) <= len(choices):
            return choices[int(answer) - 1]
        raise ValueError("Enter one of the listed numbers or New")

    return ask("Customer selection: ", parse)


def save_customer_edit(
    slug: str,
    original: dict[Path, bytes],
    changes: dict[Path, dict],
    ledger_settings: tuple[str, str] | None,
) -> Path | None:
    with lock_customers():
        for path, contents in original.items():
            if path.read_bytes() != contents:
                raise ValueError(f"{path.name} changed during editing. Reopen the customer and retry")
        customer_path = CUSTOMERS / slug / "customer.yml"
        if customer_path in changes:
            customer_name(changes[customer_path]["name"], load_customers(), slug)

        staging_root = REPO_ROOT / "tmp"
        staging_root.mkdir(exist_ok=True)
        with TemporaryDirectory(prefix="customer-edit-", dir=staging_root) as temp:
            stage = Path(temp)
            stage_gitops(
                stage, ("relay/templates",), ("validate-gitops-config.py", "generate-relay-bundle.sh"),
            )
            replacements = {}
            for path, document in changes.items():
                candidate = stage / path.relative_to(REPO_ROOT)
                candidate.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
                shutil.copymode(path, candidate)
                replacements[path] = candidate

            subprocess.run(
                [sys.executable, "scripts/validate-gitops-config.py"], cwd=stage, check=True,
            )
            ledger_path = None
            with ExitStack() as rollback:
                if ledger_settings is not None:
                    ledger = stage_handoff(stage, slug, *ledger_settings)
                    handoff = REPO_ROOT / "relay/bundles" / slug
                    if handoff.is_symlink():
                        raise ValueError("Ledger directory must not be a symbolic link")
                    handoff.parent.mkdir(parents=True, exist_ok=True)
                    if not handoff.exists():
                        handoff.mkdir(mode=0o700)
                        rollback.callback(handoff.rmdir)
                    ledger_path = handoff / LEDGER_FILENAME
                    replacements[ledger_path] = ledger

                for index, (path, candidate) in enumerate(replacements.items()):
                    if path.is_symlink():
                        raise ValueError(f"Cannot replace symbolic link {path.relative_to(REPO_ROOT)}")
                    backup = stage / f"original-{index}"
                    if path.exists():
                        shutil.copy2(path, backup)
                        rollback.callback(backup.replace, path)
                    else:
                        rollback.callback(path.unlink, missing_ok=True)
                    candidate.replace(path)
                rollback.pop_all()
    return ledger_path


def edit_customer(customer: Customer, customers: dict[str, Customer]) -> bool:
    slug = customer.slug
    customer_path = customer.path
    allowlist_path = customer_path.with_name("allowlist.yml")
    original = {path: path.read_bytes() for path in (customer_path, allowlist_path)}
    metadata = yaml.safe_load(original[customer_path])
    allowlist = yaml.safe_load(original[allowlist_path])
    validate_schema(metadata, "customer.schema.json", customer_path)
    validate_schema(allowlist, "allowlist.schema.json", allowlist_path)
    current_name = metadata["name"]
    current_entries = allowlist["entries"]
    current_cidrs = ", ".join(entry["cidr"] for entry in current_entries)
    print(f"Editing {current_name} ({slug}).")
    def edit_name(answer: str) -> str:
        if not answer or answer == current_name:
            return current_name
        return customer_name(answer, customers, slug)

    def edit_cidrs(answer: str) -> list[str] | None:
        if not answer:
            return None
        if answer.lower() == "none":
            return []
        return relay_cidrs(answer)

    name = ask(f"Customer name [{current_name}]: ", edit_name)
    cidrs = ask(
        f"Relay egress CIDRs [{current_cidrs or 'none'}] (Enter to keep, 'none' to clear): ",
        edit_cidrs,
    )

    changes = {}
    if name != current_name:
        changes[customer_path] = {**metadata, "name": name}
    if cidrs is not None:
        descriptions = {
            str(ip_network(entry["cidr"], strict=False)): entry["description"]
            for entry in current_entries
        }
        entries = [
            {"cidr": cidr, "description": descriptions.get(cidr, "Relay egress network")}
            for cidr in cidrs
        ]
        if entries != current_entries:
            changes[allowlist_path] = {**allowlist, "entries": entries}
            print("Applying the updated allowlist can block relays that use removed networks.")

    ledger_settings = None
    if confirm("Regenerate the forwarder ledger using the existing credential and sources? [y/N]: "):
        url = configured_ingest_url()
        print(f"Ingest endpoint {url}")
        _, ca = ask(f"Public ingest CA path [{DEFAULT_CA}]: ", ingest_ca)
        ledger_settings = (url, ca)
        print("The new ledger will replace handoff.txt if it already exists.")
    if not changes and ledger_settings is None:
        print("No changes to save.")
        return False
    if not confirm(f"Save changes for {slug}? [y/N]: "):
        print("Cancelled.")
        return False

    ledger_path = save_customer_edit(slug, original, changes, ledger_settings)
    if changes:
        print(f"Customer configuration updated for {slug}.")
    if ledger_path is not None:
        print_ledger(ledger_path)
    return bool(changes)


def setup_customer(customers: dict[str, Customer]) -> bool:
    name = ask("Customer name: ", lambda answer: customer_name(answer, customers))
    slug = ask("Customer slug: ", customer_slug)
    cidrs = ask("Relay egress CIDRs (comma-separated): ", relay_cidrs)
    url = configured_ingest_url()
    ca_path, ca = ask(f"Public ingest CA path [{DEFAULT_CA}]: ", ingest_ca)

    print(f"\nCustomer {name} ({slug})")
    print(f"Source {SOURCE_ID} with standard-7d retention")
    print(f"Credential {slug}-primary")
    print(f"Allowed relay networks {', '.join(cidrs)}")
    print(f"Ingest endpoint {url}")
    print(f"Public ingest CA {ca_path}")
    if not confirm("Create customer and handoff? [y/N]: "):
        print("Cancelled.")
        return False
    onboard(name, slug, cidrs, url, ca)
    return True


def main() -> int:
    try:
        customers = load_customers()
        customer = select_customer(customers)
        changed = setup_customer(customers) if customer is None else edit_customer(customer, customers)
        if not changed:
            return 0
    except (EOFError, KeyboardInterrupt):
        print("\nOnboarding cancelled.", file=sys.stderr)
        return 130
    except (OSError, ValueError, subprocess.CalledProcessError, yaml.YAMLError) as error:
        print(f"Onboarding failed: {error}", file=sys.stderr)
        return 1

    try:
        deploy_customer()
    except (EOFError, KeyboardInterrupt):
        print("\nDeployment interrupted. The wizard changes are saved. "
              "Review the last deployment step before retrying.", file=sys.stderr)
        return 130
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Deployment stopped: {error}", file=sys.stderr)
        print("The wizard changes are saved. Review the deployment output before retrying.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
