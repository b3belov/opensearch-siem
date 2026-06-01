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

credential_id="$("${PYTHON:-python3}" - "$credential_file" <<'PY'
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

"${PYTHON:-python3}" - "$repo_root" "$customer_slug" "$credential_id" <<'PY'
from pathlib import Path
import re
import sys

repo = Path(sys.argv[1])
customer_slug = sys.argv[2]
credential_id = sys.argv[3]

sys.path.insert(0, str(repo))
from scripts.lib.gitops_config import enabled_sources_for_customer, make_jinja_env

# Defense-in-depth: these values are interpolated unescaped into a Logstash
# .conf (autoescape can't help with Ruby-config syntax). guard against
# config-injection / breakout at the emission point. Pattern MUST match the
# id/dataset constraint in gitops/schemas/source.schema.json exactly so the
# generator never rejects a schema-valid source nor accepts an invalid one.
SAFE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")

sources = []
port = 5514
for src in enabled_sources_for_customer(customer_slug):
    sid, dataset = src["id"], src["dataset"]
    if not SAFE.match(sid) or not SAFE.match(dataset):
        raise SystemExit(f"unsafe source id/dataset: {sid!r}/{dataset!r}")
    sources.append({"id": sid, "dataset": dataset, "port": port})
    port += 1
if not sources:
    raise SystemExit(f"no enabled sources for customer {customer_slug}")

env = make_jinja_env(repo)
bundle = repo / "relay" / "bundles" / customer_slug
bundle.mkdir(parents=True, exist_ok=True)
(bundle / "logstash.yml").write_text(
    env.get_template("relay/templates/logstash.yml.j2").render(), encoding="utf-8")
(bundle / "pipeline.conf").write_text(
    env.get_template("relay/templates/pipeline.conf.j2").render(
        customer_slug=customer_slug,
        credential_id=credential_id,
        central_url="https://siem.example.com:5044",
        sources=sources,
    ), encoding="utf-8")
port_table = "\n".join(f"  {s['id']}: udp/tcp {s['port']}" for s in sources)
(bundle / "README.md").write_text(
    "Install central-ca.crt at /usr/share/logstash/config/certs/central-ca.crt "
    "and set CUSTOMER_FORWARDER_PASSWORD before starting the relay.\n\n"
    "Point each log source at the matching syslog listener port:\n"
    f"{port_table}\n",
    encoding="utf-8")
PY

echo "relay bundle written to $bundle_dir"
