#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ -z "${RELAY_CENTRAL_URL:-}" ]]; then
  echo "ERROR: RELAY_CENTRAL_URL not set. Set it in .env or environment." >&2
  exit 1
fi

assert_fails_with() {
  local expected="$1"
  shift
  local output
  set +e
  output="$("$@" 2>&1)"
  local rc=$?
  set -e
  if [[ $rc -eq 0 ]]; then
    echo "expected command to fail: $*" >&2
    exit 1
  fi
  if ! grep -Fq "$expected" <<<"$output"; then
    echo "missing expected failure message: $expected" >&2
    echo "$output" >&2
    exit 1
  fi
}

relay_central_url="$RELAY_CENTRAL_URL"
assert_fails_with "ERROR: RELAY_CENTRAL_URL not set" \
  env -u RELAY_CENTRAL_URL bash scripts/generate-relay-bundle.sh acme
assert_fails_with "ERROR: RELAY_CENTRAL_URL contains unsafe characters" \
  env RELAY_CENTRAL_URL='https://siem.example.com:5044"bad' bash scripts/generate-relay-bundle.sh acme
assert_fails_with "ERROR: RELAY_CENTRAL_URL must use https" \
  env RELAY_CENTRAL_URL='http://siem.example.com:5044' bash scripts/generate-relay-bundle.sh acme
assert_fails_with "ERROR: RELAY_CENTRAL_URL port must be a number" \
  env RELAY_CENTRAL_URL='https://siem.example.com:bad' bash scripts/generate-relay-bundle.sh acme
assert_fails_with "ERROR: RELAY_CENTRAL_URL must not contain whitespace" \
  env RELAY_CENTRAL_URL='https://bad host:5044' bash scripts/generate-relay-bundle.sh acme
assert_fails_with "ERROR: RELAY_CENTRAL_URL host must be a valid DNS name or IP address" \
  env RELAY_CENTRAL_URL='https://bad_host:5044' bash scripts/generate-relay-bundle.sh acme
assert_fails_with "ERROR: RELAY_CENTRAL_URL must not include username or password" \
  env RELAY_CENTRAL_URL='https://user:pass@siem.example.com:5044' bash scripts/generate-relay-bundle.sh acme

RELAY_CENTRAL_URL="$relay_central_url" bash scripts/generate-relay-bundle.sh acme
test -f relay/bundles/acme/logstash.yml
test -f relay/bundles/acme/pipeline.conf
grep -Fq "$relay_central_url" relay/bundles/acme/pipeline.conf
grep -q "central-ca.crt" relay/bundles/acme/pipeline.conf

bundle_dir="relay/bundles/acme"
grep -q 'port => 5514' "$bundle_dir/pipeline.conf" || { echo "missing generic-syslog port"; exit 1; }
grep -q '\[siem\]\[source_id\]" => "generic-syslog"' "$bundle_dir/pipeline.conf" || { echo "missing generic-syslog source_id"; exit 1; }
! grep -q 'port => 5515' "$bundle_dir/pipeline.conf" || { echo "unexpected windows-ad syslog port"; exit 1; }
! grep -q 'port => 5516' "$bundle_dir/pipeline.conf" || { echo "unexpected windows-sysmon syslog port"; exit 1; }
! grep -q '\[siem\]\[source_id\]" => "windows-ad"' "$bundle_dir/pipeline.conf" || { echo "unexpected windows-ad source_id in relay"; exit 1; }
! grep -q '\[siem\]\[source_id\]" => "windows-sysmon"' "$bundle_dir/pipeline.conf" || { echo "unexpected windows-sysmon source_id in relay"; exit 1; }
grep -q 'generic-syslog: udp/tcp 5514' "$bundle_dir/README.md" || { echo "missing generic-syslog README port"; exit 1; }
! grep -q 'windows-ad' "$bundle_dir/README.md" || { echo "unexpected windows-ad README port"; exit 1; }
! grep -q 'windows-sysmon' "$bundle_dir/README.md" || { echo "unexpected windows-sysmon README port"; exit 1; }

"${PYTHON:-python3}" - <<'PY'
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from scripts.lib import gitops_config

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

gitops_config.read_yaml = fake_read_yaml
with pytest.raises(ValueError, match="catalog dataset"):
    gitops_config.load_sources(customers, retention_names, catalog)
PY

echo "relay bundle test passed"
