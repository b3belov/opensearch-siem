#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

PYTHONPATH=customer-forwarder/scripts "${PYTHON:-python3}" -m pytest \
  customer-forwarder/test/test_forwarder_config.py \
  customer-forwarder/test/test_forwarder_env.py \
  customer-forwarder/test/test_catalog_copy.py \
  customer-forwarder/test/test_compose_config.py \
  customer-forwarder/test/test_load_smoke.py \
  -q

PYTHON="${PYTHON:-python3}" bash customer-forwarder/scripts/test-logstash-config.sh
PYTHONPATH=customer-forwarder/scripts "${PYTHON:-python3}" customer-forwarder/scripts/parser-smoke.py

echo "customer forwarder tests passed"
