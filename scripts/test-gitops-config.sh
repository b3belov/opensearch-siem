#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

"${PYTHON:-python3}" scripts/validate-gitops-config.py
"${PYTHON:-python3}" -m pytest scripts/test-source-catalog.py -q
"${PYTHON:-python3}" -m pytest scripts/test-endpoint-validation.py -q
echo "gitops config validation passed"
