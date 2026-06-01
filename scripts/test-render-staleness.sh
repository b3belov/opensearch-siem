#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

"${PYTHON:-python3}" scripts/render-gitops-config.py

if ! git diff --quiet -- gitops/rendered; then
  echo "ERROR: gitops/rendered is stale. Re-run scripts/render-gitops-config.py and commit." >&2
  git --no-pager diff --stat -- gitops/rendered >&2
  exit 1
fi

echo "rendered artifacts are up to date"
