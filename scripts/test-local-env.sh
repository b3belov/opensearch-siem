#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

assert_heap_env() {
  local env_file="$1"
  (
    set -a
    # shellcheck disable=SC1090
    . "$env_file"
    set +a
    if [[ "${OPENSEARCH_JAVA_OPTS:-}" != "-Xms2g -Xmx2g" ]]; then
      echo "${env_file} did not preserve OPENSEARCH_JAVA_OPTS" >&2
      exit 1
    fi
  )
}

assert_heap_env .env.example

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
mkdir -p "$tmp_dir/scripts"
cp scripts/setup-local-secrets.sh "$tmp_dir/scripts/setup-local-secrets.sh"

(
  cd "$tmp_dir"
  bash scripts/setup-local-secrets.sh >/dev/null
  assert_heap_env .env
)

echo "local env checks passed"
