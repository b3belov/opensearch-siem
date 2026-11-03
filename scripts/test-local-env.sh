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

assert_dashboards_proxy_env() {
  local env_file="$1"
  (
    set -a
    # shellcheck disable=SC1090
    . "$env_file"
    set +a
    if [[ "${DASHBOARDS_PUBLIC_HOST:-}" != "localhost" ]]; then
      echo "${env_file} did not default DASHBOARDS_PUBLIC_HOST to localhost" >&2
      exit 1
    fi
    if [[ "${DASHBOARDS_PROXY_BIND:-}" != "127.0.0.1" ]]; then
      echo "${env_file} did not default DASHBOARDS_PROXY_BIND to 127.0.0.1" >&2
      exit 1
    fi
  )
}

assert_heap_env .env.example
assert_dashboards_proxy_env .env.example

assert_mode() {
  local expected="$1"
  local path="$2"
  local mode
  mode="$(stat -c %a "$path" 2>/dev/null || stat -f %Lp "$path")"
  if [[ "$mode" != "$expected" ]]; then
    echo "$path has mode $mode, expected $expected" >&2
    exit 1
  fi
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
mkdir -p "$tmp_dir/scripts"
cp scripts/setup-local-secrets.sh "$tmp_dir/scripts/setup-local-secrets.sh"

(
  cd "$tmp_dir"
  bash scripts/setup-local-secrets.sh >/dev/null
  assert_heap_env .env
  assert_dashboards_proxy_env .env
  test -f secrets/certs/dashboards.crt
  test -f secrets/certs/dashboards.key
  test -f secrets/certs/dashboards-proxy.crt
  test -f secrets/certs/dashboards-proxy.key
  assert_mode 600 secrets/certs/dashboards.key
  assert_mode 644 secrets/certs/dashboards.crt
  assert_mode 644 secrets/certs/dashboards-proxy.key
  assert_mode 644 secrets/certs/dashboards-proxy.crt
  chmod 600 secrets/certs/dashboards-proxy.key
  bash scripts/setup-local-secrets.sh >/dev/null
  assert_mode 644 secrets/certs/dashboards-proxy.key
)

echo "local env checks passed"
