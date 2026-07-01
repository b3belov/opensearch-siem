#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

paths=(
  ".env"
  "secrets/local/admin-password"
  "secrets/local/customer-acme-password"
  "secrets/certs/central.key"
  "secrets/certs/central.crt"
  "secrets/certs/dashboards.key"
  "secrets/certs/dashboards.crt"
  "secrets/certs/dashboards-proxy.key"
  "secrets/certs/dashboards-proxy.crt"
  "relay/bundles/acme-forwarder.tar.gz"
  "gitops/rendered/secrets/decrypted.yml"
)

for path in "${paths[@]}"; do
  if ! git check-ignore -q "$path"; then
    echo "not ignored: $path" >&2
    exit 1
  fi
done

echo "secret ignore checks passed"
