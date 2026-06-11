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
  "relay/bundles/acme-forwarder.tar.gz"
  "gitops/rendered/secrets/decrypted.yml"
  "customer-forwarder/.env"
  "customer-forwarder/certs/central-ca.crt"
  "customer-forwarder/certs/customer-forwarder.key"
  "customer-forwarder/http-certs/server.crt"
  "customer-forwarder/http-certs/server.pkcs8.key"
  "customer-forwarder/http-certs/client.pfx"
  "customer-forwarder/data/logstash/queue/page.0"
)

for path in "${paths[@]}"; do
  if ! git check-ignore -q "$path"; then
    echo "not ignored: $path" >&2
    exit 1
  fi
done

echo "secret ignore checks passed"
