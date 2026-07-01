#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

mkdir -p secrets/local secrets/certs data/opensearch data/logstash data/backups
chmod 700 secrets secrets/local secrets/certs

write_secret() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    openssl rand -base64 32 > "$path"
    chmod 600 "$path"
  fi
}

write_secret secrets/local/opensearch-admin-password
write_secret secrets/local/logstash-writer-password
write_secret secrets/local/customer-acme-password

if [[ ! -f secrets/certs/central.key || ! -f secrets/certs/central.crt ]]; then
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout secrets/certs/central.key \
    -out secrets/certs/central.crt \
    -days 365 \
    -subj "/CN=opensearch-siem-central-logstash" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
  cp secrets/certs/central.crt secrets/certs/central-ca.crt
  chmod 600 secrets/certs/central.key
  chmod 644 secrets/certs/central.crt secrets/certs/central-ca.crt
fi

if [[ ! -f secrets/certs/root-ca.key || ! -f secrets/certs/root-ca.crt ]]; then
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout secrets/certs/root-ca.key \
    -out secrets/certs/root-ca.crt \
    -days 3650 \
    -subj "/CN=opensearch-siem-root-ca"
  chmod 600 secrets/certs/root-ca.key
  chmod 644 secrets/certs/root-ca.crt
fi

if [[ ! -f secrets/certs/opensearch.key || ! -f secrets/certs/opensearch.crt ]]; then
  openssl req -nodes -newkey rsa:2048 \
    -keyout secrets/certs/opensearch.key \
    -out secrets/certs/opensearch.csr \
    -subj "/CN=opensearch"
  openssl x509 -req -in secrets/certs/opensearch.csr \
    -CA secrets/certs/root-ca.crt -CAkey secrets/certs/root-ca.key -CAcreateserial \
    -out secrets/certs/opensearch.crt -days 825 \
    -extfile <(printf "subjectAltName=DNS:opensearch,DNS:localhost,IP:127.0.0.1")
  rm -f secrets/certs/opensearch.csr
  chmod 600 secrets/certs/opensearch.key
  chmod 644 secrets/certs/opensearch.crt
fi

if [[ ! -f secrets/certs/dashboards.key || ! -f secrets/certs/dashboards.crt ]]; then
  openssl req -nodes -newkey rsa:2048 \
    -keyout secrets/certs/dashboards.key \
    -out secrets/certs/dashboards.csr \
    -subj "/CN=opensearch-dashboards"
  openssl x509 -req -in secrets/certs/dashboards.csr \
    -CA secrets/certs/root-ca.crt -CAkey secrets/certs/root-ca.key -CAcreateserial \
    -out secrets/certs/dashboards.crt -days 825 \
    -extfile <(printf "subjectAltName=DNS:opensearch-dashboards,DNS:localhost,IP:127.0.0.1")
  rm -f secrets/certs/dashboards.csr
  chmod 600 secrets/certs/dashboards.key
  chmod 644 secrets/certs/dashboards.crt
fi

if [[ ! -f secrets/certs/dashboards-proxy.key || ! -f secrets/certs/dashboards-proxy.crt ]]; then
  openssl req -nodes -newkey rsa:2048 \
    -keyout secrets/certs/dashboards-proxy.key \
    -out secrets/certs/dashboards-proxy.csr \
    -subj "/CN=localhost"
  openssl x509 -req -in secrets/certs/dashboards-proxy.csr \
    -CA secrets/certs/root-ca.crt -CAkey secrets/certs/root-ca.key -CAcreateserial \
    -out secrets/certs/dashboards-proxy.crt -days 825 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")
  rm -f secrets/certs/dashboards-proxy.csr
  chmod 600 secrets/certs/dashboards-proxy.key
  chmod 644 secrets/certs/dashboards-proxy.crt
fi

# v1 single-node: OpenSearch matches the admin client cert by DN (CN=admin)
# only, so no extendedKeyUsage/keyUsage extensions are required. A multi-node
# v2+ deployment SHOULD constrain it:
#   -extfile <(printf "extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature")
if [[ ! -f secrets/certs/admin.key || ! -f secrets/certs/admin.crt ]]; then
  openssl req -nodes -newkey rsa:2048 \
    -keyout secrets/certs/admin.key \
    -out secrets/certs/admin.csr \
    -subj "/CN=admin"
  openssl x509 -req -in secrets/certs/admin.csr \
    -CA secrets/certs/root-ca.crt -CAkey secrets/certs/root-ca.key -CAcreateserial \
    -out secrets/certs/admin.crt -days 825
  rm -f secrets/certs/admin.csr
  chmod 600 secrets/certs/admin.key
  chmod 644 secrets/certs/admin.crt
fi

cat > .env <<EOF
OPENSEARCH_ADMIN_PASSWORD=$(cat secrets/local/opensearch-admin-password)
LOGSTASH_WRITER_USER=logstash_writer
LOGSTASH_WRITER_PASSWORD=$(cat secrets/local/logstash-writer-password)
OPENSEARCH_JAVA_OPTS="-Xms2g -Xmx2g"
BACKUP_ENABLED=false
TRUSTED_PROXY_CIDRS=
OPENSEARCH_CA=secrets/certs/root-ca.crt
DASHBOARDS_PUBLIC_HOST=localhost
DASHBOARDS_PROXY_BIND=127.0.0.1
EOF
chmod 600 .env

echo "local secrets initialized"
