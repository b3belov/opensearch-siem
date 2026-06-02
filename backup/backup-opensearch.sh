#!/usr/bin/env bash
set -euo pipefail

if [[ "${BACKUP_ENABLED:-false}" != "true" ]]; then
  echo "backup disabled"
  exit 0
fi

if [[ -z "${OPENSEARCH_USER:-}" || -z "${OPENSEARCH_PASSWORD:-}" ]]; then
  echo "ERROR: OPENSEARCH_USER and OPENSEARCH_PASSWORD must be set." >&2
  exit 1
fi

if [[ -z "${OPENSEARCH_CA:-}" || ! -f "${OPENSEARCH_CA}" ]]; then
  echo "ERROR: OPENSEARCH_CA not set or file not found at '${OPENSEARCH_CA:-}'. Mount the CA certificate." >&2
  exit 1
fi
curl_tls_args=(--cacert "$OPENSEARCH_CA")

snapshot_name="snapshot-$(date -u +%Y%m%dT%H%M%SZ)"
curl -sSf "${curl_tls_args[@]}" \
  -u "$OPENSEARCH_USER:$OPENSEARCH_PASSWORD" \
  -XPUT "$OPENSEARCH_URL/_snapshot/$SNAPSHOT_REPOSITORY/$snapshot_name?wait_for_completion=false"
echo "started OpenSearch snapshot $snapshot_name"
