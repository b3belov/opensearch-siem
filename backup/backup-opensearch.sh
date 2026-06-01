#!/usr/bin/env bash
set -euo pipefail

if [[ "${BACKUP_ENABLED:-false}" != "true" ]]; then
  echo "backup disabled"
  exit 0
fi

snapshot_name="snapshot-$(date -u +%Y%m%dT%H%M%SZ)"
curl -sku "$OPENSEARCH_USER:$OPENSEARCH_PASSWORD" \
  -XPUT "$OPENSEARCH_URL/_snapshot/$SNAPSHOT_REPOSITORY/$snapshot_name?wait_for_completion=false"
echo "started OpenSearch snapshot $snapshot_name"
