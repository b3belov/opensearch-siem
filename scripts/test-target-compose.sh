#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export OPENSEARCH_ADMIN_PASSWORD="${OPENSEARCH_ADMIN_PASSWORD:-test-admin-password}"
export LOGSTASH_WRITER_USER="${LOGSTASH_WRITER_USER:-logstash_writer}"
export LOGSTASH_WRITER_PASSWORD="${LOGSTASH_WRITER_PASSWORD:-test-logstash-password}"

docker compose config --quiet

rendered="$(docker compose config)"
if grep -q "opensearch-node2" <<<"$rendered"; then
  echo "target architecture must not define opensearch-node2" >&2
  exit 1
fi

if ! grep -q "opensearch:" <<<"$rendered"; then
  echo "missing single opensearch service" >&2
  exit 1
fi

if ! grep -q "central-logstash:" <<<"$rendered"; then
  echo "missing central-logstash service" >&2
  exit 1
fi

if ! grep -q "ingest-edge:" <<<"$rendered"; then
  echo "missing ingest-edge service" >&2
  exit 1
fi

if grep -q "5044:9601" <<<"$rendered"; then
  echo "central-logstash input must not be host-published" >&2
  exit 1
fi

if ! grep -q "INGEST_EDGE_TLS_CERT" <<<"$rendered"; then
  echo "ingest-edge must be configured for TLS" >&2
  exit 1
fi

if ! grep -q "INGEST_EDGE_MAX_BODY_BYTES" <<<"$rendered"; then
  echo "ingest-edge must set a request body limit" >&2
  exit 1
fi

if ! grep -q "OPENSEARCH_JAVA_OPTS: -Xms2g -Xmx2g" <<<"$rendered"; then
  echo "opensearch must default to a local-runnable 2g heap" >&2
  exit 1
fi

override_rendered="$(OPENSEARCH_JAVA_OPTS="-Xms12g -Xmx12g" docker compose config)"
if ! grep -q "OPENSEARCH_JAVA_OPTS: -Xms12g -Xmx12g" <<<"$override_rendered"; then
  echo "opensearch heap must be overrideable for sized production hosts" >&2
  exit 1
fi

echo "target compose config passed"
