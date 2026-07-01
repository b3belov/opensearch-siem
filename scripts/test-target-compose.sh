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

if ! grep -q "dashboards-proxy:" <<<"$rendered"; then
  echo "missing dashboards-proxy service" >&2
  exit 1
fi

if ! grep -q "DASHBOARDS_PUBLIC_HOST: localhost" <<<"$rendered"; then
  echo "dashboards-proxy must default to localhost public host" >&2
  exit 1
fi

if ! grep -q "SERVER_PUBLICBASEURL: https://localhost" <<<"$rendered"; then
  echo "opensearch-dashboards must set public base URL from DASHBOARDS_PUBLIC_HOST" >&2
  exit 1
fi

if grep -q 'published: "5601"' <<<"$rendered"; then
  echo "opensearch-dashboards must not publish port 5601 directly" >&2
  exit 1
fi

if ! grep -q 'published: "443"' <<<"$rendered" || ! grep -q "target: 443" <<<"$rendered"; then
  echo "dashboards-proxy must publish host HTTPS port 443" >&2
  exit 1
fi

if ! grep -q 'published: "80"' <<<"$rendered" || ! grep -q "target: 80" <<<"$rendered"; then
  echo "dashboards-proxy must publish host HTTP port 80 for redirects" >&2
  exit 1
fi

if ! grep -q "host_ip: 127.0.0.1" <<<"$rendered"; then
  echo "dashboards-proxy must default to localhost-only bind" >&2
  exit 1
fi

if ! grep -q "/etc/nginx/templates/default.conf.template" <<<"$rendered"; then
  echo "dashboards-proxy must mount the nginx dashboards template over the default server template" >&2
  exit 1
fi

if ! grep -q "/etc/nginx/nginx.conf" <<<"$rendered"; then
  echo "dashboards-proxy must mount a rootless nginx config without the default user directive" >&2
  exit 1
fi

if ! grep -q "/etc/nginx/certs/root-ca.crt" <<<"$rendered"; then
  echo "dashboards-proxy must mount the SIEM root CA for upstream TLS verification" >&2
  exit 1
fi

if ! grep -q "wget --spider --quiet --no-check-certificate https://127.0.0.1/" <<<"$rendered"; then
  echo "dashboards-proxy must healthcheck the local HTTPS endpoint" >&2
  exit 1
fi

if ! grep -q "/etc/nginx/certs/dashboards-proxy.crt" <<<"$rendered"; then
  echo "dashboards-proxy must use a proxy-specific browser-facing certificate" >&2
  exit 1
fi

if ! grep -q "/etc/nginx/certs/dashboards-proxy.key" <<<"$rendered"; then
  echo "dashboards-proxy must use a proxy-specific browser-facing key" >&2
  exit 1
fi

if ! grep -q "read_only: true" <<<"$rendered"; then
  echo "dashboards-proxy must run with a read-only root filesystem" >&2
  exit 1
fi

if ! grep -q "no-new-privileges:true" <<<"$rendered"; then
  echo "dashboards-proxy must run with no-new-privileges" >&2
  exit 1
fi

if ! grep -q "NET_BIND_SERVICE" <<<"$rendered"; then
  echo "dashboards-proxy must grant only NET_BIND_SERVICE for low ports" >&2
  exit 1
fi

if grep -q "CHOWN" <<<"$rendered"; then
  echo "dashboards-proxy must not grant CAP_CHOWN for nginx temp ownership" >&2
  exit 1
fi

if ! grep -q "user: 101:101" <<<"$rendered"; then
  echo "dashboards-proxy must run as the nginx uid/gid instead of root" >&2
  exit 1
fi

if ! grep -q "/etc/nginx/conf.d" <<<"$rendered" || ! grep -q "/var/cache/nginx" <<<"$rendered" || ! grep -q "/run:uid=101,gid=101" <<<"$rendered"; then
  echo "dashboards-proxy must use tmpfs for nginx writable runtime paths" >&2
  exit 1
fi

if [[ ! -f nginx/templates/dashboards.conf.template ]]; then
  echo "missing nginx dashboards template" >&2
  exit 1
fi

if ! grep -q "proxy_ssl_verify on;" nginx/templates/dashboards.conf.template; then
  echo "nginx must verify Dashboards upstream TLS" >&2
  exit 1
fi

if ! grep -q "proxy_ssl_name opensearch-dashboards;" nginx/templates/dashboards.conf.template; then
  echo "nginx must use the Dashboards certificate DNS name for upstream SNI" >&2
  exit 1
fi

if ! grep -q "resolver 127.0.0.11" nginx/templates/dashboards.conf.template; then
  echo "nginx must use Docker DNS for runtime upstream resolution" >&2
  exit 1
fi

if ! grep -q 'proxy_pass https://$dashboards_upstream:5601;' nginx/templates/dashboards.conf.template; then
  echo "nginx must defer Dashboards upstream resolution until request time" >&2
  exit 1
fi

if ! grep -q "client_max_body_size 10m;" nginx/templates/dashboards.conf.template; then
  echo "nginx must cap request body size for Dashboards" >&2
  exit 1
fi

if ! grep -q "server_tokens off;" nginx/templates/dashboards.conf.template; then
  echo "nginx must disable server token disclosure" >&2
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
