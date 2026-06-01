# OpenSearch SIEM Operations

## Host Prerequisites

Set `vm.max_map_count=262144` on the Docker host before starting OpenSearch.

The default Compose heap is `-Xms2g -Xmx2g` so the stack can start on local Docker
Desktop. On a sized production VM, set `OPENSEARCH_JAVA_OPTS` in `.env`, for
example `-Xms12g -Xmx12g`, and keep the heap below the container or host memory
limit so the JVM can finish startup.

## First Start

Run:

```bash
bash scripts/setup-local-secrets.sh
PYTHON=.venv/bin/python bash scripts/test-gitops-config.sh
.venv/bin/python scripts/render-gitops-config.py
docker compose config --quiet
docker compose up -d opensearch
set -a
. ./.env
set +a
OPENSEARCH_URL=https://127.0.0.1:9200 OPENSEARCH_USER=admin OPENSEARCH_PASSWORD="$OPENSEARCH_ADMIN_PASSWORD" \
  .venv/bin/python scripts/reconcile-opensearch-gitops.py
docker compose up -d opensearch-dashboards central-logstash ingest-edge
```

## GitOps Change Flow

1. Edit `gitops/desired/**`.
2. Run `PYTHON=.venv/bin/python bash scripts/test-gitops-config.sh`.
3. Run `.venv/bin/python scripts/render-gitops-config.py`.
4. Review changes under `gitops/rendered/**`.
5. Run `.venv/bin/python scripts/reconcile-opensearch-gitops.py --dry-run`.
6. Run `.venv/bin/python scripts/reconcile-opensearch-gitops.py` when ready to apply.

## Retention Defaults

Default searchable retention is 7 days. Critical selected datasets can retain up to 30 days. Quarantine retains 3-7 days.

## Customer Separation

Customer streams use readable slugs, for example `logs-acme-firewall`. Customer slugs must not change after data is written.

## Ingest Edge TLS And IP Allowlists

Customer relays send HTTPS traffic to the central ingest edge on TCP 5044. The ingest edge mounts `secrets/certs/central.crt` and `secrets/certs/central.key`.

IP allowlisting must be enforced where the real customer source IP is visible. The preferred version-one deployment enforces customer allowlists at the host firewall before traffic reaches Docker. If a trusted reverse proxy sits in front of `ingest-edge`, set `TRUSTED_PROXY_CIDRS` to the proxy CIDR only; `ingest-edge` then accepts `X-Forwarded-For` only from those proxy addresses. Do not accept `X-Forwarded-For` directly from the public internet.

## Backup Warning

External S3-compatible object storage is optional in version one. Until it is configured, VM or disk loss can destroy SIEM data.
