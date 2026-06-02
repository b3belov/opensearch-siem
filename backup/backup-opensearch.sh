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

missing_snapshot_config=()
[[ -z "${OPENSEARCH_URL:-}" ]] && missing_snapshot_config+=("OPENSEARCH_URL")
[[ -z "${SNAPSHOT_REPOSITORY:-}" ]] && missing_snapshot_config+=("SNAPSHOT_REPOSITORY")
if (( ${#missing_snapshot_config[@]} > 0 )); then
  printf "ERROR: %s must be set before creating an OpenSearch snapshot.\\n" "${missing_snapshot_config[*]}" >&2
  echo "Set OPENSEARCH_URL to the OpenSearch base URL and SNAPSHOT_REPOSITORY to the registered snapshot repository name." >&2
  exit 1
fi

curl_tls_args=(--cacert "$OPENSEARCH_CA")

if ! repo_check=$(curl -sS -o /dev/null -w "%{http_code}" "${curl_tls_args[@]}" \
  -u "$OPENSEARCH_USER:$OPENSEARCH_PASSWORD" \
  "$OPENSEARCH_URL/_snapshot/$SNAPSHOT_REPOSITORY"); then
  cat >&2 <<ERRMSG
ERROR: snapshot repository preflight failed before creating a snapshot.
Check OPENSEARCH_URL, OPENSEARCH_CA, and network/TLS connectivity, then retry.
ERRMSG
  exit 1
fi

if [[ "$repo_check" != "200" ]]; then
  case "$repo_check" in
    404)
      printf "ERROR: snapshot repository '%s' not found (HTTP 404).\\n" "$SNAPSHOT_REPOSITORY" >&2
      cat >&2 <<'ERRMSG'
Register it first, e.g.:

  curl --cacert "$OPENSEARCH_CA" -u "$OPENSEARCH_USER:$OPENSEARCH_PASSWORD" -XPUT "$OPENSEARCH_URL/_snapshot/$SNAPSHOT_REPOSITORY" \
    -H 'Content-Type: application/json' \
    -d '{"type":"fs","settings":{"location":"/usr/share/opensearch/snapshots"}}'

See: https://opensearch.org/docs/latest/tuning-your-cluster/availability-and-recovery/snapshots/snapshot-restore/
ERRMSG
      ;;
    401|403)
      cat >&2 <<ERRMSG
ERROR: snapshot repository preflight returned HTTP $repo_check.
Check OPENSEARCH_USER/OPENSEARCH_PASSWORD and ensure the account can read snapshot repository metadata.
ERRMSG
      ;;
    *)
      cat >&2 <<ERRMSG
ERROR: snapshot repository preflight failed (HTTP $repo_check).
Check OpenSearch availability and snapshot repository configuration before retrying.
ERRMSG
      ;;
  esac
  exit 1
fi

snapshot_name="snapshot-$(date -u +%Y%m%dT%H%M%SZ)"
curl -sSf "${curl_tls_args[@]}" \
  -u "$OPENSEARCH_USER:$OPENSEARCH_PASSWORD" \
  -XPUT "$OPENSEARCH_URL/_snapshot/$SNAPSHOT_REPOSITORY/$snapshot_name?wait_for_completion=false"
echo "started OpenSearch snapshot $snapshot_name"
