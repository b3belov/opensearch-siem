#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

"${PYTHON:-python3}" -m pytest scripts/test-opensearch-reconciler.py -q

tmp_dir="$(mktemp -d)"
server_pid=""
trap 'if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || true; wait "$server_pid" 2>/dev/null || true; fi; rm -rf "$tmp_dir"' EXIT

"${PYTHON:-python3}" - "$tmp_dir/port" <<'PY' &
from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/_index_template":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"index_templates":[]}')
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
Path(sys.argv[1]).write_text(str(server.server_address[1]), encoding="utf-8")
server.serve_forever()
PY
server_pid="$!"

for _ in {1..50}; do
  if [[ -s "$tmp_dir/port" ]]; then
    break
  fi
  sleep 0.1
done

if [[ ! -s "$tmp_dir/port" ]]; then
  echo "mock OpenSearch did not start" >&2
  exit 1
fi

port="$(<"$tmp_dir/port")"
output="$(OPENSEARCH_URL="http://127.0.0.1:${port}" \
  OPENSEARCH_USER=admin \
  OPENSEARCH_PASSWORD=secret \
  "${PYTHON:-python3}" scripts/reconcile-opensearch-gitops.py --dry-run 2>&1)"
printf '%s\n' "$output"

grep -q "DRY-RUN PUT /_plugins/_security/api/roles/logstash_writer" <<<"$output"
grep -q "DRY-RUN PUT /_plugins/_security/api/internalusers/logstash_writer" <<<"$output"
grep -q "DRY-RUN PUT /_plugins/_security/api/rolesmapping/logstash_writer" <<<"$output"

echo "opensearch reconciler dry-run passed"
