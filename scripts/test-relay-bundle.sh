#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

bash scripts/generate-relay-bundle.sh acme
test -f relay/bundles/acme/logstash.yml
test -f relay/bundles/acme/pipeline.conf
grep -q "https://siem.example.com:5044" relay/bundles/acme/pipeline.conf
grep -q "central-ca.crt" relay/bundles/acme/pipeline.conf

bundle_dir="relay/bundles/acme"
grep -q 'port => 5514' "$bundle_dir/pipeline.conf" || { echo "missing firewall port"; exit 1; }
grep -q 'port => 5515' "$bundle_dir/pipeline.conf" || { echo "missing windows port"; exit 1; }
grep -q '\[siem\]\[source_id\]" => "windows"' "$bundle_dir/pipeline.conf" || { echo "missing windows source_id"; exit 1; }

echo "relay bundle test passed"
