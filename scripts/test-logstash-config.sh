#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "docker unavailable; skipped live logstash config validation"
  exit 0
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
mkdir -p "$tmp_dir/config" "$tmp_dir/data"
cp logstash/config/pipelines.yml "$tmp_dir/config/pipelines.yml"
sed 's#^path.queue:.*#path.queue: /tmp/logstash-config-test-data/queue#' \
  logstash/config/logstash.yml > "$tmp_dir/config/logstash.yml"
printf 'path.data: /tmp/logstash-config-test-data\n' >> "$tmp_dir/config/logstash.yml"

docker compose run --rm --no-deps \
  -v "$tmp_dir/config:/usr/share/logstash/config:ro" \
  -v "$tmp_dir/data:/tmp/logstash-config-test-data" \
  central-logstash \
  logstash --path.settings /usr/share/logstash/config --config.test_and_exit

echo "logstash target config passed"
