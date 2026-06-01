#!/usr/bin/env bash
set -euo pipefail

output="/backup/gitops-$(date -u +%Y%m%dT%H%M%SZ).bundle"
git -C /repo bundle create "$output" --all
echo "wrote Git bundle $output"
