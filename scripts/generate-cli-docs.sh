#!/usr/bin/env bash
# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

# Generate CLI references from clap and the RBC SDK reference from sdk.rs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

check=0
case "${1:-}" in
  --check) check=1 ;;
  -h|--help)
    echo "Usage: ./scripts/generate-cli-docs.sh [--check]"
    echo "Generate RBC/rbs-cli Markdown and the RBC SDK reference; --check never changes documents."
    exit 0 ;;
  "") ;;
  *) echo "Unknown argument: $1" >&2; exit 2 ;;
esac
if [[ $# -gt 1 ]]; then
  echo "Expected at most one argument" >&2
  exit 2
fi

output_root="$(mktemp -d)"
trap 'rm -rf "$output_root"' EXIT
cargo run --locked --quiet -p rbs-cli --example generate-cli-docs -- --output-dir "$output_root"
"${PYTHON_BIN:-python3}" "$SCRIPT_DIR/gen-rbc-sdk-docs.py" --output "$output_root/docs/api/rbc/sdk.md"

failed=0
for path in docs/api/rbc/cli.md docs/api/rbs-cli/cli.md docs/api/rbc/sdk.md; do
  if [[ "$check" -eq 1 ]]; then
    if ! cmp -s "$output_root/$path" "$REPO_ROOT/$path"; then
      echo "error: $path differs from generated output (or is missing)." >&2
      failed=1
    fi
  else
    mkdir -p "$(dirname "$REPO_ROOT/$path")"
    if ! cmp -s "$output_root/$path" "$REPO_ROOT/$path"; then
      cp "$output_root/$path" "$REPO_ROOT/$path"
    fi
  fi
done
if [[ "$failed" -ne 0 ]]; then
  echo "Run ./scripts/generate-cli-docs.sh and commit all generated documents." >&2
  exit 1
fi
echo "CLI and SDK documentation is in sync."
