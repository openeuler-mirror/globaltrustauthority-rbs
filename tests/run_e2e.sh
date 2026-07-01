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
#
# Run e2e/interface tests via pytest (suites: rbs, rbc, tools).
# Invoke from workspace root: ./tests/run_e2e.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

CALLER=run_e2e.sh

usage() {
  cat <<EOF
Usage: ./tests/run_e2e.sh [OPTIONS]

Run pytest e2e suites under tests/e2e/.

Options:
  --suite|-suite NAME   Suite marker (repeatable): rbs, rbc, tools
  --pattern STR         Test-name substring token; comma-separated tokens are OR'd
  --testcase STR        Alias for --pattern (repeatable)
  -h, --help            Show this help and exit

Environment variables:
  E2E_SUITES    Comma-separated suite markers (default: rbs,rbc,tools)
  E2E_PATTERN   Comma-separated testcase substring tokens (OR)
  PYTHON_BIN    Python interpreter for pytest

Requires: python3, pytest (tests/requirements.txt), openssl, cargo (rest feature).
EOF
}

main() {
  cd "$REPO_ROOT"

  local suites=() patterns=() empty_policy=skip

  append_e2e_patterns_from_csv patterns "${E2E_PATTERN:-}"
  [[ -n "${E2E_PATTERN:-}" ]] && empty_policy=fail
  append_csv_to_array suites "${E2E_SUITES:-}"
  [[ -n "${E2E_SUITES:-}" ]] && empty_policy=fail

  while [[ "${1-}" != "" ]]; do
    case "$1" in
      --suite|-suite)
        shift
        [[ -n "${1-}" ]] || { echo "Missing value for --suite" >&2; usage >&2; exit 1; }
        validate_e2e_suites "$1"
        suites+=("$1")
        empty_policy=fail
        ;;
      --pattern|--testcase)
        shift
        [[ -n "${1-}" ]] || { echo "Missing value for --pattern/--testcase" >&2; usage >&2; exit 1; }
        append_e2e_patterns_from_csv patterns "$1"
        empty_policy=fail
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "Unknown option: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
    shift
  done

  run_e2e_pytest suites patterns "$empty_policy"
}

main "$@"
