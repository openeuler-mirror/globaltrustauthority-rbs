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
# Merge gate: Cargo workspace tests, OpenAPI drift check, pytest e2e.
# Invoke from anywhere; the script cd's to the repo root.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

CALLER=test_all.sh

usage() {
  cat <<EOF
Usage: ./tests/test_all.sh [OPTIONS]

Run the project test suite from the repository root.

Options:
  --no-cargo          Skip Cargo tests
  --no-e2e            Skip e2e/interface tests
  --suite NAME        Limit to a component (repeatable). NAME is one of:
                        rbs, rbc, tools           — Cargo + e2e for that area
                        rbs-e2e, rbc-e2e, tools-e2e — e2e only (no Cargo)
  -suite NAME         Same as --suite
  --testcase NAME     E2e only: test-name substring token(s), comma-separated OR. Requires --suite.
  -h, --help          Show this help and exit

Examples:
  ./tests/test_all.sh
  ./tests/test_all.sh --no-cargo
  ./tests/test_all.sh --suite rbs
  ./tests/test_all.sh -suite rbs-e2e --testcase version,other

Environment variables (default: both enabled):
  ENABLE_CARGO_TESTS=\${ENABLE_CARGO_TESTS:-1}
  ENABLE_E2E_TESTS=\${ENABLE_E2E_TESTS:-1}
EOF
}

assert_openapi_yaml_matches_build() {
  echo ""
  echo "=== OpenAPI: docs/proto/rbs_rest_api.yaml matches rbs build output ==="
  cargo build -p rbs --features rest -q
  if ! git diff --quiet HEAD -- docs/proto/rbs_rest_api.yaml; then
    echo "error: docs/proto/rbs_rest_api.yaml differs from \`cargo build -p rbs --features rest\`." >&2
    echo "Regenerate: cargo build -p rbs --features rest && git add docs/proto/rbs_rest_api.yaml" >&2
    git diff HEAD -- docs/proto/rbs_rest_api.yaml >&2 || true
    exit 1
  fi
  echo "OpenAPI YAML is in sync with the rbs crate build."
}

apply_suite_token() {
  local token=$1
  case "$token" in
    rbs)
      array_push_unique cargo_packages rbs
      array_push_unique cargo_packages rbs-core
      array_push_unique cargo_packages rbs-rest
      array_push_unique cargo_packages rbs-api-types
      array_push_unique e2e_suites rbs
      ;;
    rbc)
      array_push_unique cargo_packages rbc
      array_push_unique e2e_suites rbc
      ;;
    tools)
      array_push_unique cargo_packages rbs-cli
      array_push_unique cargo_packages rbs-admin-client
      array_push_unique e2e_suites tools
      ;;
    rbs-e2e)  array_push_unique e2e_suites rbs ;;
    rbc-e2e)  array_push_unique e2e_suites rbc ;;
    tools-e2e) array_push_unique e2e_suites tools ;;
    *)
      echo "test_all.sh: unknown suite '$token' (expected rbs, rbc, tools, rbs-e2e, rbc-e2e, tools-e2e)" >&2
      exit 1
      ;;
  esac
}

run_cargo_section() {
  local label=$1
  local openapi_check=$2
  shift 2
  local -a cargo_args=("$@")

  if [[ "$ENABLE_CARGO_TESTS" != "1" ]]; then
    echo "=== Cargo tests SKIPPED (ENABLE_CARGO_TESTS=$ENABLE_CARGO_TESTS) ==="
    if [[ "$openapi_check" -eq 1 ]]; then
      echo "(OpenAPI YAML drift check also skipped; requires Cargo build)"
    fi
    return 0
  fi

  if [[ ${#cargo_args[@]} -eq 0 ]]; then
    echo "=== Cargo tests SKIPPED (no Cargo packages for selected suite(s)) ==="
    return 0
  fi

  if [[ "$label" == "workspace" ]]; then
    echo "=== Cargo tests (workspace) ==="
  else
    echo "=== Cargo tests (selected packages) ==="
  fi
  cargo test "${cargo_args[@]}"
  if [[ "$openapi_check" -eq 1 ]]; then
    assert_openapi_yaml_matches_build
  fi
}

run_e2e_section() {
  local suites_name=$1 patterns_name=$2 empty_policy=${3:-skip}

  if [[ "$ENABLE_E2E_TESTS" != "1" ]]; then
    echo "=== E2e / interface tests SKIPPED (ENABLE_E2E_TESTS=$ENABLE_E2E_TESTS) ==="
    return 0
  fi

  local -n _suites=$suites_name
  if [[ ${#_suites[@]} -eq 0 && "$empty_policy" == "fail" ]]; then
    echo "=== E2e / interface tests SKIPPED (no e2e suite in selection) ==="
    return 0
  fi

  echo ""
  run_e2e_pytest "$suites_name" "$patterns_name" "$empty_policy"
}

main() {
  cd "$REPO_ROOT"

  ENABLE_CARGO_TESTS="${ENABLE_CARGO_TESTS:-1}"
  ENABLE_E2E_TESTS="${ENABLE_E2E_TESTS:-1}"
  local suites=() e2e_patterns=()
  local cargo_packages=() e2e_suites=()

  while [[ "${1-}" != "" ]]; do
    case "$1" in
      --no-cargo) ENABLE_CARGO_TESTS="0" ;;
      --no-e2e)   ENABLE_E2E_TESTS="0" ;;
      --suite|-suite)
        shift
        [[ -n "${1-}" ]] || { echo "test_all.sh: missing value for --suite" >&2; usage >&2; exit 1; }
        suites+=("$1")
        ;;
      --testcase)
        shift
        [[ -n "${1-}" ]] || { echo "test_all.sh: missing value for --testcase" >&2; usage >&2; exit 1; }
        append_e2e_patterns_from_csv e2e_patterns "$1"
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

  if [[ ${#e2e_patterns[@]} -gt 0 && ${#suites[@]} -eq 0 ]]; then
    echo "test_all.sh: --testcase requires at least one --suite" >&2
    exit 1
  fi

  if [[ "$ENABLE_CARGO_TESTS" != "1" && "$ENABLE_E2E_TESTS" != "1" ]]; then
    echo "No test sections enabled; nothing to run."
    exit 0
  fi

  if [[ ${#suites[@]} -eq 0 ]]; then
    run_cargo_section workspace 1 --workspace
    run_e2e_section e2e_suites e2e_patterns skip
  else
    local s
    for s in "${suites[@]}"; do
      apply_suite_token "$s"
    done
    local -a cargo_args=()
    local p openapi_check=0
    for p in "${cargo_packages[@]}"; do
      cargo_args+=(-p "$p")
    done
    if e2e_suites_include_rbs "${suites[@]}"; then
      openapi_check=1
    fi
    run_cargo_section selected "$openapi_check" "${cargo_args[@]}"

    local e2e_empty_policy
    e2e_empty_policy="$(resolve_test_all_e2e_empty_policy ${#e2e_patterns[@]} "${suites[@]}")"
    run_e2e_section e2e_suites e2e_patterns "$e2e_empty_policy"
  fi

  echo ""
  echo "=== test_all.sh completed successfully ==="
}

main "$@"
