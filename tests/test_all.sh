#!/usr/bin/env bash
# Run all tests: Cargo workspace unit/integration tests, then e2e/interface scripts.
# Can be invoked from anywhere; the script cd's to the repo root.
#
# Usage:
#   ./tests/test_all.sh                               # Run all tests
#   ./tests/test_all.sh --no-cargo                    # Skip Cargo tests
#   ./tests/test_all.sh --no-e2e                      # Skip e2e tests
#   ./tests/test_all.sh -h                            # Show help
#   ./tests/test_all.sh --suite rbs                   # Only run RBS tests (Cargo + tests/rbs e2e)
#   ./tests/test_all.sh --suite rbc                   # Only run RBC tests
#   ./tests/test_all.sh --suite tools                 # Only run tools tests
#   ./tests/test_all.sh -suite rbs-e2e                # Only run RBS e2e scripts
#   ./tests/test_all.sh -suite rbc-e2e                # Only run RBC e2e scripts
#   ./tests/test_all.sh -suite tools-e2e              # Only run tools e2e scripts
#   ./tests/test_all.sh -suite rbs-e2e --testcase e2e_version_curl,other
#                                                   # RBS e2e scripts matching any listed substring
#
# Environment toggles (default: all enabled):
#   ENABLE_CARGO_TESTS=0 ./tests/test_all.sh   # skip Cargo tests
#   ENABLE_E2E_TESTS=0   ./tests/test_all.sh   # skip e2e/interface tests

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
  cat <<EOF
Usage: ./tests/test_all.sh [OPTIONS]

Run the project test suite from the repository root.

Options:
  --no-cargo          Skip Cargo tests
  --no-e2e            Skip e2e/interface tests
  --suite NAME        Limit to a component (repeatable). NAME is one of:
                        rbs, rbc, tools           — Cargo tests for that area + e2e suite
                        rbs-e2e, rbc-e2e, tools-e2e — e2e scripts for that directory only (no Cargo)
  -suite NAME         Same as --suite
  --testcase NAME     When running e2e, only scripts whose filename matches NAME (substring). Use a
                        comma-separated list for OR (e.g. e2e_version_curl,other_case). Repeatable.
  -h, --help          Show this help and exit

Examples:
  ./tests/test_all.sh                                       # Run all tests
  ./tests/test_all.sh --no-cargo                            # Skip Cargo tests
  ./tests/test_all.sh --no-e2e                              # Skip e2e tests
  ./tests/test_all.sh -h                                    # Show help
  ./tests/test_all.sh --suite rbs                           # Only RBS tests (Cargo + rbs e2e)
  ./tests/test_all.sh --suite rbc                           # Only RBC tests
  ./tests/test_all.sh --suite tools                         # Only tools tests
  ./tests/test_all.sh -suite rbs-e2e                        # Only RBS e2e tests
  ./tests/test_all.sh -suite rbc-e2e                        # Only RBC e2e tests
  ./tests/test_all.sh -suite tools-e2e                      # Only tools e2e tests
  ./tests/test_all.sh -suite rbs-e2e --testcase e2e_version_curl,other
                                                            # RBS e2e: OR match on filename substrings

Environment variables (defaults shown):
  ENABLE_CARGO_TESTS=\${ENABLE_CARGO_TESTS:-1}
  ENABLE_E2E_TESTS=\${ENABLE_E2E_TESTS:-1}
EOF
}

# Append unique values to a name-reference array (bash 4.3+)
array_push_unique() {
  local -n _arr=$1
  local val=$2
  local x
  for x in "${_arr[@]:-}"; do
    [[ "$x" == "$val" ]] && return 0
  done
  _arr+=("$val")
}

main() {
  cd "$REPO_ROOT"

  ENABLE_CARGO_TESTS="${ENABLE_CARGO_TESTS:-1}"
  ENABLE_E2E_TESTS="${ENABLE_E2E_TESTS:-1}"
  local suites=()
  local testcase_flags=()

  while [[ "${1-}" != "" ]]; do
    case "$1" in
      --no-cargo)
        ENABLE_CARGO_TESTS="0"
        ;;
      --no-e2e)
        ENABLE_E2E_TESTS="0"
        ;;
      --suite|-suite)
        shift
        if [[ "${1-}" == "" ]]; then
          echo "test_all.sh: missing value for --suite" >&2
          usage >&2
          exit 1
        fi
        suites+=("$1")
        ;;
      --testcase)
        shift
        if [[ "${1-}" == "" ]]; then
          echo "test_all.sh: missing value for --testcase" >&2
          usage >&2
          exit 1
        fi
        testcase_flags+=(--testcase "$1")
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

  if [[ "${#testcase_flags[@]}" -gt 0 && "${#suites[@]}" -eq 0 ]]; then
    echo "test_all.sh: --testcase requires at least one --suite" >&2
    exit 1
  fi

  if [[ "$ENABLE_CARGO_TESTS" != "1" && "$ENABLE_E2E_TESTS" != "1" ]]; then
    echo "No test sections enabled (ENABLE_CARGO_TESTS=$ENABLE_CARGO_TESTS, ENABLE_E2E_TESTS=$ENABLE_E2E_TESTS); nothing to run."
    exit 0
  fi

  local cargo_packages=()
  local e2e_suites=()

  if [[ "${#suites[@]}" -eq 0 ]]; then
    # Default: full workspace + all e2e
    if [[ "$ENABLE_CARGO_TESTS" == "1" ]]; then
      echo "=== Cargo tests (workspace) ==="
      cargo test --workspace
    else
      echo "=== Cargo tests (workspace) SKIPPED (ENABLE_CARGO_TESTS=$ENABLE_CARGO_TESTS) ==="
    fi

    echo ""
    if [[ "$ENABLE_E2E_TESTS" == "1" ]]; then
      echo "=== E2e / interface tests ==="
      ./tests/run_e2e.sh
    else
      echo "=== E2e / interface tests SKIPPED (ENABLE_E2E_TESTS=$ENABLE_E2E_TESTS) ==="
    fi
  else
    for s in "${suites[@]}"; do
      case "$s" in
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
        rbs-e2e)
          array_push_unique e2e_suites rbs
          ;;
        rbc-e2e)
          array_push_unique e2e_suites rbc
          ;;
        tools-e2e)
          array_push_unique e2e_suites tools
          ;;
        *)
          echo "test_all.sh: unknown suite '$s' (expected rbs, rbc, tools, rbs-e2e, rbc-e2e, tools-e2e)" >&2
          exit 1
          ;;
      esac
    done

    if [[ "$ENABLE_CARGO_TESTS" == "1" ]]; then
      if [[ "${#cargo_packages[@]}" -gt 0 ]]; then
        echo "=== Cargo tests (selected packages) ==="
        local args=()
        local p
        for p in "${cargo_packages[@]}"; do
          args+=(-p "$p")
        done
        cargo test "${args[@]}"
      else
        echo "=== Cargo tests SKIPPED (no Cargo packages for selected suite(s); use rbs/rbc/tools for unit tests) ==="
      fi
    else
      echo "=== Cargo tests SKIPPED (ENABLE_CARGO_TESTS=$ENABLE_CARGO_TESTS) ==="
    fi

    echo ""
    if [[ "$ENABLE_E2E_TESTS" == "1" ]]; then
      if [[ "${#e2e_suites[@]}" -gt 0 ]]; then
        echo "=== E2e / interface tests (selected suites) ==="
        local e2e_args=()
        local d
        for d in "${e2e_suites[@]}"; do
          e2e_args+=(--suite "$d")
        done
        if [[ "${#testcase_flags[@]}" -gt 0 ]]; then
          e2e_args+=("${testcase_flags[@]}")
        fi
        ./tests/run_e2e.sh "${e2e_args[@]}"
      else
        echo "=== E2e / interface tests SKIPPED (no e2e suite in selection) ==="
      fi
    else
      echo "=== E2e / interface tests SKIPPED (ENABLE_E2E_TESTS=$ENABLE_E2E_TESTS) ==="
    fi
  fi

  echo ""
  echo "=== test_all.sh completed successfully ==="
}

main "$@"
