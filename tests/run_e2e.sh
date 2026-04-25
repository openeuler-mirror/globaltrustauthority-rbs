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
# Run e2e/interface tests (RBS, RBC, tools).
# Invoke from workspace root: ./tests/run_e2e.sh
#
# By default runs all *.sh scripts under tests/rbs, tests/rbc, tests/tools in directory order;
# any failure exits with non-zero.
#
# Usage:
#   ./tests/run_e2e.sh
#   ./tests/run_e2e.sh --suite rbs           # only rbs suite
#   ./tests/run_e2e.sh --pattern version    # only scripts whose filename matches "version"
#   ./tests/run_e2e.sh --testcase foo,bar    # filename must contain foo OR bar (comma-separated)
#
# Environment overrides:
#   E2E_SUITES="rbs,tools"   # limit suites
#   E2E_PATTERN="a,b"        # comma-separated filename substrings (OR); same as multiple --testcase
#
# tests/test_all.sh wraps this script: --testcase there requires --suite; run_e2e.sh alone does not.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
  cat <<EOF
Usage: ./tests/run_e2e.sh [OPTIONS]

Run e2e/interface shell test suites.

Options:
  --suite|-suite NAME   Run only the given suite (can be repeated). Known suites: rbs, rbc, tools
  --pattern STR         Only run scripts whose basename matches STR (substring). STR may be
                        comma-separated; a script runs if it matches any token (OR).
  --testcase STR        Same as --pattern (repeatable; tokens accumulate)
  -h, --help            Show this help and exit

Environment variables:
  E2E_SUITES   Comma-separated list of suites to run (overrides default "rbs,rbc,tools")
  E2E_PATTERN  Comma-separated filename substrings (OR match), same rules as --pattern
EOF
}

# Trim leading/trailing whitespace (bash parameter expansion).
trim_spaces() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

# Append non-empty patterns from a comma-separated string into the name-referenced array.
append_patterns_from_csv() {
  local -n _arr=$1
  local csv="$2"
  [[ -z "$csv" ]] && return 0
  local part parts
  IFS=',' read -r -a parts <<< "$csv"
  for part in "${parts[@]}"; do
    part="$(trim_spaces "$part")"
    [[ -n "$part" ]] && _arr+=("$part")
  done
}

# Return 0 if basename matches any pattern, or if there are no patterns.
filename_matches_patterns() {
  local -n _arr=$1
  local base="$2"
  local p
  [[ "${#_arr[@]}" -eq 0 ]] && return 0
  for p in "${_arr[@]}"; do
    [[ "$base" == *"$p"* ]] && return 0
  done
  return 1
}

main() {
  cd "$REPO_ROOT"

  # Default suites
  local default_e2e_suites=("rbs" "rbc" "tools")
  local suites=()
  local patterns=()
  # Set to 1 when the caller restricts suites or patterns via CLI or env (empty result is an error).
  local filter_was_explicit=0

  if [[ -n "${E2E_PATTERN:-}" ]]; then
    append_patterns_from_csv patterns "${E2E_PATTERN}"
    filter_was_explicit=1
  fi

  # If E2E_SUITES is set, use it as initial suite list
  if [[ -n "${E2E_SUITES:-}" ]]; then
    IFS=',' read -r -a suites <<< "$E2E_SUITES"
    filter_was_explicit=1
  fi

  # Parse CLI flags
  while [[ "${1-}" != "" ]]; do
    case "$1" in
      --suite|-suite)
        shift
        if [[ "${1-}" == "" ]]; then
          echo "Missing value for --suite" >&2
          usage >&2
          exit 1
        fi
        suites+=("$1")
        filter_was_explicit=1
        ;;
      --pattern|--testcase)
        shift
        if [[ "${1-}" == "" ]]; then
          echo "Missing value for --pattern/--testcase" >&2
          usage >&2
          exit 1
        fi
        append_patterns_from_csv patterns "$1"
        filter_was_explicit=1
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

  # If no suites specified anywhere, fall back to defaults
  if [[ "${#suites[@]}" -eq 0 ]]; then
    suites=("${default_e2e_suites[@]}")
  fi

  echo "=== E2e / interface tests (tests/run_e2e.sh) ==="

  local any_e2e_script_ran=0

  for suite in "${suites[@]}"; do
    local dir="$SCRIPT_DIR/$suite"
    [[ -d "$dir" ]] || continue

    for f in "$dir"/*.sh; do
      [[ -f "$f" ]] || continue
      local base
      base="$(basename "$f")"

      if ! filename_matches_patterns patterns "$base"; then
        continue
      fi

      echo "--- $suite: $base ---"
      "$f"
      any_e2e_script_ran=1
    done
  done

  if [[ $any_e2e_script_ran -eq 1 ]]; then
    echo "=== All e2e tests passed ==="
  elif [[ $filter_was_explicit -eq 1 ]]; then
    echo "run_e2e.sh: no scripts matched the requested suite/pattern filter" >&2
    exit 1
  else
    echo "=== No e2e scripts to run ==="
  fi
}

main "$@"
