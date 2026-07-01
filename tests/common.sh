# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
# Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.

# Shared helpers for tests/*.sh entry scripts.
# Expects SCRIPT_DIR (tests/) to be set before sourcing.

E2E_DEFAULT_SUITES=(rbs rbc tools)

resolve_python_bin() {
  if [[ -n "${PYTHON_BIN:-}" ]]; then
    return 0
  fi
  if [[ -x /usr/bin/python3 ]]; then
    PYTHON_BIN=/usr/bin/python3
  else
    PYTHON_BIN=python3
  fi
}

ensure_pytest_deps() {
  resolve_python_bin
  if ! "$PYTHON_BIN" -c "import pytest, httpx, yaml" 2>/dev/null; then
    echo "${CALLER:-tests}: e2e Python dependencies are required. Install with:" >&2
    echo "  python3 -m pip install -r tests/requirements.txt" >&2
    exit 1
  fi
}

trim_spaces() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

append_csv_to_array() {
  local -n _arr=$1
  local csv=$2
  [[ -z "$csv" ]] && return 0
  local part parts
  IFS=',' read -r -a parts <<< "$csv"
  for part in "${parts[@]}"; do
    part="$(trim_spaces "$part")"
    [[ -n "$part" ]] && _arr+=("$part")
  done
}

# Project-level testcase tokens (not raw pytest -k expressions).
validate_e2e_testcase_token() {
  local token=$1
  if [[ ! "$token" =~ ^[A-Za-z0-9_:-]+$ ]]; then
    echo "${CALLER:-tests}: invalid testcase token '$token' (allowed: letters, digits, _, -, :; comma separates OR tokens)" >&2
    return 1
  fi
  case "$token" in
    and|or|not)
      echo "${CALLER:-tests}: invalid testcase token '$token' (reserved pytest -k keywords; use direct pytest for expressions)" >&2
      return 1
      ;;
  esac
}

append_e2e_patterns_from_csv() {
  local -n _arr=$1
  local csv=$2
  [[ -z "$csv" ]] && return 0
  local part parts
  IFS=',' read -r -a parts <<< "$csv"
  for part in "${parts[@]}"; do
    part="$(trim_spaces "$part")"
    [[ -z "$part" ]] && continue
    _arr+=("$part")
  done
}

# RBS-only legacy bash script basename -> pytest -k substring (applied only when rbs marker is selected).
map_legacy_rbs_testcase_token() {
  case "$1" in
    e2e_version_curl) printf '%s' "version" ;;
    *) printf '%s' "$1" ;;
  esac
}

# Validate tokens and map legacy aliases when the rbs e2e marker is in scope.
prepare_e2e_k_tokens() {
  local -n _out=$1
  local rbs_selected=$2
  shift 2
  local raw_tokens=("$@")
  _out=()
  local token mapped
  for token in "${raw_tokens[@]}"; do
    validate_e2e_testcase_token "$token" || return 1
    if [[ "$rbs_selected" -eq 1 ]]; then
      mapped="$(map_legacy_rbs_testcase_token "$token")"
    else
      mapped="$token"
    fi
    _out+=("$mapped")
  done
}

# Join tokens with " or " for pytest -m / -k expressions.
build_or_expr() {
  local expr="" t
  for t in "$@"; do
    [[ -z "$t" ]] && continue
    [[ -z "$expr" ]] && expr="$t" || expr="$expr or $t"
  done
  printf '%s' "$expr"
}

array_push_unique() {
  local -n _arr=$1
  local val=$2
  local x
  for x in "${_arr[@]}"; do
    [[ "$x" == "$val" ]] && return 0
  done
  _arr+=("$val")
}

validate_e2e_suites() {
  local s known found
  for s in "$@"; do
    found=0
    for known in "${E2E_DEFAULT_SUITES[@]}"; do
      if [[ "$s" == "$known" ]]; then
        found=1
        break
      fi
    done
    if [[ $found -eq 0 ]]; then
      echo "${CALLER:-tests}: unknown e2e suite '$s' (expected: ${E2E_DEFAULT_SUITES[*]})" >&2
      return 1
    fi
  done
}

e2e_suites_include_rbs() {
  local s
  for s in "$@"; do
    [[ "$s" == "rbs" ]] && return 0
  done
  return 1
}

# True when tests/e2e/<suite>/test_*.py exists (lightweight; no pytest import).
e2e_suite_has_test_files() {
  local suite=$1
  local dir="${SCRIPT_DIR:?}/e2e/${suite}"
  local files=()
  shopt -s nullglob
  files=("$dir"/test_*.py)
  shopt -u nullglob
  [[ ${#files[@]} -gt 0 ]]
}

e2e_markers_have_any_test_files() {
  local s
  for s in "$@"; do
    if e2e_suite_has_test_files "$s"; then
      return 0
    fi
  done
  return 1
}

# test_all.sh: empty_policy when pytest collects zero tests (skip|fail).
# fail when --testcase is set or every --suite token is *-e2e; else skip for component suites.
resolve_test_all_e2e_empty_policy() {
  local pattern_count=$1
  shift
  local suite_tokens=("$@")

  if [[ $pattern_count -gt 0 ]]; then
    printf '%s' "fail"
    return 0
  fi

  local s
  for s in "${suite_tokens[@]}"; do
    case "$s" in
      rbs-e2e|rbc-e2e|tools-e2e) ;;
      *)
        printf '%s' "skip"
        return 0
        ;;
    esac
  done

  printf '%s' "fail"
}

# Run pytest e2e: $1 = suite markers (nameref), $2 = testcase tokens (nameref), $3 = empty_policy (skip|fail).
# Nameref: caller array names must not collide with locals _suites / _patterns below.
# empty_policy=fail: pytest exit 5 is a failure; skip: treat as success.
run_e2e_pytest() {
  local -n _suites=$1
  local -n _patterns=$2
  local empty_policy=${3:-skip}
  local marker_suites=()
  local k_tokens=()
  local legacy_rbs=0

  if [[ ${#_suites[@]} -eq 0 ]]; then
    marker_suites=("${E2E_DEFAULT_SUITES[@]}")
  else
    marker_suites=("${_suites[@]}")
    if e2e_suites_include_rbs "${_suites[@]}"; then
      legacy_rbs=1
    fi
  fi

  validate_e2e_suites "${marker_suites[@]}"

  if e2e_suites_include_rbs "${marker_suites[@]}" && ! e2e_suite_has_test_files rbs; then
    echo "${CALLER:-tests}: rbs e2e requires tests/e2e/rbs/test_*.py" >&2
    return 1
  fi

  if ! e2e_markers_have_any_test_files "${marker_suites[@]}"; then
    echo "=== E2e / interface tests (pytest) ==="
    if [[ "$empty_policy" == "fail" ]]; then
      echo "${CALLER:-tests}: no e2e test files under tests/e2e/ for marker(s): ${marker_suites[*]}" >&2
      return 1
    fi
    echo "=== No e2e test files for selected suite(s) (skipped) ==="
    return 0
  fi

  ensure_pytest_deps

  if [[ ${#_patterns[@]} -gt 0 ]]; then
    prepare_e2e_k_tokens k_tokens "$legacy_rbs" "${_patterns[@]}" || return 1
  fi

  echo "=== E2e / interface tests (pytest) ==="

  local marker_expr k_expr
  marker_expr="$(build_or_expr "${marker_suites[@]}")"
  local pytest_args=(-c "$SCRIPT_DIR/pytest.ini" "$SCRIPT_DIR/e2e" -m "$marker_expr")

  if [[ ${#k_tokens[@]} -gt 0 ]]; then
    k_expr="$(build_or_expr "${k_tokens[@]}")"
    pytest_args+=(-k "$k_expr")
  fi

  set +e
  "$PYTHON_BIN" -m pytest "${pytest_args[@]}"
  local rc=$?
  set -e

  if [[ $rc -eq 0 ]]; then
    echo "=== All e2e tests passed ==="
    return 0
  fi
  if [[ $rc -eq 5 && "$empty_policy" == "fail" ]]; then
    echo "${CALLER:-run_e2e}: no pytest tests matched the requested suite/pattern filter" >&2
    return 1
  fi
  if [[ $rc -eq 5 ]]; then
    echo "=== No e2e tests collected (skipped) ==="
    return 0
  fi
  return "$rc"
}
