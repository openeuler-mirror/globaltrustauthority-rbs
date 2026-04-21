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
# Generate API documentation: OpenAPI YAML (Cargo), then Markdown and HTML (npm).
#
# In CI (CI=true) the script also verifies that the committed docs/api/rbs/ tree is
# up-to-date and exits non-zero when there is a drift.
#
# On Ubuntu/Debian or openEuler (and common derivatives), if npm is missing, may attempt a
# non-interactive package install (apt or dnf) only when ENABLE_AUTO_INSTALL_DEPS=1.
# Auto-install is always skipped when CI=true or DISABLE_AUTO_INSTALL_DEPS=1.
#
# Environment:
#   SKIP_LICENSE_CHECK=1  Skip npm license-checker before api:md/api:html (faster local runs).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=lib/os-pkg.sh
source "$SCRIPT_DIR/lib/os-pkg.sh"

cd "$REPO_ROOT"

# Minimum Node.js release — must stay in sync with scripts/conf/openapi-docs/package.json "engines.node".
# Optional: repository-root .nvmrc (not tracked) for nvm/fnm local development.
readonly NODE_VERSION_MIN="22.12.0"

usage() {
    cat <<'EOF'
Usage: ./scripts/generate-api-docs.sh [help | -h | --help]

  Regenerates docs/proto/rbs_rest_api.yaml via Cargo, then Markdown/HTML under docs/api/rbs/.
  In a git worktree, compares generated paths to HEAD (committed tree); CI=true fails on drift, otherwise notice.

  SKIP_LICENSE_CHECK=1  Skip license-checker before generating MD/HTML (local iteration).
  ENABLE_AUTO_INSTALL_DEPS=1   Allow sudo-install of missing npm on supported distros (off by default).
  DISABLE_AUTO_INSTALL_DEPS=1  Forbid sudo-install (redundant with default; same as CI for packages).

  Node.js must satisfy package.json engines (see NODE_VERSION_MIN in this script; currently >= 22.12.0).
EOF
}

if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "help" ]]; then
    usage
    exit 0
fi

require_minimum_node_version() {
    local ver low
    if ! command -v node >/dev/null 2>&1; then
        echo "error: node is not on PATH; install Node.js (same major as npm) and ensure both are on PATH." >&2
        exit 1
    fi
    ver="$(node -p "process.versions.node" 2>/dev/null || echo "")"
    if [[ -z "$ver" ]]; then
        echo "error: could not read Node.js version from node." >&2
        exit 1
    fi
    # Lexicographic version sort (-V): lowest of (min, actual) must be min iff actual >= min.
    low="$(printf '%s\n' "$NODE_VERSION_MIN" "$ver" | sort -V | head -n1)"
    if [[ "$low" != "$NODE_VERSION_MIN" ]]; then
        echo "error: Node.js >= ${NODE_VERSION_MIN} required for OpenAPI doc tooling (found ${ver}; see scripts/conf/openapi-docs/package.json engines)." >&2
        echo "Install a newer Node (nvm/fnm with optional repo-root .nvmrc, NodeSource, or distro packages), then re-run." >&2
        exit 1
    fi
}

ensure_npm() {
    if command -v npm >/dev/null 2>&1; then
        require_minimum_node_version
        return 0
    fi

    if build_deps_auto_install_disabled; then
        echo "error: npm is required; install Node.js/npm, or set ENABLE_AUTO_INSTALL_DEPS=1 to allow a distro install on supported OSes." >&2
        exit 1
    fi

    local family
    family="$(detect_pkg_family)"
    echo "notice: npm not found; attempting install (pkg_family=${family}) ..." >&2

    case "$family" in
        apt)
            if ! command -v apt-get >/dev/null 2>&1; then
                echo "error: apt-get not found; install nodejs and npm manually." >&2
                exit 1
            fi
            run_privileged apt-get update -qq
            run_privileged env DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs npm
            ;;
        dnf)
            if command -v dnf >/dev/null 2>&1; then
                run_privileged dnf install -y nodejs npm
            elif command -v yum >/dev/null 2>&1; then
                run_privileged yum install -y nodejs npm
            else
                echo "error: neither dnf nor yum found; install nodejs and npm manually." >&2
                exit 1
            fi
            ;;
        *)
            echo "error: unsupported distro for automatic npm install (pkg_family=${family})." >&2
            echo "Install Node.js and npm, or use nvm, then re-run this script." >&2
            exit 1
            ;;
    esac

    if ! command -v npm >/dev/null 2>&1; then
        echo "error: npm is still not on PATH after package install." >&2
        exit 1
    fi
    require_minimum_node_version
}

is_git_work_tree() {
    git rev-parse --is-inside-work-tree >/dev/null 2>&1
}

# True (exit 0) when the path matches HEAD (committed tree), or when not in a git work tree (drift checks skipped).
# Uses `git diff HEAD` so staged-but-uncommitted changes are not mistaken for a clean tree; plain
# `git diff` (index vs worktree only) would miss that case.
git_worktree_clean_for_path() {
    local path="$1"
    if ! is_git_work_tree; then
        echo "notice: not a git worktree; skipping drift check for ${path}." >&2
        return 0
    fi
    git diff --quiet HEAD -- "$path"
}

npm_ci_or_exit() {
    local dir="$1"
    if ! npm ci --prefix "$dir"; then
        echo "error: npm ci failed under ${dir}." >&2
        echo "hint: run from repository root; ensure package-lock.json matches package.json (regenerate lock if needed)." >&2
        exit 1
    fi
}

run_api_docs() {
    local dir="$1"
    if [[ "${SKIP_LICENSE_CHECK:-}" == "1" ]]; then
        npm --prefix "$dir" run api:docs:gen
    else
        npm --prefix "$dir" run api:docs
    fi
}

# Fail fast if Node tooling is missing before a long Cargo build.
ensure_npm

cargo build -p rbs --features rest

# OpenAPI YAML is emitted by rbs/build.rs; ensure the checked-in file matches the build.
if ! git_worktree_clean_for_path docs/proto/rbs_rest_api.yaml; then
    if [[ "${CI:-}" == "true" ]]; then
        echo "error: docs/proto/rbs_rest_api.yaml differs from build output; rebuild and commit." >&2
        exit 1
    else
        echo "notice: docs/proto/rbs_rest_api.yaml updated; commit it before regenerating companion docs." >&2
    fi
fi

# --- OpenAPI → Markdown / HTML (Node; see scripts/conf/openapi-docs/package.json) ---
# Input:  docs/proto/rbs_rest_api.yaml (from cargo build above via rbs/build.rs).
# Output: docs/api/rbs/md/rbs_rest_api.md   — Widdershins (api:md), OpenAPI → Markdown, --omitHeader.
#         docs/api/rbs/html/rbs_rest_api.html — Redocly build-docs (api:html).
# api:docs runs license:check, then api:docs:gen (api:md + api:html). SKIP_LICENSE_CHECK=1 runs api:docs:gen only.
mkdir -p docs/api/rbs/md docs/api/rbs/html

OPENAPI_DOCS_NPM_DIR="$REPO_ROOT/scripts/conf/openapi-docs"
if [[ "${CI:-}" == "true" ]] || [[ ! -d "$OPENAPI_DOCS_NPM_DIR/node_modules" ]]; then
    npm_ci_or_exit "$OPENAPI_DOCS_NPM_DIR"
fi

run_api_docs "$OPENAPI_DOCS_NPM_DIR"

# Drift detection: warn locally; fail in CI so stale docs are caught before merge.
if ! git_worktree_clean_for_path docs/api/rbs/; then
    if [[ "${CI:-}" == "true" ]]; then
        echo "error: docs/api/rbs/ differs from committed files; regenerate and commit the updated docs." >&2
        exit 1
    else
        echo "notice: docs/api/rbs/ updated; review and commit the changes." >&2
    fi
fi
