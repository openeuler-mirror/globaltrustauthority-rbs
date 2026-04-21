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
# End-to-end test: start RBS with custom config, call /rbs/version via curl (HTTP and HTTPS), assert response, then clean up.
# Run from workspace root: ./tests/run_e2e.sh or ./tests/rbs/e2e_version_curl.sh
# Requires: curl, jq, openssl, cargo (with rest feature). Cleans up temp dir and server process on exit.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Workspace root (tests/rbs -> tests -> workspace root)
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
E2E_PORT_HTTP="${E2E_PORT_HTTP:-47666}"
E2E_PORT_HTTPS="${E2E_PORT_HTTPS:-47667}"
MAX_WAIT=15
# Set to 1 when RBS is started via setsid so SERVER_PID is the process-group leader (safe for kill -- -PGID).
RBS_STARTED_WITH_SETSID=0

# Stop RBS started for this script. With setsid, kill the whole process group; otherwise signal
# direct children (pkill -P) then the main PID. Never use kill -- -PID without setsid (PGID may
# not equal the child PID and the signal could target the wrong group).
rbs_server_stop() {
    if [[ -z "${SERVER_PID:-}" ]]; then
        return 0
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        SERVER_PID=""
        RBS_STARTED_WITH_SETSID=0
        return 0
    fi
    if [[ "${RBS_STARTED_WITH_SETSID:-0}" -eq 1 ]]; then
        kill -TERM -- "-${SERVER_PID}" 2>/dev/null || kill -TERM "$SERVER_PID" 2>/dev/null || true
    else
        if command -v pkill >/dev/null 2>&1; then
            pkill -TERM -P "$SERVER_PID" 2>/dev/null || true
        fi
        kill -TERM "$SERVER_PID" 2>/dev/null || true
    fi
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
    RBS_STARTED_WITH_SETSID=0
}

# Cleanup: remove temp dir and kill server (if any). Runs on EXIT (success or failure).
cleanup() {
    local status=$?
    rbs_server_stop
    if [[ -n "${E2E_SCRATCH_DIR:-}" ]] && [[ -d "$E2E_SCRATCH_DIR" ]]; then
        rm -rf "$E2E_SCRATCH_DIR"
    fi
    if [[ $status -ne 0 ]]; then
        echo "e2e_version_curl: FAILED (exit $status)"
        exit $status
    fi
}
trap cleanup EXIT

# Prerequisites
command -v curl    >/dev/null || { echo "e2e_version_curl: curl is required"; exit 1; }
command -v jq      >/dev/null || { echo "e2e_version_curl: jq is required"; exit 1; }
command -v openssl >/dev/null || { echo "e2e_version_curl: openssl is required for HTTPS test"; exit 1; }

# Wait for server at BASE_URL (http or https) and return 0 when /rbs/version returns 200.
wait_for_version() {
    local base_url="$1"
    local insecure="${2:-}"
    local curl_extra=()
    [[ "$insecure" == "insecure" ]] && curl_extra=(-k)
    for i in $(seq 1 "$MAX_WAIT"); do
        if curl -sS -o /dev/null -w "%{http_code}" "${curl_extra[@]}" "$base_url/rbs/version" 2>/dev/null | grep -q 200; then
            return 0
        fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "e2e_version_curl: server process exited unexpectedly"
            return 1
        fi
        sleep 1
    done
    return 1
}

# Fetch /rbs/version and assert JSON shape. service_name is a fixed identity and checked exactly;
# api_version is checked as a non-empty string to avoid updating the script on every release.
assert_version_response() {
    local base_url="$1"
    shift
    local curl_args=("$@")
    local resp
    resp="$(curl -sS "${curl_args[@]}" "$base_url/rbs/version")"
    echo "$resp" | jq -e '.service_name == "globaltrustauthority-rbs"' >/dev/null || { echo "e2e_version_curl: unexpected service_name"; echo "$resp" | jq .; return 1; }
    echo "$resp" | jq -e '.api_version | type == "string" and length > 0' >/dev/null || { echo "e2e_version_curl: api_version missing or empty"; echo "$resp" | jq .; return 1; }
    echo "$resp" | jq -e '.build.version | type == "string" and length > 0' >/dev/null || { echo "e2e_version_curl: build.version missing or empty"; echo "$resp" | jq .; return 1; }
    echo "$resp" | jq -e '.build.git_hash | type == "string" and length > 0' >/dev/null || { echo "e2e_version_curl: build.git_hash missing or empty"; echo "$resp" | jq .; return 1; }
    echo "$resp" | jq -e '.build.build_date | type == "string" and length > 0' >/dev/null || { echo "e2e_version_curl: build.build_date missing or empty"; echo "$resp" | jq .; return 1; }
}

# Unique temp dir for this run (config, log, TLS cert/key)
E2E_SCRATCH_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rbs_e2e_version_XXXXXX")"
CONFIG_PATH="$E2E_SCRATCH_DIR/rbs.yaml"
LOG_PATH="$E2E_SCRATCH_DIR/rbs.log"
CERT_PATH="$E2E_SCRATCH_DIR/server.pem"
KEY_PATH="$E2E_SCRATCH_DIR/server.key"

cd "$REPO_ROOT"
echo "e2e_version_curl: building rbs (rest feature)..."
cargo build -p rbs --bin rbs --features rest --quiet
RBS_BIN="$REPO_ROOT/target/debug/rbs"

# ---- HTTP ----
LISTEN_HTTP="127.0.0.1:${E2E_PORT_HTTP}"
BASE_HTTP="http://${LISTEN_HTTP}"
cat > "$CONFIG_PATH" << EOF
rest:
  listen_addr: "${LISTEN_HTTP}"
  https:
    enabled: false
    cert_file: ""
    key_file: ""
logging:
  level: info
  format: text
  file_path: "${LOG_PATH}"
EOF

echo "e2e_version_curl: starting RBS (HTTP) on $LISTEN_HTTP ..."
RBS_STARTED_WITH_SETSID=0
if command -v setsid >/dev/null 2>&1; then
    setsid "$RBS_BIN" --config "$CONFIG_PATH" </dev/null &
    RBS_STARTED_WITH_SETSID=1
else
    "$RBS_BIN" --config "$CONFIG_PATH" </dev/null &
fi
SERVER_PID=$!

if ! wait_for_version "$BASE_HTTP"; then
    echo "e2e_version_curl: HTTP server did not respond with 200 within ${MAX_WAIT}s"
    exit 1
fi
assert_version_response "$BASE_HTTP"
echo "e2e_version_curl: HTTP version response OK"

rbs_server_stop

# ---- HTTPS (self-signed cert) ----
echo "e2e_version_curl: generating self-signed cert for HTTPS test..."
openssl req -x509 -newkey rsa:2048 -keyout "$KEY_PATH" -out "$CERT_PATH" -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1

LISTEN_HTTPS="127.0.0.1:${E2E_PORT_HTTPS}"
BASE_HTTPS="https://${LISTEN_HTTPS}"
LOG_PATH_HTTPS="$E2E_SCRATCH_DIR/rbs_https.log"
cat > "$CONFIG_PATH" << EOF
rest:
  listen_addr: "${LISTEN_HTTPS}"
  https:
    enabled: true
    cert_file: "${CERT_PATH}"
    key_file: "${KEY_PATH}"
logging:
  level: info
  format: text
  file_path: "${LOG_PATH_HTTPS}"
EOF

echo "e2e_version_curl: starting RBS (HTTPS) on $LISTEN_HTTPS ..."
RBS_STARTED_WITH_SETSID=0
if command -v setsid >/dev/null 2>&1; then
    setsid "$RBS_BIN" --config "$CONFIG_PATH" </dev/null &
    RBS_STARTED_WITH_SETSID=1
else
    "$RBS_BIN" --config "$CONFIG_PATH" </dev/null &
fi
SERVER_PID=$!

if ! wait_for_version "$BASE_HTTPS" "insecure"; then
    echo "e2e_version_curl: HTTPS server did not respond with 200 within ${MAX_WAIT}s"
    exit 1
fi
assert_version_response "$BASE_HTTPS" -k
echo "e2e_version_curl: HTTPS version response OK"

echo "e2e_version_curl: PASSED (HTTP + HTTPS)"
