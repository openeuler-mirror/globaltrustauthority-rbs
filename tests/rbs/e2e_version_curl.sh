#!/usr/bin/env bash
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

# Cleanup: remove temp dir and kill server (if any). Runs on EXIT (success or failure).
cleanup() {
    local status=$?
    if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [[ -n "${TMPDIR_E2E:-}" ]] && [[ -d "$TMPDIR_E2E" ]]; then
        rm -rf "$TMPDIR_E2E"
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
TMPDIR_E2E="$(mktemp -d "${TMPDIR:-/tmp}/rbs_e2e_version_XXXXXX")"
CONFIG_PATH="$TMPDIR_E2E/rbs.yaml"
LOG_PATH="$TMPDIR_E2E/rbs.log"
CERT_PATH="$TMPDIR_E2E/server.pem"
KEY_PATH="$TMPDIR_E2E/server.key"

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
"$RBS_BIN" --config "$CONFIG_PATH" &
SERVER_PID=$!

if ! wait_for_version "$BASE_HTTP"; then
    echo "e2e_version_curl: HTTP server did not respond with 200 within ${MAX_WAIT}s"
    exit 1
fi
assert_version_response "$BASE_HTTP"
echo "e2e_version_curl: HTTP version response OK"

kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true
SERVER_PID=""

# ---- HTTPS (self-signed cert) ----
echo "e2e_version_curl: generating self-signed cert for HTTPS test..."
openssl req -x509 -newkey rsa:2048 -keyout "$KEY_PATH" -out "$CERT_PATH" -days 1 -nodes -subj "/CN=localhost" >/dev/null 2>&1

LISTEN_HTTPS="127.0.0.1:${E2E_PORT_HTTPS}"
BASE_HTTPS="https://${LISTEN_HTTPS}"
LOG_PATH_HTTPS="$TMPDIR_E2E/rbs_https.log"
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
"$RBS_BIN" --config "$CONFIG_PATH" &
SERVER_PID=$!

if ! wait_for_version "$BASE_HTTPS" "insecure"; then
    echo "e2e_version_curl: HTTPS server did not respond with 200 within ${MAX_WAIT}s"
    exit 1
fi
assert_version_response "$BASE_HTTPS" -k
echo "e2e_version_curl: HTTPS version response OK"

echo "e2e_version_curl: PASSED (HTTP + HTTPS)"
