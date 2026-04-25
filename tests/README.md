# E2e / interface tests

E2e and interface tests for the workspace: **RBS** server, **RBC** client, and **tools**. All run from a single entry script.

## Directory layout

```
tests/
├── test_all.sh         # Run all: Cargo tests + OpenAPI YAML check + e2e (from workspace root)
├── run_e2e.sh          # Run e2e only (from workspace root)
├── README.md           # This file
├── rbs/                # RBS server e2e (REST API, curl, etc.)
│   └── e2e_version_curl.sh
├── rbc/                # RBC client tests (add scripts here)
│   └── .gitkeep
└── tools/              # Tools tests (e.g. rbs-admin-client; add scripts here)
    └── .gitkeep
```

- **rbs/** — Tests for the RBS binary (server): start with custom config, call endpoints (e.g. `/rbs/version`), assert response, clean up.
- **rbc/** — Tests for the RBC client; add `.sh` scripts as needed.
- **tools/** — Tests for workspace tools; add `.sh` scripts as needed.

The entry script runs every executable `.sh` under `rbs/`, then `rbc/`, then `tools/`, in alphabetical order. Any script failure exits with non-zero.

## How to run

**Run all tests** (Cargo unit/integration + OpenAPI YAML check + e2e) from workspace root:

```bash
./tests/test_all.sh
```

`test_all.sh` supports selectively skipping parts of the test suite via environment variables or CLI flags:

- Run **only** Cargo tests:

```bash
ENABLE_E2E_TESTS=0 ./tests/test_all.sh
```

- Run **only** e2e tests:

```bash
ENABLE_CARGO_TESTS=0 ./tests/test_all.sh
```

- Equivalent CLI flags (CLI takes precedence over env):

```bash
./tests/test_all.sh --no-cargo    # Skip Cargo tests
./tests/test_all.sh --no-e2e      # Skip e2e tests
./tests/test_all.sh -h            # Show help
```

**E2e only** from workspace root:

```bash
./tests/run_e2e.sh
```

`run_e2e.sh` filters which scripts to run by suite and optional filename pattern:

- Run only a single suite (`rbs` / `rbc` / `tools`):

```bash
./tests/run_e2e.sh --suite rbs
./tests/run_e2e.sh --suite rbc
./tests/run_e2e.sh --suite tools
```

- Filter by filename substring (for example, only scripts containing `version`):

```bash
./tests/run_e2e.sh --suite rbs --pattern version
```

- Or control via environment variables:

```bash
E2E_SUITES="rbs,tools" E2E_PATTERN="version" ./tests/run_e2e.sh
```

To run a single script directly, invoke the file itself, for example:

```bash
./tests/rbs/e2e_version_curl.sh
```

## Adding tests

1. Add a new `.sh` script under the right suite (`rbs/`, `rbc/`, or `tools/`).
2. Make it executable (`chmod +x ...`).
3. Scripts should use the workspace root for `cargo` (e.g. `REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"` for scripts under `tests/rbs/`).
4. Clean up any temp files, processes, or env changes on exit (e.g. `trap`).

---

## RBS suite: version API e2e

`rbs/e2e_version_curl.sh` starts the RBS server with a custom config (temp dir), calls `/rbs/version` over **HTTP** and **HTTPS**, and asserts the JSON response. Cleanup: server process and temp dir (config, logs, cert, key) removed on exit.

**Requirements:** `curl`, `jq`, `openssl`, `cargo` (with `rest` feature).

Optional env: `E2E_PORT_HTTP` (default `47666`), `E2E_PORT_HTTPS` (default `47667`).

**What is tested:** HTTP with `rest.https.enabled: false`; HTTPS with a self-signed cert generated in the temp dir, `curl -k` to `https://.../rbs/version`. Both assert 200 and JSON shape (`service_name`, `api_version`, `build`).
