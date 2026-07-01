# E2e / interface tests

Workspace **merge gate** and **black-box e2e** tests. Rust unit/integration tests live in each crate (`cargo test`); this tree holds pytest e2e and shell orchestration.

## Directory layout

```
tests/
├── test_all.sh         # Merge gate: cargo test + OpenAPI drift + e2e
├── run_e2e.sh          # E2e only (pytest wrapper)
├── common.sh           # Shared shell helpers (python/pytest resolution)
├── requirements.txt    # Python e2e dependencies
├── pytest.ini          # Pytest config (rootdir = tests/)
├── conftest.py         # Session fixtures: repo_root
├── helpers/            # Python helpers (env, RBS lifecycle, build)
├── e2e/                # Pytest e2e suites
│   ├── rbs/            # RBS server (REST, process-level); see e2e/rbs/README.md
│   ├── rbc/            # RBC client placeholder (.gitkeep; add test_*.py)
│   └── tools/          # Workspace tools placeholder (.gitkeep; add test_*.py)
└── README.md
```

| Suite | Marker | Description |
|-------|--------|-------------|
| `e2e/rbs/` | `e2e` + `rbs` | Start `rbs` binary, call REST endpoints — [`e2e/rbs/README.md`](e2e/rbs/README.md) |
| `e2e/rbc/` | `e2e` + `rbc` | RBC CLI / SDK black-box tests |
| `e2e/tools/` | `e2e` + `tools` | `rbs-cli`, admin client, etc. |

## Test framework

Workspace tests use **two layers**:

| Layer | Runner | Location | Scope |
|-------|--------|----------|-------|
| **Rust unit / integration** | `cargo test` | Each crate (`rbs/core/tests/`, `rbs/rest/tests/`, …) | In-process; modules, handlers, types |
| **Black-box e2e** | **pytest** + `httpx` | `tests/e2e/<suite>/` | Real binaries/processes; HTTP or CLI |

`test_all.sh` runs both when enabled (default). This tree owns the **pytest e2e** layer and shell wrappers only.

### Pytest stack

| Piece | Role |
|-------|------|
| `pytest.ini` | `rootdir = tests/`; discovers `e2e/**/test_*.py`; registers markers (`e2e`, `rbs`, `rbc`, `tools`) |
| `conftest.py` | Session `repo_root` — workspace root for all suites |
| `e2e/<suite>/conftest.py` | Suite fixtures (e.g. RBS `rbs_binary`, `rbs_server`) |
| `helpers/` | Cross-suite Python helpers (`env`, `rbs_build`, `rbs_server`) — lifecycle/build, not assertions |
| `common.sh` | Shell: Python/pytest resolution, suite validation, `run_e2e_pytest` |
| `test_all.sh` / `run_e2e.sh` | Entry scripts; map `--suite` / `--testcase` to `pytest -m` / `-k` |

**Dependencies** (`requirements.txt`): `pytest`, `httpx` (HTTP client), `PyYAML` (RBS temp config).

**Conventions**

- Every e2e module: `pytestmark = [pytest.mark.e2e, pytest.mark.<suite>]`.
- Assertions live in the `test_*.py` that exercises the endpoint (not in `helpers/`).
- Process teardown via fixture `yield` (see `e2e/rbs/conftest.py`).
- RBS e2e: fixed ports (`helpers/env.py`), serial run (no `pytest-xdist` unless each worker sets distinct `E2E_PORT_*`).

### Fixtures (RBS suite)

| Fixture | Scope | Purpose |
|---------|-------|---------|
| `repo_root` | session | Workspace root (`tests/conftest.py`) |
| `rbs_binary` | session | Build `target/debug/rbs` once; skip if `openssl`/`cargo`/git missing |
| `rbs_scratch_dir` | function | Per-test temp dir |
| `rbs_server` | function | Start/stop one RBS process; isolated config per test |

Details and constraints: [`e2e/rbs/README.md`](e2e/rbs/README.md).

### Test cases (e2e)

| Suite | File | Test | What it checks |
|-------|------|------|----------------|
| `rbs` | `e2e/rbs/test_version.py` | `test_version_http` | `GET /rbs/version` over HTTP — JSON contract, embedded `git_hash` / `build_date` |
| `rbs` | `e2e/rbs/test_version.py` | `test_version_https` | Same over HTTPS (self-signed cert, `verify=False`) |

`rbc` and `tools` suites have markers and placeholders; add `test_*.py` under `e2e/rbc/` or `e2e/tools/` when ready.

## Prerequisites

```bash
python3 -m pip install -r tests/requirements.txt
```

Also on `PATH` for RBS e2e: `openssl`, `cargo` (with `rest` feature). When running **direct pytest** (not via shell wrappers), missing `openssl` or `cargo` skips the rbs suite instead of erroring all tests.

Python packages (`tests/requirements.txt`): `pytest`, `httpx`, `PyYAML`.

Optional env: `PYTHON_BIN` (override Python), `E2E_PORT_HTTP` / `E2E_PORT_HTTPS` / `E2E_WAIT_SECS` (integers; invalid values fail at import with a clear message), `E2E_SUITES` / `E2E_PATTERN` (see `run_e2e.sh`).

## Merge gate (`test_all.sh`)

Runs from repo root in order when enabled:

| Stage | When | Notes |
|-------|------|-------|
| Cargo test | `ENABLE_CARGO_TESTS=1` (default) | Full workspace, or `-p` packages for selected `--suite` |
| OpenAPI drift | Full run, or `--suite rbs` (not `rbs-e2e`) | Compares `docs/proto/rbs_rest_api.yaml` to build output |
| pytest e2e | `ENABLE_E2E_TESTS=1` (default) | See suite tokens and empty policy below |

### `test_all.sh` suite tokens

| `--suite` | Cargo packages | e2e marker |
|-----------|----------------|------------|
| `rbs` | rbs, rbs-core, rbs-rest, rbs-api-types | `rbs` |
| `rbc` | rbc | `rbc` |
| `tools` | rbs-cli, rbs-admin-client | `tools` |
| `rbs-e2e` | *(none)* | `rbs` |
| `rbc-e2e` | *(none)* | `rbc` |
| `tools-e2e` | *(none)* | `tools` |

`run_e2e.sh` accepts only the e2e markers (`rbs`, `rbc`, `tools`), not the `*-e2e` cargo variants.

### E2e empty policy (`empty_policy`)

When pytest collects zero tests (exit code 5):

| Selection | Policy |
|-----------|--------|
| Full merge gate (no `--suite`) | `skip` for empty `rbc`/`tools`; **fails** if `tests/e2e/rbs/test_*.py` is missing |
| Component suite (`rbs`) | `fail` — requires `tests/e2e/rbs/test_*.py` |
| Component suite (`rbc`, `tools`, …) | `skip` when no `test_*.py` (no pip install needed) |
| `*-e2e` suite only | `fail` |
| Any `--testcase` with `--suite` | `fail` |
| `run_e2e.sh` with explicit `--suite` / `--pattern` / env | `fail` |

### `--testcase` / `--pattern` API

Project-level **test-name substring tokens**, not raw pytest `-k` expressions.

- Allowed characters per token: `A–Z`, `a–z`, `0–9`, `_`, `-`, `:`
- Comma separates OR tokens (shell expands to pytest `-k "a or b"` internally)
- Rejects spaces, parentheses, and reserved words `and`, `or`, `not` (use **Direct pytest** for full `-k` expressions)
- Requires at least one `--suite` on `test_all.sh`
- Legacy alias `e2e_version_curl` → `version` only when **`rbs` is explicitly selected** (`--suite rbs` or `rbs-e2e`)

For full pytest expression power, use **Direct pytest** below (`-k` is **not** supported by `test_all.sh` or `run_e2e.sh`).

## Run

**Full merge gate** (from repo root):

```bash
./tests/test_all.sh
```

Skip flags:

```bash
ENABLE_E2E_TESTS=0 ./tests/test_all.sh      # Cargo + OpenAPI only
ENABLE_CARGO_TESTS=0 ./tests/test_all.sh    # E2e only
./tests/test_all.sh --no-cargo
./tests/test_all.sh --no-e2e
./tests/test_all.sh --suite rbs               # RBS cargo packages + rbs e2e
./tests/test_all.sh --suite tools             # Cargo + e2e skip when tests/e2e/tools/test_*.py absent (no pip needed)
./tests/test_all.sh --suite rbs-e2e --testcase version
./tests/test_all.sh --suite rbs --testcase e2e_version_curl   # legacy alias (rbs suite only) → version
```

**E2e only:**

```bash
./tests/run_e2e.sh
./tests/run_e2e.sh --suite rbs
./tests/run_e2e.sh --suite rbs --pattern version
./tests/run_e2e.sh --suite rbs --testcase version   # same as --pattern
E2E_SUITES=rbs,tools E2E_PATTERN=version ./tests/run_e2e.sh
```

**Direct pytest:**

```bash
python3 -m pytest -c tests/pytest.ini tests/e2e -m rbs -v
python3 -m pytest -c tests/pytest.ini tests/e2e -m "rbs or tools" -k version
```

## Adding e2e tests

1. Add `test_*.py` under `tests/e2e/<suite>/`.
2. Tag with `pytest.mark.e2e` and the suite marker (`rbs`, `rbc`, or `tools`).
3. Put shared setup in `tests/e2e/<suite>/conftest.py`; cross-suite helpers in `tests/helpers/`. Keep endpoint assertions in the test module that exercises that API.
4. Tear down processes and temp files in fixtures (`yield`), not bare `atexit`.
5. Suite-specific notes (tests covered, assertions, constraints): add or extend `tests/e2e/<suite>/README.md`.
