# RBS e2e

Markers: `e2e` + `rbs`. Starts the `rbs` binary and exercises REST endpoints.

## Constraints

- **Fixed ports** — defaults `47666` (HTTP) and `47667` (HTTPS) in `helpers/env.py`; set `E2E_PORT_*` per job on shared CI hosts.
- **No pytest-xdist** — run serially unless each worker uses distinct ports.
- **Function-scoped server** — `rbs_server` fixture in `conftest.py` starts/stops RBS per test.
- **Binary** — `target/debug/rbs`; e2e builds embed `GIT_HASH` (`git rev-parse`) and `BUILD_DATE` (UTC) at compile time.

## Version API (`test_version.py`)

HTTP and HTTPS `GET /rbs/version`:

- Temp config, RSA keys, SQLite DB, minimal attestation backend stub (GTA on discard port 9; version path does not call attestation)
- Self-signed TLS cert for HTTPS (`verify=False`)

Assertions (in `test_version.py`):

- `service_name == "globaltrustauthority-rbs"`, `api_version == "0"`, non-empty `build.version`
- `build.git_hash` / `build.build_date`: non-empty strings
- `git_hash` must be 40- or 64-char hex (from `git rev-parse` at build time)

Run:

```bash
./tests/run_e2e.sh --suite rbs
./tests/run_e2e.sh --suite rbs --testcase version
```
