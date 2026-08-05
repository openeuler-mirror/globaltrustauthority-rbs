# RBS e2e

Markers: `e2e` + `rbs`. Starts the `rbs` binary and exercises REST endpoints.

## Constraints

- **Ports** — shared HTTP defaults to `47666`, isolated HTTP scenarios request an unused loopback port, and isolated HTTPS defaults to `47667`; set `E2E_PORT_*` per job on shared CI hosts.
- **No pytest-xdist** — run serially unless each worker uses distinct ports.
- **Session-scoped deployments** — RBS, RBC, and tools API tests share long-lived RBS, Fake GTA, and OpenBao processes; the SQLite API tables reset after each test. Tests use unique API identifiers within each test.
- **Isolated startup scenarios** — HTTPS, rate-limit, and startup-order tests retain module-scoped processes on separate ports.
- **Binary** — `target/debug/rbs`; e2e builds embed `GIT_HASH` (`git rev-parse`) and `BUILD_DATE` (UTC) at compile time.

## REST API coverage

> Known contract gap: policy create/update currently validates Base64, UTF-8,
> and size but does not validate Rego syntax. E2E does not codify acceptance of
> invalid Rego while that product decision remains open.

| Directory/module | Endpoints covered |
|---|---|
| `test_version.py` | HTTP and HTTPS `GET /rbs/version` |
| `attestation/` | `GET /rbs/v0/challenge`, `POST /rbs/v0/attest`, and their combined flow |
| `users/` | `GET`, `POST /rbs/v0/users`; `GET`, `PUT`, `DELETE /rbs/v0/users/{username}` |
| `policies/` | `GET`, `POST`, `DELETE /rbs/v0/resource/policy`; `GET`, `PUT`, `DELETE /rbs/v0/resource/policy/{policy_id}` |
| `resources/` | `POST`, `GET`, `PUT`, `DELETE /rbs/v0/{uri}`; Bearer/Attest authorization; allow/deny policies; `GET /info`; `POST /retrieve`; JWE failure and invalid-token paths |
| `system/` | Authentication middleware, wildcard routing, URI length, and per-IP rate limiting |

The version tests verify:

- Temp config, RSA keys, SQLite DB, and a local Fake GTA for attestation-flow tests
- Self-signed TLS cert for HTTPS, explicitly loaded as the test trust anchor and verified

- `service_name == "globaltrustauthority-rbs"`, `api_version == "0"`, non-empty `build.version`
- `build.git_hash` / `build.build_date`: non-empty strings
- `git_hash` must be 40- or 64-char hex (from `git rev-parse` at build time)

## Fake GTA

The shared environment contains a session-scoped local Fake GTA HTTP server. It implements the exact
challenge and attest endpoints consumed by `GtaRestProvider`, records forwarded
requests, signs short-lived PS256 AttestTokens using the temporary key, and can
return one-shot upstream failures for deterministic error-path tests. The key is
paired with RBS's configured verification public key. It is intended for RBS,
RBC, and tools E2E workflows; no real GTA deployment is required for those
flows.

## OpenBao dev mode

The shared environment starts `bao server -dev` (or `openbao server -dev`) on a
random loopback port with an E2E-only root token. Tests pass its URL and token
into RBS's `resource.backends.vault` configuration before RBS starts. This
fixture uses no machine-level OpenBao configuration or data. The startup-order
test creates a separate module-scoped OpenBao instance.

Resource content assertions Base64-decode the compact JWE, require
`RSA-OAEP-256` plus `A256GCM`, decrypt it with the temporary private key, and
compare the plaintext with the exact value stored in OpenBao.

Run:

```bash
./tests/run_e2e.sh --suite rbs
./tests/run_e2e.sh --suite rbs --testcase version
```
