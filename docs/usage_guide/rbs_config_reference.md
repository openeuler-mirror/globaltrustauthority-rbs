# RBS Configuration Reference (rbs.yaml)

This is the configuration reference for the [RBS Usage Manual](rbs_usage_manual.md); it lists every
`rbs.yaml` key with its default, required-ness, and value constraints. If you just want the service
running, copy the minimal config from chapter 4 of the usage manual.

The full annotated example lives at [`rbs/conf/rbs.yaml`](../../rbs/conf/rbs.yaml). The top level
accepts exactly these keys — any other key is rejected at startup:

`rest` · `logging` · `storage` · `attestation` · `auth` · `admin` · `policy` · `resource`.

The whole configuration is validated at startup and the service **fails fast** on anything invalid.
Column meanings:

- **Default**: only a real, concrete default is shown; `—` means there is no usable default — empty
  strings, optional fields, and required fields are all marked `—`.
- **Required**: `required` = must provide a non-empty value; `optional` = can be omitted (or uses a
  default); `conditional` = depends on other settings, see the "Meaning / range" column.

## Table of contents

- [1. `rest` — HTTP server](#1-rest--http-server)
- [2. `logging`](#2-logging)
- [3. `storage` — database](#3-storage--database)
- [4. `auth` — token verification](#4-auth--token-verification)
- [5. `admin` — bootstrap administrator](#5-admin--bootstrap-administrator)
- [6. `policy` — resource-policy limits](#6-policy--resource-policy-limits)
- [7. `attestation` — attestation backends](#7-attestation--attestation-backends)
- [8. `resource` — resource backends](#8-resource--resource-backends)
- [9. Supported JWT algorithms](#9-supported-jwt-algorithms)

---

## 1. `rest` — HTTP server

| Key | Default | Required | Meaning / range |
|---|---|---|---|
| `rest.listen_addr` | `127.0.0.1:6666` | optional | Address to bind, in `host:port` form, non-empty and ≤ 128 chars. Use `0.0.0.0:<port>` to expose beyond localhost. |
| `rest.workers` | `4` | optional | Number of actix worker threads, `1..=256`. |
| `rest.body_limit_bytes` | `10485760` | optional | Max request body size (10 MiB), `1024..=104857600` (100 MiB); 413 when exceeded. |
| `rest.listen_backlog` | `128` | optional | TCP accept queue size, ≤ 65535. |
| `rest.request_timeout_secs` | `60` | optional | Max time to read a request and write a response, `1..=3600`. Note: **`0` is rejected at startup**, not "no limit". |
| `rest.shutdown_timeout_secs` | `30` | optional | Graceful-shutdown wait for in-flight requests, `1..=300`. |
| `rest.https.enabled` | `true` | optional | Enable TLS. If `true`, `cert_file`/`key_file` must be non-empty valid PEM files, or the service refuses to start. |
| `rest.https.cert_file` | — | conditional | Server certificate PEM path; required non-empty when `https.enabled: true`. |
| `rest.https.key_file` | — | conditional | Server private-key PEM path; required non-empty when `https.enabled: true`. |
| `rest.rate_limit.enabled` | `false` | optional | Per-IP rate limiting. The rate-limit code is compiled in by default; setting this to `true` enables it. |
| `rest.rate_limit.requests_per_sec` | `60` | optional | Token-bucket refill rate per client IP, `1..=1000000`. |
| `rest.rate_limit.burst` | — | optional | Bucket capacity, `1..=1000000`; defaults to `requests_per_sec`. |
| `rest.trusted_proxy.addrs` | `[]` | optional | Peer IPs treated as trusted reverse proxies; client IP is then taken from `Forwarded`/`X-Forwarded-For`. |

## 2. `logging`

| Key | Default | Required | Meaning / range |
|---|---|---|---|
| `logging.level` | `info` | optional | `trace` \| `debug` \| `info` \| `warn` \| `error` \| `off`. |
| `logging.format` | `text` | optional | `text` or `json`. |
| `logging.file_path` | — | optional | Log file path. Omit it → stderr only; the shipped sample and the RPM-installed config set `/var/log/rbs/rbs.log`. |
| `logging.enable_rotation` | `false` | optional | Enable log rotation. |
| `logging.rotation.max_file_size_bytes` | `10485760` | optional | Size at which a file rolls, `1024..=104857600` (100 MiB). |
| `logging.rotation.max_files` | `6` | optional | Number of retained files, `1..=100`. |
| `logging.rotation.compression` | `none` | optional | `none` or `gzip`. |
| `logging.rotation.file_mode` | `440` | optional | Permission of rotated files (octal). |
| `logging.file_mode` | `640` | optional | Permission of the active file (octal). |

## 3. `storage` — database

| Key | Default | Required | Meaning / range |
|---|---|---|---|
| `storage.db_type` | `mysql` | optional | `sqlite`, `memory`, `mysql`, or `postgres`. The code default is `mysql`; the minimal config uses `sqlite`, and `memory` is test-only. |
| `storage.max_connections` | `20` | optional | Connection-pool size, `1..=10000`. |
| `storage.timeout` | `30` | optional | Seconds, ≤ 300. |
| `storage.url` | — | conditional | DSN; required for `mysql`/`postgres`. SQLite example: `sqlite:///var/lib/rbs/rbs.db?mode=rwc` (`mode=rwc`: the file is auto-created on first connect if it does not exist; the parent directory must exist); MySQL: `mysql://user:pass@host:3306/rbs`. |
| `storage.sql_file_path` | — | conditional | Path to the SQL schema applied at startup (e.g. `/usr/share/rbs/sqlite_rbs.sql`); required for every type except `memory`. |

## 4. `auth` — token verification

| Key | Default | Required | Meaning / range |
|---|---|---|---|
| `auth.attest_token.public_key_path` | — | conditional | PEM public key used to verify Attest tokens; mutually exclusive with `jwks_file`. |
| `auth.attest_token.jwks_file` | — | conditional | JWKS file used to verify Attest tokens; mutually exclusive with `public_key_path`. |
| `auth.attest_token.issuer` | — | required | Required `iss` claim on Attest tokens (sample: `"Global Trust Authority"`). |
| `auth.attest_token.audience` | — | optional | Optional `aud` claim on Attest tokens. |
| `auth.bearer_token.issuer` | — | required | Required `iss` on admin/client bearer JWTs; must match the issuer (sample/CLI default `rbs-cli`). |
| `auth.bearer_token.audience` | — | required | Required `aud` on bearer JWTs; token validation fails unless the token's `aud` equals this value (sample/CLI default `globaltrustauthority-rbs`). |

- Exactly one of `attest_token.public_key_path` / `attest_token.jwks_file` must be set, and the file
  must exist and be valid — the verifier loads it eagerly at startup.
- `attest_token.issuer`, `bearer_token.issuer`, and `bearer_token.audience` must all be non-empty
  or startup fails.

## 5. `admin` — bootstrap administrator

| Key | Default | Required | Meaning |
|---|---|---|---|
| `admin.max_users` | `10` | optional | Max regular (non-admin) users (`1..=100`). |
| `admin.admin_key.public_key_path` | — | conditional | PEM public key of the built-in administrator; mutually exclusive with `jwks_file`. |
| `admin.admin_key.jwks_file` | — | conditional | JWK file for the built-in administrator; mutually exclusive with `public_key_path`. |

- `admin.admin_key` must configure exactly one of `public_key_path` / `jwks_file` (validated on
  every start). On the first start with an empty user table, RBS bootstraps a built-in user named
  `Administrator` (role `admin`) from this key.
- Bearer tokens are verified per-user by looking up the `sub` claim's public key. The bootstrapped
  `Administrator` is identified by `sub = "Administrator"`.

## 6. `policy` — resource-policy limits

| Key | Default | Required | Meaning |
|---|---|---|---|
| `policy.max_per_user` | `10` | optional | Max resource policies per user (`1..=100`). |

## 7. `attestation` — attestation backends

`attestation` is required: `backends` must have at least one entry and `default_as_provider` must
name a key present in `backends`, or startup fails.

| Key | Default | Required | Meaning / range |
|---|---|---|---|
| `attestation.default_as_provider` | `gta` | optional | Backend used when no `as_provider` is given; must exist in `backends`. |
| `attestation.backends.<name>.mode` | `rest` | optional | `rest` (GTA REST) or `builtin`. |
| `.rest.base_url` | — | conditional | GTA base URL; required non-empty for `mode: rest`. |
| `.rest.timeout_secs` | `30` | optional | Request timeout, ≤ 3600. |
| `.rest.retries` | `3` | optional | Retry count for **runtime attestation calls** (`GET /challenge`, `POST /attest`), ≤ 100: GTA 5xx responses and transport errors (incl. timeouts) are retried with a fixed 5 s interval. Management proxy calls (`/rbs/v0/attestation/...` ref_value/cert/policy CRUD) are **never retried** — writes are not idempotent; failures surface to the caller for manual verification. |
| `.rest.tls_verify` | `true` | optional | Verify GTA's server certificate (one-way TLS, the default; `false` disables verification — test only). |
| `.rest.ca_file` | — | optional | Custom CA bundle for one-way TLS verification; empty = system default. |
| `.rest.client_cert_path` | — | conditional | mTLS client certificate PEM; required together with `client_key_path` when using mTLS (one-way TLS needs neither). |
| `.rest.client_key_path` | — | conditional | mTLS client private key PEM (PKCS#8); required together with `client_cert_path` when using mTLS. |
| `.rest.credentials.user_id` | — | required | User ID sent to GTA; ≤ 36 chars, alphanumeric plus `-`/`_`. |
| `.rest.credentials.api_key_auth` | `false` | optional | Add API-Key auth headers (`main_api_key`/`sub_api_key`). |
| `.rest.credentials.main_api_key` | — | conditional | Required when `api_key_auth: true`: `m.` + 32 alphanumeric (34 chars). |
| `.rest.credentials.sub_api_key` | — | conditional | Required when `api_key_auth: true`: `s.` + 32 alphanumeric (34 chars). |

## 8. `resource` — resource backends

`resource` is optional. When present it holds `resource.max_per_user` (`1..=100`, default `10`) and
`resource.backends`; if the `resource:` section is present, `backends` must be non-empty. The
`admin`, `attestation`, `resource`, and `health` names are reserved for the resource URI's
`res_provider` segment (rejected at request time), so avoid using them as backend keys.

Each backend selects its type with `type`: `vault`, `hsm`, or `ca`.

### 8.1 Vault / OpenBao (`type: vault`)

| Key | Default | Required | Meaning |
|---|---|---|---|
| `url` | — | required | Vault base URL, must start with `http://` or `https://`, ≤ 2048 chars. |
| `token` | — | required | Vault access token (sensitive, redacted in logs). |
| `mount_path` | — | required | Secrets-engine mount path, non-empty and ≤ 128 chars. |
| `kv_version` | `v2` | optional | `v1` or `v2`. |
| `verify_ssl` | `true` | optional | Verify the server TLS certificate against the **system trust store**. No per-backend `ca_file` option: for a private-CA OpenBao, import the CA into the system trust store (`verify_ssl: false` disables verification — test environments only). |
| `timeout` | `30` | optional | Request timeout in seconds, `1..=3600`. |
| `max_connections` | `100` | optional | Connection count, `1..=10000`. |
| `max_retries` | `2` | optional | Retry count, ≤ 100. |
| `max_response_body_bytes` | `1048576` | optional | Max accepted response body (1 MiB), `1024..=10485760`. |
| `allowed_resource_types` | — | required | Resource-type whitelist (e.g. `["secret", "cert"]`), must be non-empty. |

### 8.2 HSM / PKCS#11 (`type: hsm`)

| Key | Default | Required | Meaning |
|---|---|---|---|
| `module_path` | — | required | PKCS#11 module `.so` path, non-empty. |
| `slot.label` | — | required | Slot label of the target token, non-empty. |
| `credentials.pin_env` | — | required | Name of the env var holding the PIN, non-empty. |
| `allowed_resource_types` | — | required | Resource-type whitelist, non-empty. |
| `max_key_bytes` | `1048576` | optional | Max key-material size in bytes, must be > 0. |
| `timeout` | `30` | optional | Per-call timeout in seconds, `1..=3600`. |

### 8.3 CA / CMPv2 (`type: ca`)

| Key | Default | Required | Meaning |
|---|---|---|---|
| `url` | — | required | CMP endpoint, must start with `http://` or `https://`. |
| `https.verify` | `true` | optional | Verify the peer TLS certificate. |
| `https.ca_file` | — | optional | Custom CA bundle; empty = system default. |
| `message_protection_cert_file` | — | required | CMP PKI Protection signing certificate, non-empty. |
| `message_protection_key_file` | — | required | CMP PKI Protection signing private key, non-empty. |
| `response_protection_trust_anchors_file` | — | required | Trust anchors for verifying CMP responses, non-empty. |
| `cert_profile` | — | optional | Certificate profile name; empty = omit. |
| `allowed_resource_types` | — | required | Resource-type whitelist, non-empty. |
| `max_response_bytes` | `1048576` | optional | Max response body in bytes, must be > 0. |
| `timeout` | `30` | optional | HTTP POST timeout in seconds, `1..=3600`. |
| `idempotency.max_entries` | `1000` | optional | Idempotency LRU cache capacity, must be > 0. |
| `idempotency.ttl_seconds` | `300` | optional | Idempotency TTL in seconds, must be > 0. |

## 9. Supported JWT algorithms

For both bearer and attest tokens: `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`, `EdDSA`, `SM2`.

Any other `alg` value is rejected with `unsupported algorithm` before signature verification — in particular `RS256`/`RS384`/`RS512` and all HMAC variants (`HS256`/`HS384`/`HS512`) are not accepted.

Verification is dispatched per algorithm family:

| Algorithms | Verification path |
|---|---|
| `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `EdDSA` | `jsonwebtoken` crate |
| `ES512` | Dedicated `josekit` path |
| `SM2` | Vendored OpenSSL — SM2 ECDSA over the SM3 digest (GM/T 0003); the GM/T 0009 default user ID `1234567812345678` is pinned because OpenSSL ≥ 3.5 no longer applies it implicitly |
