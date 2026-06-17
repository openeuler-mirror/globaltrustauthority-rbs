# Global Trust Authority Resource Broker Service (RBS)

## Project Overview

RBS (Resource Broker Service) brokers keys, certificates, and other resources after configured checks: remote attestation (when enabled), attestation-token validation, policy authorization, and JWE-encrypted responses.

Architecture: [`docs/design/architecture.md`](docs/design/architecture.md).

## Tech Stack

- **Language**: Rust 2021 edition
- **Web Framework**: actix-web 4.x
- **Database**: sea-orm (SQLite, PostgreSQL, MySQL support)
- **API Documentation**: OpenAPI 3.0 / Swagger, utoipa
- **Logging**: `log` facade + custom logger in `rbs/core/src/infra/logging/` (optional rotation/gzip via `flate2`)
- **TLS**: OpenSSL
- **Serialization**: serde, serde_json, serde_yaml

## Workspace Structure

```
globaltrustauthority-rbs/
├── rbs/                    # Main RBS workspace member
│   ├── api-types/         # Shared API types and OpenAPI schema
│   ├── core/              # Core business logic, attestation, resource management
│   │   └── tests/         # Core integration tests
│   ├── rest/              # REST HTTP server (actix-web)
│   └── rdb_sql/           # SQL schema (SQLite, MySQL)
├── rbc/                   # Resource Broker Client CLI
├── tools/                 # rbs-cli (unified CLI: admin, client, config, token, version)
│   └── rbs-admin-client/  # Admin client library
├── scripts/               # Build and documentation scripts
├── docs/
│   ├── design/            # Architecture and design docs
│   └── api/rbs/           # Generated API docs (Markdown, HTML)
├── tests/                 # Workspace e2e / merge-readiness scripts
└── service/               # Service deployment configurations
```

## Key Modules

### rbs/core
- `AttestationManager` - Handles remote attestation (challenge and evidence exchange)
- `ResourceService` - Resource retrieval, authorization, and JWE encryption
- `PolicyService` - Policy CRUD and admin API operations
- `AdminManager` - User administration and bootstrap
- Provider pattern: `AttestationProvider`, `ResourceBackend` trait + `BackendProvider` registry, `PolicyClient` (policy adapter)
- Auth integration: `UserKeyProvider` (implemented by `AdminManager` for bearer JWT verification)
- All provider traits must implement `Send + Sync`
- Uses `async_trait` for async trait objects

### rbs/rest
- REST API server built on actix-web
- Routes defined in `rbs/rest/src/routes/`
- Rate limiting support (feature-gated: `per-ip-rate-limit`)
- HTTPS/TLS support via OpenSSL

### rbs/api-types
- Shared type definitions
- OpenAPI schema generation via `#[derive(utoipa::ToSchema)]`
- Configuration structures (`RestConfig`, `LoggingConfig`, etc.)

## Development Workflow

### Building

RBS supports two invocation and deployment shapes (see `docs/design/architecture.md` §4):

| Style | Deployment shape | Description |
|-------|------------------|-------------|
| **RESTful** | **Standalone process** | RBS runs as an independent HTTP/HTTPS service (`rbs` binary); clients connect via REST API |
| **built-in** | **Embedded / library** | Host application links `rbs-core` directly; in-process calls, no `rbs-rest` HTTP layer |

**Passport Model** and **Background-Check Model** are [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334) attestation interaction flows documented in `docs/design/architecture.md` §5 — not deployment modes.

Embedded/library mode is not production-ready with the default `BuiltinAttestationProvider` (currently returns `NotImplemented`); supply a real `AttestationProvider` implementation.

```bash
# Build core library (for built-in mode, as library dependency)
cargo build -p rbs-core

# Build REST binary (rest is the default feature)
cargo build -p rbs

# Library-only binary (no HTTP server)
cargo build -p rbs --no-default-features --features lib

# Full build (all crates)
cargo build --workspace

# Release build
cargo build --release --workspace

# Build RPM packages
./scripts/build-rpm.sh
```

See also: [`docs/build/build_and_install.md`](docs/build/build_and_install.md), [`docs/build/rpm.md`](docs/build/rpm.md).

### Testing

```bash
# Merge-readiness gate (Cargo + OpenAPI check + e2e)
./tests/test_all.sh

# Fast Rust-only
cargo test --workspace

# Run tests for specific crate
cargo test -p rbs-core
cargo test -p rbs-rest

# Run with output
cargo test -- --nocapture
```

See [`tests/README.md`](tests/README.md) for e2e layout and skip flags.

**Requirement**: All tests must pass before merging (`./tests/test_all.sh`).

### API Documentation

When adding or modifying API endpoints or parameters:

1. Modify route handlers in `rbs/rest/src/routes/`
2. Update OpenAPI schema annotations (`#[utoipa::path]`, `#[derive(ToSchema)]`)
3. Run the documentation generator:
   ```bash
   ./scripts/generate-api-docs.sh
   ```
4. The script generates:
   - `docs/proto/rbs_rest_api.yaml` (OpenAPI YAML)
   - `docs/api/rbs/md/rbs_rest_api.md` (Markdown)
   - `docs/api/rbs/html/rbs_rest_api.html` (HTML)
5. Commit all updated documentation

In CI (`CI=true`), the script will fail if documentation is out of sync.

### API Path Convention

- Challenge: `GET /rbs/v0/challenge`
- Attestation: `POST /rbs/v0/attest`
- Resource content (wildcard): `/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}` — GET/PUT/POST/DELETE for CRUD; `GET .../info` for metadata; `POST .../retrieve` for inline-evidence JWE retrieval
- Policy admin (Bearer only): `/rbs/v0/resource/policy` (+ `/{policy_id}`); batch delete: `DELETE /rbs/v0/resource/policy?ids=...`
- Admin users (Bearer only): `/rbs/v0/users` (+ `/{username}`)
- Version (no auth): `GET /rbs/version`

Full endpoint list: [`docs/proto/rbs_rest_api.yaml`](docs/proto/rbs_rest_api.yaml) or generated HTML/Markdown under `docs/api/rbs/`.

## Security Invariants

See [`docs/design/architecture.md` §10](docs/design/architecture.md#10-security-architecture) for the full threat model. Operational summary:

- **Challenge nonce** — delegated to GTA; no local single-use nonce store in `rbs-core`.
- **Default deny** — missing policy, invalid token, `AdminOnly` role mismatch, or backend errors reject access (owner Bearer GET does not require `role`).
- **JWE boundary** — resource plaintext is JWE-encrypted before leaving RBS; `export_mode: plain` is rejected.
- **Public middleware paths** — `/rbs/v0/challenge`, `/rbs/v0/attest`, `/rbs/version`, `POST .../retrieve` (handler-level inline attest; unauthenticated GTA fan-out — DoS/abuse surface; see architecture §10 rate limiting).
- **Attest token replay** — reusable within `exp`; no `jti` tracking.
- **Bearer vs Attest** — Bearer for admin/user/policy APIs and owner GET/GET info (`admin_policy.rego`); Attest for resource-bound Rego + TEE claims on GET/retrieve.

## Code Conventions

### Module Visibility

- `rbs/rest/src/lib.rs` exposes `routes`, `server`, and `middleware` for integration tests
- `rbs/rest/src/server/mod.rs` exposes `http` and (when enabled) `rate_limit` only
- Route modules: `admin`, `attestation`, `error`, `policy`, `resource`, `version` — auth lives in `middleware/auth.rs`, not `routes/`

### Naming

- Route handler functions: `snake_case` (e.g., `get_challenge`, `attest`, `retrieve_resource`) — HTTP layer in `rbs/rest/src/routes/`
- Core/API attestation: `get_auth_challenge` on `AttestationManager` / `AttestationProvider` (e.g. route handler `get_challenge` in `routes/attestation.rs` delegates to it)
- Schema types: `PascalCase` (e.g., `AuthChallengeResponse`, `AttestRequest`)
- Configuration structs: `PascalCase` ending in `Config` (e.g., `LoggingConfig`, `RestConfig`)

### Logging

- Use the `log` crate facade
- Log levels: `error!`, `warn!`, `info!`, `debug!`, `trace!`
- Call `log::logger().flush()` only in tests or shutdown paths — not on per-request hot paths

### OpenAPI Schema

- Use `#[utoipa::ToSchema]` derive for API types
- Use `#[utoipa::path]` for endpoint documentation
- Example values in schema should be non-empty strings (build-time embedded)

## Common Patterns

### Provider Implementation

```rust
use async_trait::async_trait;
use std::sync::Arc;
use rbs_api_types::{AttestRequest, AttestResponse, AuthChallengeResponse};
use rbs_core::attestation::{AttestationManager, AttestationProvider};

#[async_trait]
impl AttestationProvider for MyProvider {
    async fn get_auth_challenge(&self, as_provider: Option<&str>) -> Result<AuthChallengeResponse> {
        // ...
    }
    async fn attest(&self, req: AttestRequest) -> Result<AttestResponse> {
        // ...
    }
}

let mut manager = AttestationManager::new();
manager.register("gta", Arc::new(MyProvider::new()));
manager.set_default("gta");
```

### Testing Private Code

Prefer public APIs and `#[cfg(test)]` modules in-crate. Widen visibility only when the crate already exposes modules for integration tests (as `rbs-rest` does for `routes`).

## Known Issues and Caveats

### init_logging

`init_logging` uses `Once` (`call_once`) for `log::set_logger`; repeated calls update inner logger state (level, file target) but do not re-register the global logger. In tests:
- Multiple calls may not fully reset log output if the global logger is already set
- Tests that rely on re-initializing logging should be run in isolation

### Database Migrations

- SQL schema lives in `rbs/rdb_sql/` (e.g. `sqlite_rbs.sql`, `mysql_rbs.sql`)
- Applied at startup via `infra/rdb/connection.rs::migrate_core_tables()` — not sea-orm `Migrator`

### Rate Limiting

Compile-time feature `per-ip-rate-limit` on `rbs-rest` plus runtime `rest.rate_limit.enabled`. When enabled, configure:
- `rest.rate_limit.requests_per_sec`
- `rest.rate_limit.burst`
- `rest.trusted_proxy.addrs` (client IP behind proxies)

## License

Mulan PSL v2 - See `LICENSE` and `license/` directory for details.
