# Global Trust Authority Resource Broker Service (RBS)

## Project Overview

RBS (Resource Broker Service) distributes keys, certificates, and other resources in a highly secure manner by verifying remote attestation results from a Global Trust Authority.

## Tech Stack

- **Language**: Rust 2021 edition
- **Web Framework**: actix-web 4.x
- **Database**: sea-orm (SQLite, PostgreSQL, MySQL support)
- **API Documentation**: OpenAPI 3.0 / Swagger, utoipa
- **Logging**: log + log4rs with rotation and gzip compression
- **TLS**: OpenSSL
- **Serialization**: serde, serde_json, serde_yaml

## Workspace Structure

```
globaltrustauthority-rbs/
├── rbs/                    # Main RBS workspace member
│   ├── api-types/         # Shared API types and OpenAPI schema
│   ├── core/              # Core business logic, attestation, resource management
│   ├── rest/              # REST HTTP server (actix-web)
│   └── tests/             # Core integration tests
├── rbc/                   # Resource Broker Client CLI
├── tools/
│   └── rbs-admin-client/  # Admin client tool
├── scripts/               # Build and documentation scripts
├── docs/                  # Generated API documentation
│   └── api/rbs/          # Markdown and HTML API docs
└── service/               # Service deployment configurations
```

## Key Modules

### rbs/core
- `AttestationManager` - Handles remote attestation
- `ResourceManager` - Manages resource requests
- Provider pattern: `AttestationProvider`, `ResourceProvider`, `UserProvider`
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

RBS supports two invocation styles:

| Style | Description |
|-------|-------------|
| **RESTful** | RBS runs as an independent HTTP service, clients connect via REST API |
| **built-in** | Library mode: link `rbs-core` as a dependency into the host application, direct function calls in the same process, no HTTP |

Deployment modes:

| Mode | Description |
|------|-------------|
| **Background** | RBS runs in the background as a separate process |
| **Passport** | RBS is embedded in the application, built-in style |

```bash
# Build core library (for built-in mode, as library dependency)
cargo build -p rbs-core

# Build with REST HTTP service (for RESTful mode)
cargo build -p rbs --features rest

# Full build (all crates)
cargo build --workspace

# Release build
cargo build --release --workspace

# Build RPM packages
./scripts/build-rpm.sh
```

### Testing

```bash
# Run all tests
cargo test --workspace

# Run tests for specific crate
cargo test -p rbs-core
cargo test -p rbs-rest

# Run with output
cargo test -- --nocapture
```

**Requirement**: All tests must pass before merging.

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

- Challenge endpoint: `/rbs/v0/challenge` (GET)
- Attestation: `/rbs/v0/attest` (POST)
- Resource operations: `/rbs/v0/resource/...`

## Code Conventions

### Module Visibility

- `rbs/rest/src/lib.rs` and `rbs/rest/src/server/mod.rs` expose public modules for testing:
  ```rust
  pub mod routes;
  pub mod server;
  ```

- Route modules are public for integration tests:
  ```rust
  pub mod auth;
  pub mod error;
  pub mod resource;
  pub mod version;
  ```

### Naming

- Route handler functions: `snake_case` (e.g., `get_challenge`, `attest_resource`)
- Schema types: `PascalCase` (e.g., `ChallengeResponse`, `AttestRequest`)
- Configuration structs: `PascalCase` ending in `Config` (e.g., `LoggingConfig`, `RestConfig`)

### Logging

- Use the `log` crate facade
- Log levels: `error!`, `warn!`, `info!`, `debug!`, `trace!`
- Always flush the logger after critical operations: `log::logger().flush()`

### OpenAPI Schema

- Use `#[utoipa::ToSchema]` derive for API types
- Use `#[utoipa::path]` for endpoint documentation
- Example values in schema should be non-empty strings (build-time embedded)

## Common Patterns

### Provider Implementation

```rust
// Provider traits must implement Send + Sync
pub trait AttestationProvider: Send + Sync {
    fn get_challenge(&self, req: &ChallengeRequest) -> Result<ChallengeResponse>;
    fn attest(&self, req: &AttestRequest) -> Result<AttestResponse>;
}
```

### Using Arc<dyn Trait>

```rust
let provider: Arc<dyn AttestationProvider> = Arc::new(MyProvider::new());
let manager = AttestationManager::new(provider);
```

### Testing Private Code

For integration tests accessing private modules, either:
1. Make the module public in the parent lib.rs, OR
2. Use `#[cfg(test)]` with `mod tests { use super::*; }`

## Known Issues and Caveats

### init_logging

The `init_logging` function uses a global logger via `call_once`. In tests:
- Multiple calls to `init_logging` in the same process may not switch log targets
- Tests that rely on re-initializing logging should be run in isolation

### Database Migrations

- Use sea-orm migration framework
- Migrations are defined in `rbs/core/src/infra/db/migrations/`

### Rate Limiting

Rate limiting is feature-gated (`per-ip-rate-limit`). When enabled:
- Configure trusted proxy addresses to extract client IP correctly
- Set `requests_per_sec` and `burst` in `RestConfig`

## License

Mulan PSL v2 - See `LICENSE` and `license/` directory for details.
