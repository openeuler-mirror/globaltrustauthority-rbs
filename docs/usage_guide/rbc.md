# RBC (Resource Broker Client) Usage Guide

## Table of Contents

1. [Overview](#1-overview)
2. [Features](#2-features)
3. [Architecture](#3-architecture)
4. [Getting Started](#4-getting-started)
5. [Configuration Reference](#5-configuration-reference)
6. [Core Interfaces](#6-core-interfaces)
7. [Usage Guide](#7-usage-guide)
8. [Development Guide](#8-development-guide)

---

## 1. Overview

RBC (Resource Broker Client) is the client-side library for the Global Trust Authority (GTA) Resource Broker Service (RBS). It enables TEE (Trusted Execution Environment) workloads to securely retrieve protected resources — such as secrets, certificates, and configuration data — from an RBS server by completing an attestation flow.

RBC handles the full attestation lifecycle: collecting hardware evidence, exchanging evidence for an attestation token, fetching the protected resource, and decrypting the JWE-encrypted content using an ephemeral TEE key pair. Applications can use RBC as a Rust library or link against the generated C shared/static library. A command-line interface (`rbc-cli`) is also provided for retrieving resources directly from a shell without writing application code.

---

## 2. Features

- **Dual language interface**: Native Rust API and a C FFI with a cbindgen-generated header (`rbc.h`), usable from C, C++, Go, Python, and other languages via FFI.
- **Pluggable evidence provider**: currently supports `native` mode (collects TEE evidence locally via `attestation_client`). The `EvidenceProvider` trait is available as an extension point for custom implementations.
- **Two token provider modes**: `rbs` (attests with RBS to obtain a token) or `native` (reads a pre-existing token from a local agent).
- **Two resource retrieval modes**: by attestation token (`ByAttestToken`) or direct pull-by-evidence (`ByEvidence`).
- **Two key management modes**: RBC auto-generates an ephemeral TEE key pair per session, or the caller supplies its own `tee_pubkey` (caller-managed mode).
- **JWE end-to-end encryption**: resource content is encrypted by RBS using the TEE public key. Supported algorithms: RSA-OAEP-256 (4096-bit) and ECDH-ES+A256KW (P-256/P-384/P-521), content encryption A256GCM.
- **Sensitive data zeroization**: resource content and private keys are zeroed in memory on drop via the `zeroize` crate.

---

## 3. Architecture

```
rbc/
├── src/
│   ├── bin/main.rs              # CLI entry point (rbc-cli)
│   ├── sdk.rs                   # Core public API: Config, ConfigBuilder, Client, Session, Resource
│   ├── client/                  # RBS REST client (reqwest-based HTTP)
│   ├── evidence/                # EvidenceProvider trait and implementations
│   ├── token/                   # TokenProvider trait and implementations
│   ├── tools/                   # TEE ephemeral key pair (RSA/EC) + JWE encrypt/decrypt        
│   ├── ffi/                     # C FFI layer (functions exported to rbc.h)
│   ├── error.rs                 # RbcError unified error type
│   └── lib.rs                   # Crate root and public re-exports
├── include/
│   └── rbc.h                    # Auto-generated C header (do not edit manually)
├── examples/                    # Complete C usage example           
├── tests/                      
├── conf/
│   └── rbc.yaml                 # Default configuration template
├── build.rs                     # Triggers cbindgen to regenerate rbc.h on every build
└── cbindgen.toml                # cbindgen configuration (PascalCase naming convention)
```

---

## 4. Getting Started

### 4.1 Prerequisites

| Requirement | Version | Notes                                                                                                                                                      |
|-------------|---------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Rust toolchain | ≥ 1.75 | Install via [rustup](https://rustup.rs)                                                                                                                    |
| libclang | any | Required by cbindgen at build time                                                                                                                         |
| openssl-devel | ≥ 3.0.x | Required by reqwest TLS backend; must be a version with all known CVEs patched, prefer a ≥ 3.0 LTS release actively maintained by your OS vendor.          |
| attestation_agent | — | Required at runtime for the `native` evidence and token provider, refer to [global-trust-authority](https://gitcode.com/openeuler/global-trust-authority). |

### 4.2 Build

```bash
# Debug build — produces librbc.so, librbc.a, rbc binary, and regenerates rbc/include/rbc.h
cargo build -p rbc

# Release build
cargo build -p rbc --release

# Run all tests
cargo test -p rbc
```

Build outputs (under `target/debug/` or `target/release/`):

| File                | Description |
|---------------------|-------------|
| `librbc.so`         | Shared library for C FFI |
| `librbc.a`          | Static library for C FFI |
| `rbc-cli`           | Command-line interface for resource retrieval |
| `rbc/include/rbc.h` | Auto-regenerated C header |

### 4.3 Run the C Demo

After building, compile and run the bundled C demo:

```bash
# Compile
cc -I rbc/include rbc/examples/c/demo.c \
   -L target/debug -lrbc -lpthread -ldl -lm \
   -o /tmp/rbc_demo

# Run (edit rbc/conf/rbc.yaml to point at a real RBS server first)
LD_LIBRARY_PATH=target/debug /tmp/rbc_demo rbc/conf/rbc.yaml <resource_uri>
```

See [Section 7.4](#74-c--full-attestation-flow) for a line-by-line walkthrough of the demo.

---

## 5. Configuration Reference

### 5.1 Config File Loading

RBC is configured with a YAML file. There are two ways to load it:

**From file:**
```rust
let client = Client::from_config("/etc/rbc/rbc.yaml")?;
```

**Via `ConfigBuilder` (programmatic):**
```rust
use rbc::{Client, Config, ProviderRawConfig, ProviderType};

let config = Config::builder()
    .base_url("https://rbs.example.com")
    .ca_cert("/etc/ssl/ca.pem")        // optional
    .timeout_secs(30)                   // optional
    .evidence_provider(vec![ProviderRawConfig {
        provider_type: ProviderType::Native,
        enabled: true,
        rest: {
            let mut m = serde_json::Map::new();
            m.insert("config_path".to_string(),
                     serde_json::json!("/etc/gta/agent_config.yaml"));
            m
        },
    }])
    .token_provider(vec![ProviderRawConfig {
        provider_type: ProviderType::Rbs,
        enabled: true,
        rest: Default::default(),
    }])
    .build()?;
let client = Client::new(config)?;
```

### 5.2 Top-level Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `rbs` | block | **required** | RBS connection parameters (see below) |
| `key_algorithm` | `rsa` \| `ec` | `rsa` | Algorithm for the ephemeral TEE key pair |
| `evidence_provider` | list | — | Evidence provider entries; first enabled entry is used (see §5.3) |
| `token_provider` | list | — | Token provider entries; first enabled entry is used (see §5.4) |

**`rbs` block fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `base_url` | string | **required** | Base URL of the RBS server |
| `ca_cert` | string | — | Path to a custom CA certificate (PEM) for TLS verification |
| `timeout_secs` | integer | — | Timeout in seconds for evidence collection, token acquisition, and RBS HTTP requests |

### 5.3 `evidence_provider` List

Each entry in the list describes one provider. RBC uses the **first entry with `enabled: true`**; remaining entries are ignored.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | `native` | **required** | Provider implementation. Only `native` is currently supported. |
| `enabled` | bool | `true` | Set to `false` to skip this entry |
| `config_path` | string | `/etc/attestation_agent/agent_config.yaml` | Path to the attestation agent config file |

### 5.4 `token_provider` List

Each entry in the list describes one provider. RBC uses the **first entry with `enabled: true`**; remaining entries are ignored. Listing multiple entries makes it easy to switch between providers by toggling `enabled` without removing configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | `rbs` \| `native` | **required** | `rbs`: obtains a token by attesting with RBS; `native`: reads a token from a local agent |
| `enabled` | bool | `true` | Set to `false` to skip this entry |
| `config_path` | string | — | *(native mode only)* Path to the local agent config file |

### 5.5 Complete `rbc.yaml` Example

```yaml
# RBS connection parameters
rbs:
  base_url: "https://rbs.example.com"
  # Optional: custom CA certificate for TLS (PEM format)
  ca_cert: /etc/ssl/certs/rbs-ca.pem
  # Optional: request timeout in seconds
  timeout_secs: 30

# Optional: TEE key pair algorithm used to wrap the resource content key
# Accepted values: rsa (default) | ec
# key_algorithm: ec

# Evidence providers: first entry with enabled: true is used
evidence_provider:
  - type: native
    enabled: true
    config_path: /etc/gta/agent_config.yaml

# Token providers: first entry with enabled: true is used
# Toggle enabled flags to switch between providers without removing configuration
token_provider:
  - type: rbs
    enabled: true

  - type: native
    enabled: false
    config_path: /etc/gta/agent_config.yaml
```

---

## 6. Core Interfaces

### 6.1 Rust API

The full Rust API reference is auto-generated from source by `scripts/gen-sdk-docs.py`:

- [`docs/api/rbc/sdk.md`](../api/rbc/sdk.md)

It covers all `pub struct` and `pub enum` types in `rbc/src/sdk.rs`, including their fields, enum variants, and inherent `pub fn` methods, with `///` doc comments preserved from source.

---

### 6.2 C FFI API

The C API is declared in `rbc/include/rbc.h` and targets C99+. Link against `librbc.so` (dynamic) or `librbc.a` (static).

#### 6.2.1 Opaque Handle Types

```c
typedef struct RbcClient   RbcClient;
typedef struct RbcSession  RbcSession;
typedef struct RbcResource RbcResource;
```

Handles are opaque pointers. Never dereference or stack-allocate them; only pass pointers between RBC functions.

#### 6.2.2 Memory Ownership Rules

| Return type | Ownership | How to release |
|-------------|-----------|----------------|
| `char **` out-param | Caller owns | `RbcStringFree(ptr)` |
| `uint8_t **` out-param | Caller owns | `RbcBufferFree(ptr, len)` — `len` must be the value written by the call |
| `const char *` from resource accessor | Borrowed | Do **not** free; valid until `RbcResourceFree` |
| `const uint8_t *` from `RbcResourceGetContent` | Borrowed | Do **not** free; valid until `RbcResourceFree` |

> **Thread safety**: All handles must be used only on the thread that created them. The error slot used by `RbcLastErrorMessage` is thread-local.

#### 6.2.3 Error Handling

Every fallible function returns `RbcErrorCode`. On failure, a detailed message is available via `RbcLastErrorMessage()` on the same thread.

```c
RbcErrorCode rc = RbcClientNewFromFile(path, &client);
if (rc != RBC_ERROR_CODE_OK) {
    fprintf(stderr, "error %d: %s\n", (int)rc, RbcLastErrorMessage());
    exit(1);
}
```

| Code | Integer | Description |
|------|---------|-------------|
| `RBC_ERROR_CODE_OK` | 0 | Success |
| `RBC_ERROR_CODE_INVALID_ARG` | 1 | Null or invalid argument |
| `RBC_ERROR_CODE_CONFIG` | 2 | Config parse or validation error |
| `RBC_ERROR_CODE_TLS` | 3 | TLS certificate error |
| `RBC_ERROR_CODE_PROVIDER` | 4 | Provider not configured or init failed |
| `RBC_ERROR_CODE_KEYGEN` | 5 | Key pair generation error |
| `RBC_ERROR_CODE_EVIDENCE` | 6 | Evidence collection error |
| `RBC_ERROR_CODE_NETWORK` | 7 | Network or connection error |
| `RBC_ERROR_CODE_TIMEOUT` | 8 | Request timed out |
| `RBC_ERROR_CODE_AUTH` | 9 | Token invalid or expired (401/403) |
| `RBC_ERROR_CODE_POLICY_DENIED` | 10 | Request denied by attestation policy |
| `RBC_ERROR_CODE_RESOURCE_NOT_FOUND` | 11 | Resource URI not found (404) |
| `RBC_ERROR_CODE_ATTEST` | 12 | Attestation flow failure |
| `RBC_ERROR_CODE_SERVER` | 13 | RBS server internal error (5xx) |
| `RBC_ERROR_CODE_ENCRYPT` | 14 | JWE encryption error |
| `RBC_ERROR_CODE_DECRYPT` | 15 | JWE decryption error |
| `RBC_ERROR_CODE_JSON` | 16 | JSON serialization error |
| `RBC_ERROR_CODE_INTERNAL` | 17 | Internal RBC error |

```c
// Retrieve the last error message (thread-local; valid until the next RBC call).
const char *RbcLastErrorMessage(void);

// Clear the last error on the current thread.
void RbcLastErrorClear(void);
```

#### 6.2.4 Function Reference

For the complete function list and signatures, refer to [`rbc/include/rbc.h`](../../rbc/include/rbc.h). The header is auto-generated on every build and is always in sync with the implementation.

---

## 7. Usage Guide

### 7.1 Rust — Full Attestation Flow

Standard flow: load config → create client → get challenge → create session → collect evidence → attest → fetch resource → decrypt.

```rust
use rbc::{Client, GetResourceRequest};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load config and create client
    let client = Client::from_config("/etc/rbc/rbc.yaml")?;

    // Step 1: obtain a nonce from RBS
    let challenge = client.get_auth_challenge()?;

    // Step 2: create a session (auto-generates an ephemeral TEE key pair)
    let session = client.new_session(None)?;

    // Step 3: collect local TEE evidence bound to the nonce
    let evidence = session.collect_evidence(&challenge)?;

    // Step 4: attest — exchange evidence for a token
    let attest_resp = session.attest(Some(&evidence))?;

    // Step 5: fetch the protected resource
    let resource = session.get_resource(
        "my/secret/key",
        GetResourceRequest::ByAttestToken(&attest_resp.token),
    )?;

    // Step 6: decrypt the JWE-encrypted content (None = use ephemeral key)
    let plaintext = session.decrypt_content(
        std::str::from_utf8(&resource.content)?,
        None,
    )?;

    println!("resource: {}  ({} bytes)", resource.uri, plaintext.len());
    Ok(())
}
```

### 7.2 Rust — Pull by Evidence (No Token)

In pull-by-evidence mode, the evidence bundle is submitted directly to RBS. RBS performs attestation internally and returns the resource in a single call, skipping the separate `attest` step.

```rust
use rbc::{Client, GetResourceRequest};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client   = Client::from_config("/etc/rbc/rbc.yaml")?;
    let challenge = client.get_auth_challenge()?;
    let session   = client.new_session(None)?;
    let evidence  = session.collect_evidence(&challenge)?;

    let resource = session.get_resource(
        "my/secret/key",
        GetResourceRequest::ByEvidence { value: &evidence },
    )?;

    let plaintext = session.decrypt_content(
        std::str::from_utf8(&resource.content)?,
        None,
    )?;

    println!("{} bytes", plaintext.len());
    Ok(())
}
```

### 7.3 Rust — Caller-managed Key

Use this mode when the TEE hardware generates its own key pair and the public key must be bound into the evidence quote by the attester.

```rust
use rbc::{Client, GetResourceRequest};
use rbs_api_types::AttesterData;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load the TEE-generated public key (JWK) and matching private key (PEM)
    let public_jwk: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string("/path/to/tee_pubkey.jwk")?
    )?;
    let private_key_pem = std::fs::read_to_string("/path/to/tee_private.pem")?;

    // Inject tee_pubkey into attester_data so it is bound to the evidence quote
    let mut runtime_data = serde_json::Map::new();
    runtime_data.insert("tee_pubkey".to_string(), public_jwk);
    let attester_data = AttesterData { runtime_data: Some(runtime_data) };

    let client    = Client::from_config("/etc/rbc/rbc.yaml")?;
    let challenge = client.get_auth_challenge()?;

    // Session detects tee_pubkey in attester_data → enters caller-managed key mode
    let session  = client.new_session(Some(&attester_data))?;
    let evidence = session.collect_evidence(&challenge)?;
    let token    = session.attest(Some(&evidence))?.token;

    let resource = session.get_resource(
        "my/secret/key",
        GetResourceRequest::ByAttestToken(&token),
    )?;

    // Supply the matching private key for decryption
    let plaintext = session.decrypt_content(
        std::str::from_utf8(&resource.content)?,
        Some(&private_key_pem),
    )?;

    println!("{} bytes", plaintext.len());
    Ok(())
}
```

### 7.4 C — Full Attestation Flow

The following is the complete C demo (`rbc/examples/c/demo.c`) with annotations:

```c
#include <stdio.h>
#include <stdlib.h>
#include "rbc.h"

static void die(const char *where, RbcErrorCode code) {
    fprintf(stderr, "%s failed (code=%d): %s\n",
            where, (int)code, RbcLastErrorMessage());
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <config.yaml> <resource_uri>\n", argv[0]);
        return 2;
    }

    /* 1. Create client from config file */
    RbcClient *client = NULL;
    RbcErrorCode rc = RbcClientNewFromFile(argv[1], &client);
    if (rc != RBC_ERROR_CODE_OK) die("RbcClientNewFromFile", rc);

    /* 2. Fetch authentication challenge (nonce) from RBS */
    char *nonce = NULL;
    rc = RbcGetAuthChallenge(client, &nonce);
    if (rc != RBC_ERROR_CODE_OK) die("RbcGetAuthChallenge", rc);

    /* 3. Begin session — ephemeral TEE key pair is generated automatically */
    RbcSession *session = NULL;
    rc = RbcSessionNew(client, NULL, &session);
    if (rc != RBC_ERROR_CODE_OK) die("RbcSessionNew", rc);

    /* 4. Collect local TEE evidence bound to the nonce */
    char *evidence = NULL;
    rc = RbcSessionCollectEvidence(session, nonce, &evidence);
    if (rc != RBC_ERROR_CODE_OK) die("RbcSessionCollectEvidence", rc);

    /* 5. Attest: exchange evidence for an attestation token */
    char *token = NULL;
    rc = RbcSessionAttest(session, evidence, &token);
    if (rc != RBC_ERROR_CODE_OK) die("RbcSessionAttest", rc);

    /* 6. Fetch the protected resource by token */
    RbcResource *res = NULL;
    rc = RbcSessionGetResourceByToken(session, argv[2], token, &res);
    if (rc != RBC_ERROR_CODE_OK) die("RbcSessionGetResourceByToken", rc);

    /* 7. Access resource fields (borrowed — valid until RbcResourceFree) */
    size_t n = 0;
    const uint8_t *content = RbcResourceGetContent(res, &n);
    const char    *ctype   = RbcResourceGetContentType(res);
    printf("uri:          %s\n", RbcResourceGetUri(res));
    printf("content-type: %s\n", ctype ? ctype : "(none)");
    printf("content:      %.*s\n", (int)n, (const char *)content);

    /* 8. Optionally decrypt JWE-encrypted content */
    // uint8_t *pt = NULL; size_t pt_len = 0;
    // rc = RbcSessionDecryptContent(session, (const char *)content,
    //                               NULL, &pt, &pt_len);
    // if (rc != RBC_ERROR_CODE_OK) die("RbcSessionDecryptContent", rc);
    // printf("plaintext: %.*s\n", (int)pt_len, (const char *)pt);
    // RbcBufferFree(pt, pt_len);

    /* 9. Release all handles in reverse order */
    RbcResourceFree(res);
    RbcStringFree(token);
    RbcStringFree(evidence);
    RbcSessionFree(session);   /* ephemeral key is zeroized here */
    RbcStringFree(nonce);
    RbcClientFree(client);
    return 0;
}
```

---

## 8. Development Guide

### 8.1 Custom Evidence Provider

Implement the `EvidenceProvider` trait to collect evidence from a custom TEE platform:

```rust
use async_trait::async_trait;
use rbc::{EvidenceProvider, RbcError};
use rbs_api_types::{AttesterData, AuthChallengeResponse};
use serde_json::Value;

struct MyEvidenceProvider;

#[async_trait]
impl EvidenceProvider for MyEvidenceProvider {
    async fn collect_evidence(
        &self,
        challenge: &AuthChallengeResponse,
        attester_data: Option<&AttesterData>,
    ) -> Result<Value, RbcError> {
        let nonce = &challenge.nonce;
        // Collect hardware evidence bound to `nonce`.
        // If attester_data.runtime_data contains tee_pubkey, include it in the
        // quote so RBS can verify the key binding.
        Ok(serde_json::json!({
            "quote": "<your-tee-quote>",
            "nonce": nonce,
        }))
    }
}
```

> **Note**: The current `Client::new()` instantiates only the built-in `NativeEvidenceProvider`. Custom providers can be injected via the internal `ClientInner` struct in test code, or by extending the provider dispatch in `sdk.rs`.

### 8.2 Custom Token Provider

Implement the `TokenProvider` trait to obtain attestation tokens from a custom attestation service:

```rust
use async_trait::async_trait;
use rbc::{RbcError, TokenProvider};
use rbs_api_types::AttesterData;
use serde_json::Value;

struct MyTokenProvider;

#[async_trait]
impl TokenProvider for MyTokenProvider {
    async fn get_token(
        &self,
        evidence: Option<&Value>,
        _attester_data: Option<&AttesterData>,
    ) -> Result<String, RbcError> {
        let _evidence = evidence.ok_or_else(||
            RbcError::ProviderError("evidence required".into()))?;
        // Submit evidence to your attestation service and return the token.
        Ok("your-attestation-token".to_string())
    }
}
```

### 8.3 Regenerating the C Header

`rbc/include/rbc.h` is auto-generated by [cbindgen](https://github.com/mozilla/cbindgen) via `build.rs`. It is regenerated automatically on every `cargo build -p rbc`. Do not edit it manually.

Naming conventions and header options (include guards, PascalCase function names, etc.) are controlled by `rbc/cbindgen.toml`.

```bash
# Trigger regeneration manually
cargo build -p rbc
# Output: rbc/include/rbc.h
```
