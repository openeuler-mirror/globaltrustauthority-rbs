# RBC SDK Reference

> Generated from `rbc/src/sdk.rs`.

---

## `ProviderType`

Selects the evidence or token provider implementation.

**Variants**

- `Native` — Built-in provider running in the same process.
- `Rbs` — Remote provider accessed via the RBS REST API.

---

## `ProviderRawConfig`

Raw provider configuration entry as deserialized from `rbc.yaml`.

**Fields**

| Field | Type | Description |
|-------|------|-------------|
| `provider_type` | `ProviderType` |  |
| `enabled` | `bool` |  |
| `rest` | `serde_json::Map<String, Value>` |  |

---

## `RbsConfig`

RBS connection parameters, mapped from the `rbs:` block in `rbc.yaml`.

**Fields**

| Field | Type | Description |
|-------|------|-------------|
| `base_url` | `String` |  |
| `timeout_secs` | `Option<u64>` |  |
| `ca_cert` | `Option<String>` |  |

---

## `Config`

Full RBC configuration, directly mirrors the structure of `rbc.yaml`.

**Fields**

| Field | Type | Description |
|-------|------|-------------|
| `rbs` | `RbsConfig` |  |
| `evidence_provider` | `Option<Vec<ProviderRawConfig>>` |  |
| `token_provider` | `Option<Vec<ProviderRawConfig>>` |  |
| `key_algorithm` | `KeyType` |  |

**Methods**

#### `from_file`

```rust
pub fn from_file(path: &str) -> Result<Self, RbcError>
```

Load configuration from a YAML file at `path`.

#### `builder`

```rust
pub fn builder() -> ConfigBuilder
```

Return a [`ConfigBuilder`] for constructing a [`Config`] programmatically.

---

## `ConfigBuilder`

Builder for [`Config`]; obtain one via [`Config::builder`].

**Methods**

#### `base_url`

```rust
pub fn base_url(mut self, url: &str) -> Self
```

Set the RBS base URL (required).

#### `ca_cert`

```rust
pub fn ca_cert(mut self, path: &str) -> Self
```

Set the path to a custom CA certificate for TLS verification.

#### `timeout_secs`

```rust
pub fn timeout_secs(mut self, secs: u64) -> Self
```

Set the request timeout in seconds.

#### `evidence_provider`

```rust
pub fn evidence_provider(mut self, ep: Vec<ProviderRawConfig>) -> Self
```

Set the evidence provider configuration list.

#### `token_provider`

```rust
pub fn token_provider(mut self, tp: Vec<ProviderRawConfig>) -> Self
```

Set the token provider configuration list.

#### `key_algorithm`

```rust
pub fn key_algorithm(mut self, alg: KeyType) -> Self
```

Set the key algorithm used for ephemeral TEE key generation.

#### `build`

```rust
pub fn build(self) -> Result<Config, RbcError>
```

Build the [`Config`], returning an error if `base_url` was not set.

---

## `GetResourceRequest`

Specifies the authorization mode when calling [`Session::get_resource`].

**Variants**

- `ByAttestToken(&'a str)` — Authorize with a pre-obtained attest token.
- `ByEvidence { value: &'a Value }` — Authorize by submitting raw evidence for inline attestation.

---

## `Resource`

**Fields**

| Field | Type | Description |
|-------|------|-------------|
| `uri` | `String` |  |
| `content` | `Zeroizing<Vec<u8>>` | Raw content, possibly a JWE ciphertext; zeroed on `Drop`. |
| `content_type` | `Option<String>` |  |

---

## `Client`

SDK entry point. Holds the RBS connection and provider state; not thread-safe (uses `Rc` internally). Create one instance per thread.

**Methods**

#### `new`

```rust
pub fn new(config: Config) -> Result<Self, RbcError>
```

Create a `Client` from a [`Config`].

#### `from_config`

```rust
pub fn from_config(path: &str) -> Result<Self, RbcError>
```

Create a `Client` by loading configuration from the YAML file at `path`.

#### `get_auth_challenge`

```rust
pub fn get_auth_challenge(&self) -> Result<AuthChallengeResponse, RbcError>
```

Request an authentication challenge (nonce) from RBS.

#### `new_session`

```rust
pub fn new_session( &self, attester_data: Option<&AttesterData>, ) -> Result<Session, RbcError>
```

Begin a new session. If `attester_data` does not contain `tee_pubkey`, an ephemeral key pair is generated automatically; otherwise the caller is responsible for the key.

---

## `Session`

Represents a single attestation session. Not thread-safe (uses `Rc` internally).

**Methods**

#### `collect_evidence`

```rust
pub fn collect_evidence( &self, challenge: &AuthChallengeResponse, ) -> Result<Value, RbcError>
```

Collect TEE evidence for the given challenge using the configured evidence provider.

#### `attest`

```rust
pub fn attest(&self, evidence: Option<&Value>) -> Result<AttestResponse, RbcError>
```

Obtain an attest token from the configured token provider, optionally passing raw evidence.

#### `get_resource`

```rust
pub fn get_resource( &self, uri: &str, request: GetResourceRequest<'_>, ) -> Result<Resource, RbcError>
```

Fetch the resource at `uri`, authorized via `request`.

#### `decrypt_content`

```rust
pub fn decrypt_content( &self, jwe_token: &str, private_key_pem: Option<&str>, passphrase: Option<&[u8]>, ) -> Result<Zeroizing<Vec<u8>>, RbcError>
```

Decrypt a JWE-encrypted resource content. Pass `private_key_pem` when the caller manages the TEE key; omit it to use the session's ephemeral key. Pass `passphrase` when the PEM is encrypted; caller is responsible for zeroizing the slice after this call returns.

---
