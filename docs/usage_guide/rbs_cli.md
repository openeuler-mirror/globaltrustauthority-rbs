# rbs-cli Usage Guide

## Overview

`rbs-cli` is the command-line interface for the current RBS workspace. In the current build it exposes these top-level command groups:

```text
rbs-cli
├── cert
├── client
├── policy
├── ref-value
├── res
├── res-policy
├── token
├── user
└── version
```

---

## Global Options

Global options accepted by `rbs-cli`:

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `-b`, `--base-url <BASE_URL>` | No | `http://localhost:8080` | Base URL of the target RBS service. |
| `-t`, `--token <TOKEN>` | No | from `RBS_TOKEN` when set | Bearer token used for authenticated admin requests. |
| `--cert <CERT>` | No | unset | CA certificate file used to verify the RBS server. |
| `-f`, `--format <FORMAT>` | No | `text` | Output format: `text` or `json`. |
| `-o`, `--output-file <OUTPUT_FILE>` | No | unset | Write rendered output to a file. |
| `-v`, `--verbose` | No | `false` | Enable verbose logging. |
| `-q`, `--quiet` | No | `false` | Suppress non-essential output. Conflicts with `--verbose`. |
| `--noout` | No | `false` | Do not print command output to stdout. |

Notes:

- Admin commands such as `user`, `res`, `res-policy`, `ref-value`, `cert`, and `policy` require a bearer token. Pass it with `--token` or `RBS_TOKEN`.
- Client commands reuse the `rbc` command model and carry their own command-specific options such as `--agent-config`.

---

## GTA Attestation Management Commands

`rbs-cli` proxies GTA attestation-management APIs through RBS. These commands
operate on the default `gta` attestation provider and require an RBS bearer
token with administrator privileges.

| Command group | GTA entity | Available operations |
|---|---|---|
| `ref-value` | Reference-value baselines | `list`, `get`, `create`, `update`, `delete` |
| `cert` | Certificates and CRLs | `list`, `get`, `create`, `update`, `delete` |
| `policy` | Attestation policies | `list`, `get`, `create`, `update`, `delete` |

Examples:

```bash
# Create a TPM baseline from a JWT file.
rbs-cli -b https://rbs.example.com -t "$RBS_TOKEN" \
  ref-value create --name tpm-baseline --attester-type tpm --content @baseline.jwt

# Upload a TPM certificate.
rbs-cli -b https://rbs.example.com -t "$RBS_TOKEN" \
  cert create --name tpm-ak-cert --type tpm --content @ak-cert.pem

# Page through certificates and fetch one certificate or CRL by ID.
rbs-cli -b https://rbs.example.com -t "$RBS_TOKEN" cert list --limit 10 --offset 0
rbs-cli -b https://rbs.example.com -t "$RBS_TOKEN" cert get --id C1
rbs-cli -b https://rbs.example.com -t "$RBS_TOKEN" ref-value get --id RV1
rbs-cli -b https://rbs.example.com -t "$RBS_TOKEN" policy get --id P1
rbs-cli -b https://rbs.example.com -t "$RBS_TOKEN" ref-value list --limit 10 --offset 0
rbs-cli -b https://rbs.example.com -t "$RBS_TOKEN" policy list --limit 10 --offset 0

# Create a GTA attestation policy; text content is Base64 encoded.
rbs-cli -b https://rbs.example.com -t "$RBS_TOKEN" \
  policy create --name allow-tpm --attester-type tpm --content-type text --content @policy.b64
```

Use `rbs-cli <ref-value|cert|policy> <command> --help` for the complete,
operation-specific option list.

---

## Client Commands

`rbs-cli client` exposes four runnable subcommands:

```text
rbs-cli client challenge
rbs-cli client collect-evidence
rbs-cli client get-token
rbs-cli client get-resource
```

### `client challenge`

Request an authentication nonce from the RBS server.

**Usage**

```bash
rbs-cli client challenge [OPTIONS]
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `--agent-config <AGENT_CONFIG>` | No | `/etc/attestation_agent/agent_config.yaml` | Path to the attestation agent config file. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 \
  client challenge \
  --agent-config /etc/attestation_agent/agent_config.yaml \
  -o /tmp/nonce.txt
```

### `client collect-evidence`

Collect local evidence using the attestation agent.

**Usage**

```bash
rbs-cli client collect-evidence [OPTIONS] \
  --nonce <NONCE> \
  --attester-pubkey <ATTESTER_PUBKEY>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `--agent-config <AGENT_CONFIG>` | No | `/etc/attestation_agent/agent_config.yaml` | Path to the attestation agent config file. |
| `--nonce <NONCE>` | Yes | none | Nonce to embed in collected evidence. Supports inline input or `@file`. |
| `--attester-pubkey <ATTESTER_PUBKEY>` | Yes | none | Attester public key used to populate `tee-pubkey` in runtime data. Supports inline input or `@file`. |
| `--attester-data <ATTESTER_DATA>` | No | unset | Attester-data JSON or `@file` path merged into the request. |
| `--runtime-data <RUNTIME_DATA>` | No | repeatable | Runtime data entry in `key=value` form. Repeat to add multiple entries. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 \
  client collect-evidence \
  --nonce @/tmp/nonce.txt \
  --attester-pubkey @/tmp/public.pem \
  --agent-config /etc/attestation_agent/agent_config.yaml \
  -o /tmp/evidence.json
```

### `client get-token`

Obtain an attestation token. This command has two mutually exclusive modes:

- evidence mode: `--evidence`
- native mode: `--attester-pubkey`

#### `client get-token` by evidence

**Usage**

```bash
rbs-cli client get-token [OPTIONS] --evidence <EVIDENCE>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `--agent-config <AGENT_CONFIG>` | No | `/etc/attestation_agent/agent_config.yaml` | Path to the attestation agent config file. |
| `--evidence <EVIDENCE>` | Yes | none | Evidence JSON or `@file` path. |
| `--attester-pubkey <ATTESTER_PUBKEY>` | No | unset | Not allowed with `--evidence`. |
| `--attester-data <ATTESTER_DATA>` | No | unset | Not allowed with `--evidence`. |
| `--runtime-data <RUNTIME_DATA>` | No | repeatable | Not allowed with `--evidence`. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 \
  client get-token \
  --evidence @/tmp/evidence.json \
  --agent-config /etc/attestation_agent/agent_config.yaml \
  -o /tmp/token.jwt
```

#### `client get-token` by attester public key

**Usage**

```bash
rbs-cli client get-token [OPTIONS] --attester-pubkey <ATTESTER_PUBKEY>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `--agent-config <AGENT_CONFIG>` | No | `/etc/attestation_agent/agent_config.yaml` | Path to the attestation agent config file. |
| `--attester-pubkey <ATTESTER_PUBKEY>` | Yes | none | Attester public key used to populate `tee-pubkey` in runtime data. Supports inline input or `@file`. |
| `--attester-data <ATTESTER_DATA>` | No | unset | Attester-data JSON or `@file` path merged into the request. |
| `--runtime-data <RUNTIME_DATA>` | No | repeatable | Runtime data entry in `key=value` form. Repeat to add multiple entries. |
| `--evidence <EVIDENCE>` | No | unset | Mutually exclusive with `--attester-pubkey`. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 \
  client get-token \
  --attester-pubkey @/tmp/public.pem \
  --agent-config /etc/attestation_agent/agent_config.yaml \
  -o /tmp/token.jwt
```

### `client get-resource`

Fetch a protected resource through the client attestation flow. This command has four mutually exclusive authentication modes:

- `--attest-token`
- `--evidence`
- `--passport`
- `--background`

Bearer-token resource access is handled by `rbs-cli res get`, because that path uses the admin bearer token and an explicit private key to decrypt the returned JWE content.

#### `client get-resource` by attest token

**Usage**

```bash
rbs-cli client get-resource [OPTIONS] \
  --uri <URI> \
  --attest-token <ATTEST_TOKEN>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `--agent-config <AGENT_CONFIG>` | No | `/etc/attestation_agent/agent_config.yaml` | Path to the attestation agent config file. |
| `--uri <URI>` | Yes | none | Resource URI to fetch. |
| `--attest-token <ATTEST_TOKEN>` | Yes | none | Attestation token. Supports inline input or `@file`. |
| `--evidence <EVIDENCE>` | No | unset | Mutually exclusive with `--attest-token`. |
| `--private-key-file <PRIVATE_KEY_FILE>` | No | unset | PEM private key used to decrypt returned content when needed. |
| `--private-key-passphrase [<@PATH>]` | No | unset | Read the private key passphrase interactively or from `@PATH`. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 \
  client get-resource \
  --uri vault/default/secret/test-key \
  --attest-token @/tmp/token.jwt \
  --agent-config /etc/attestation_agent/agent_config.yaml \
  --private-key-file /tmp/private_key.pem \
  -o /tmp/resource.txt
```

#### `client get-resource` by evidence

**Usage**

```bash
rbs-cli client get-resource [OPTIONS] \
  --uri <URI> \
  --evidence <EVIDENCE>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `--agent-config <AGENT_CONFIG>` | No | `/etc/attestation_agent/agent_config.yaml` | Path to the attestation agent config file. |
| `--uri <URI>` | Yes | none | Resource URI to fetch. |
| `--evidence <EVIDENCE>` | Yes | none | Evidence JSON or `@file` path. |
| `--attest-token <ATTEST_TOKEN>` | No | unset | Mutually exclusive with `--evidence`. |
| `--private-key-file <PRIVATE_KEY_FILE>` | No | unset | PEM private key used to decrypt returned content when needed. |
| `--private-key-passphrase [<@PATH>]` | No | unset | Read the private key passphrase interactively or from `@PATH`. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 \
  client get-resource \
  --uri vault/default/secret/test-key \
  --evidence @/tmp/evidence.json \
  --agent-config /etc/attestation_agent/agent_config.yaml \
  --private-key-file /tmp/private_key.pem \
  -o /tmp/resource.txt
```

#### `client get-resource` by `--passport` auto flow

**Usage**

```bash
rbs-cli client get-resource [OPTIONS] \
  --uri <URI> \
  --passport
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `--agent-config <AGENT_CONFIG>` | No | `/etc/attestation_agent/agent_config.yaml` | Path to the attestation agent config file. |
| `--uri <URI>` | Yes | none | Resource URI to fetch. |
| `--passport` | Yes | none | Run the auto flow: `native get-token -> get-resource`. |
| `--attester-data <ATTESTER_DATA>` | No | unset | Attester-data JSON or `@file` path merged into the auto-flow request. |
| `--runtime-data <RUNTIME_DATA>` | No | repeatable | Runtime data entry in `key=value` form; repeat to add multiple entries. |
| `--private-key-file <PRIVATE_KEY_FILE>` | No | unset | Not allowed with `--passport`. |
| `--private-key-passphrase [<@PATH>]` | No | unset | Not allowed with `--passport`. |

Notes:

- `--passport` is mutually exclusive with `--attest-token`, `--evidence`, and external private-key options.
- The command uses an in-memory `TeePubKeyPair` and automatically decrypts encrypted resource content when possible.

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 \
  client get-resource \
  --uri vault/default/secret/test-key \
  --passport \
  --agent-config /etc/attestation_agent/agent_config.yaml \
  -o /tmp/resource.txt
```

#### `client get-resource` by `--background` auto flow

**Usage**

```bash
rbs-cli client get-resource [OPTIONS] \
  --uri <URI> \
  --background
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `--agent-config <AGENT_CONFIG>` | No | `/etc/attestation_agent/agent_config.yaml` | Path to the attestation agent config file. |
| `--uri <URI>` | Yes | none | Resource URI to fetch. |
| `--background` | Yes | none | Run the auto flow: `challenge -> native collect-evidence -> retrieve resource`. |
| `--attester-data <ATTESTER_DATA>` | No | unset | Attester-data JSON or `@file` path merged into the auto-flow request. |
| `--runtime-data <RUNTIME_DATA>` | No | repeatable | Runtime data entry in `key=value` form; repeat to add multiple entries. |
| `--private-key-file <PRIVATE_KEY_FILE>` | No | unset | Not allowed with `--background`. |
| `--private-key-passphrase [<@PATH>]` | No | unset | Not allowed with `--background`. |

Notes:

- `--background` is mutually exclusive with `--attest-token`, `--evidence`, and external private-key options.
- The command uses an in-memory `TeePubKeyPair` and automatically decrypts encrypted resource content when possible.

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 \
  client get-resource \
  --uri vault/default/secret/test-key \
  --background \
  --agent-config /etc/attestation_agent/agent_config.yaml \
  -o /tmp/resource.txt
```

---

## User Commands

`rbs-cli user` manages broker-side users.

### `user list`

**Usage**

```bash
rbs-cli user list [OPTIONS]
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `--limit <LIMIT>` | No | `10` | Maximum number of users to return. |
| `--offset <OFFSET>` | No | `0` | Pagination offset. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" user list --limit 20 --offset 0
```

### `user get`

**Usage**

```bash
rbs-cli user get [OPTIONS] --username <USERNAME>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `-u`, `--username <USERNAME>` | Yes | none | Username to query. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" user get --username smoke-user
```

### `user create`

**Usage**

```bash
rbs-cli user create [OPTIONS] \
  --username <USERNAME> \
  <--public-key <PUBLIC_KEY>|--jwk <JWK>>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `--username <USERNAME>` | Yes | none | Username to create. |
| `--role <ROLE>` | No | `user` | User role: `user` or `admin`. |
| `--enabled <ENABLED>` | No | unset | Whether the user is enabled after creation. |
| `--public-key <PUBLIC_KEY>` | Conditionally | unset | PEM public key or `@file` path. Mutually exclusive with `--jwk`. |
| `--jwk <JWK>` | Conditionally | unset | JWK JSON or `@file` path. Mutually exclusive with `--public-key`. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" \
  user create \
  --username smoke-user \
  --role user \
  --enabled true \
  --public-key @/tmp/public.pem
```

### `user update`

**Usage**

```bash
rbs-cli user update [OPTIONS] --username <USERNAME>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `-u`, `--username <USERNAME>` | Yes | none | Username to update. |
| `--role <ROLE>` | No | unset | New user role: `user` or `admin`. |
| `--enabled <ENABLED>` | No | unset | Whether the user is enabled. |
| `--public-key <PUBLIC_KEY>` | No | unset | PEM public key or `@file` path. Mutually exclusive with `--jwk`. |
| `--jwk <JWK>` | No | unset | JWK JSON or `@file` path. Mutually exclusive with `--public-key`. |

Notes:

- At least one updatable field must be provided.

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" \
  user update \
  --username smoke-user \
  --role admin
```

### `user delete`

**Usage**

```bash
rbs-cli user delete [OPTIONS] --username <USERNAME>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `-u`, `--username <USERNAME>` | Yes | none | Username to delete. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" user delete --username smoke-user
```

---

## Resource Policy Commands

`rbs-cli res-policy` manages resource access policies.

### `res-policy list`

**Usage**

```bash
rbs-cli res-policy list [OPTIONS]
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `--ids <IDS>` | No | unset | Comma-separated resource policy IDs. |
| `--limit <LIMIT>` | No | `10` | Page size. |
| `--offset <OFFSET>` | No | `0` | Pagination offset. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" \
  res-policy list \
  --ids policy-1,policy-2 \
  --limit 10 \
  --offset 0
```

### `res-policy get`

**Usage**

```bash
rbs-cli res-policy get [OPTIONS] --id <ID>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `--id <ID>` | Yes | none | Resource policy ID. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" res-policy get --id policy-1
```

### `res-policy create`

**Usage**

```bash
rbs-cli res-policy create [OPTIONS] \
  --name <NAME> \
  --content <CONTENT>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `--name <NAME>` | Yes | none | Resource policy name. |
| `--content <CONTENT>` | Yes | none | Base64 policy content or `@file` path. Raw input is Base64-encoded automatically. |
| `--content-type <CONTENT_TYPE>` | No | `base64` | Currently only `base64` is supported. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" \
  res-policy create \
  --name allow-secret \
  --content @policy.rego
```

### `res-policy update`

**Usage**

```bash
rbs-cli res-policy update [OPTIONS] \
  --id <ID> \
  --name <NAME> \
  --content <CONTENT>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `--id <ID>` | Yes | none | Resource policy ID. |
| `--name <NAME>` | Yes | none | Resource policy name. |
| `--content <CONTENT>` | Yes | none | Base64 policy content or `@file` path. Raw input is Base64-encoded automatically. |
| `--content-type <CONTENT_TYPE>` | No | `base64` | Currently only `base64` is supported. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" \
  res-policy update \
  --id policy-1 \
  --name allow-secret-v2 \
  --content @policy.rego
```

### `res-policy delete`

**Usage**

```bash
rbs-cli res-policy delete [OPTIONS] <--id <ID>|--ids <IDS>>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `--id <ID>` | Conditionally | unset | Single resource policy ID. Mutually exclusive with `--ids`. |
| `--ids <IDS>` | Conditionally | unset | Comma-separated resource policy IDs. Mutually exclusive with `--id`. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" \
  res-policy delete \
  --ids policy-1,policy-2
```

---

## Resource Commands

`rbs-cli res` manages resource metadata bindings and retrieves encrypted resource content for keys, secrets, and certs.

### Shared URI field

The following URI option is reused by `res get`, `res get-res-info`, `res create`, `res update`, and `res delete`:

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `--uri <URI>` | Yes | none | Resource URI in `provider/repository/type/name` form, for example `vault/default/secret/my-secret`. The resource type must be `key`, `secret`, or `cert`. |

### `res get`

Fetch resource content with the bearer token configured by `-t/--token`, then decrypt the returned JWE content with a private key. The private key must match the `enc-pubkey` claim in the bearer token.

**Usage**

```bash
rbs-cli res get [OPTIONS] \
  --uri <URI> \
  --private-key-file <PRIVATE_KEY_FILE>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| shared URI field | Yes | none | See the shared URI table above. |
| `--private-key-file <PRIVATE_KEY_FILE>` | Yes | none | PEM private key used to decrypt the returned JWE content. |
| `--private-key-passphrase [<@PATH>]` | No | unset | Read the private key passphrase interactively or from `@PATH`. Inline passphrase values are rejected. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" \
  res get \
  --uri vault/default/secret/my-secret \
  --private-key-file /tmp/enc-private-key.pem
```

### `res get-res-info`

Fetch resource metadata only. This command does not return or decrypt resource content.

**Usage**

```bash
rbs-cli res get-res-info [OPTIONS] \
  --uri <URI>
```

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" \
  res get-res-info \
  --uri vault/default/secret/my-secret
```

### `res create`

**Usage**

```bash
rbs-cli res create [OPTIONS] \
  --uri <URI> \
  --policy-id <POLICY_ID>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| shared URI field | Yes | none | See the shared URI table above. |
| `--policy-id <POLICY_ID>` | Yes | none | Bound resource policy ID. |
| `--additional-info <ADDITIONAL_INFO>` | No | unset | Optional Base64 `additional_info` value or `@file` path. |
| `--content-type <CONTENT_TYPE>` | No | unset | Resource content type: `jwt`, `json`, `text`, `binary`, `jwk`, or `jwe`. |
| `--export-mode <EXPORT_MODE>` | No | unset | Export mode. Currently only `jwe` is accepted. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" \
  res create \
  --uri vault/default/secret/my-secret \
  --policy-id policy-1 \
  --content-type text \
  --export-mode jwe
```

### `res update`

**Usage**

```bash
rbs-cli res update [OPTIONS] \
  --uri <URI> \
  --policy-id <POLICY_ID>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| shared URI field | Yes | none | See the shared URI table above. |
| `--policy-id <POLICY_ID>` | Yes | none | Bound resource policy ID. |
| `--additional-info <ADDITIONAL_INFO>` | No | unset | Optional Base64 `additional_info` value or `@file` path. |
| `--content-type <CONTENT_TYPE>` | No | unset | Resource content type: `jwt`, `json`, `text`, `binary`, `jwk`, or `jwe`. |
| `--export-mode <EXPORT_MODE>` | No | unset | Export mode. Currently only `jwe` is accepted. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" \
  res update \
  --uri vault/default/secret/my-secret \
  --policy-id policy-1 \
  --export-mode jwe
```

### `res delete`

**Usage**

```bash
rbs-cli res delete [OPTIONS] \
  --uri <URI>
```

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" \
  res delete \
  --uri vault/default/secret/my-secret
```

---

## Token Commands

`rbs-cli token` currently exposes one runnable subcommand:

```text
rbs-cli token gen
```

This guide keeps the token section at overview level. For the exact current parameter list of `token gen`, use:

```bash
rbs-cli token gen --help
```

Typical usage:

```bash
rbs-cli token gen \
  --private-key-file ./private.pem \
  --iss rbs-cli \
  --aud globaltrustauthority-rbs \
  --role admin \
  --kid smoke-ed25519-key-1 \
  --sub Administrator \
  --claims @./claims.json
```

---

## Version Command

### `version`

Print the current `rbs-cli` package name and version.

**Usage**

```bash
rbs-cli version
```

**Example**

```bash
rbs-cli version
```
