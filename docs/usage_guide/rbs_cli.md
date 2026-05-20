# rbs-cli Usage Guide

## Overview

`rbs-cli` is the command-line interface for the current RBS workspace. In the current build it exposes these top-level command groups:

```text
rbs-cli
├── client
├── res
├── res-policy
├── token
├── user
└── version
```

The current command tree does not expose `policy`, `cert`, or `ref-value` as runnable top-level commands, so they are intentionally omitted from this guide.

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

- Admin commands such as `user`, `res`, and `res-policy` require a bearer token. Pass it with `--token` or `RBS_TOKEN`.
- Client commands reuse the `rbc` command model and carry their own command-specific options such as `--agent-config`.

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

Fetch a protected resource. This command has three mutually exclusive authentication modes:

- `--attest-token`
- `--bearer-token`
- `--evidence`

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
| `--bearer-token <BEARER_TOKEN>` | No | unset | Mutually exclusive with `--attest-token` and `--evidence`. |
| `--evidence <EVIDENCE>` | No | unset | Mutually exclusive with `--attest-token` and `--bearer-token`. |
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

#### `client get-resource` by bearer token

**Usage**

```bash
rbs-cli client get-resource [OPTIONS] \
  --uri <URI> \
  --bearer-token <BEARER_TOKEN>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `--agent-config <AGENT_CONFIG>` | No | `/etc/attestation_agent/agent_config.yaml` | Path to the attestation agent config file. |
| `--uri <URI>` | Yes | none | Resource URI to fetch. |
| `--bearer-token <BEARER_TOKEN>` | Yes | none | Bearer token. Supports inline input or `@file`. |
| `--attest-token <ATTEST_TOKEN>` | No | unset | Mutually exclusive with `--bearer-token` and `--evidence`. |
| `--evidence <EVIDENCE>` | No | unset | Mutually exclusive with `--attest-token` and `--bearer-token`. |
| `--private-key-file <PRIVATE_KEY_FILE>` | No | unset | PEM private key used to decrypt returned content when needed. |
| `--private-key-passphrase [<@PATH>]` | No | unset | Read the private key passphrase interactively or from `@PATH`. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 \
  client get-resource \
  --uri vault/default/secret/test-key \
  --bearer-token @/tmp/bearer.jwt \
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
| `--attest-token <ATTEST_TOKEN>` | No | unset | Mutually exclusive with `--evidence` and `--bearer-token`. |
| `--bearer-token <BEARER_TOKEN>` | No | unset | Mutually exclusive with `--evidence` and `--attest-token`. |
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

## Resource Metadata Commands

`rbs-cli res` manages resource metadata bindings for keys, secrets, and certs.

### Shared path fields

The following fields are reused by `res get`, `res create`, `res update`, and `res delete`:

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| `--provider-name <PROVIDER_NAME>` | Yes | none | Resource provider, for example `vault`. |
| `--repository-name <REPOSITORY_NAME>` | Yes | none | Repository or namespace name. |
| `--resource-type <RESOURCE_TYPE>` | Yes | none | Resource type: `key`, `secret`, or `cert`. |
| `--resource-name <RESOURCE_NAME>` | Yes | none | Resource name. |

### `res get`

**Usage**

```bash
rbs-cli res get [OPTIONS] \
  --provider-name <PROVIDER_NAME> \
  --repository-name <REPOSITORY_NAME> \
  --resource-type <RESOURCE_TYPE> \
  --resource-name <RESOURCE_NAME>
```

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" \
  res get \
  --provider-name vault \
  --repository-name default \
  --resource-type secret \
  --resource-name my-secret
```

### `res create`

**Usage**

```bash
rbs-cli res create [OPTIONS] \
  --provider-name <PROVIDER_NAME> \
  --repository-name <REPOSITORY_NAME> \
  --resource-type <RESOURCE_TYPE> \
  --resource-name <RESOURCE_NAME> \
  --policy-id <POLICY_ID>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| shared path fields | Yes | none | See the shared path table above. |
| `--policy-id <POLICY_ID>` | Yes | none | Bound resource policy ID. |
| `--additional-info <ADDITIONAL_INFO>` | No | unset | Optional Base64 `additional_info` value or `@file` path. |
| `--content-type <CONTENT_TYPE>` | No | unset | Resource content type: `jwt`, `json`, `text`, `binary`, `jwk`, or `jwe`. |
| `--export-mode <EXPORT_MODE>` | No | unset | Export mode: `plain` or `jwe`. |

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" \
  res create \
  --provider-name vault \
  --repository-name default \
  --resource-type secret \
  --resource-name my-secret \
  --policy-id policy-1 \
  --content-type text \
  --export-mode plain
```

### `res update`

**Usage**

```bash
rbs-cli res update [OPTIONS] \
  --provider-name <PROVIDER_NAME> \
  --repository-name <REPOSITORY_NAME> \
  --resource-type <RESOURCE_TYPE> \
  --resource-name <RESOURCE_NAME>
```

**Parameters**

| Option | Required | Default | Meaning / Notes |
|---|---|---|---|
| shared path fields | Yes | none | See the shared path table above. |
| `--policy-id <POLICY_ID>` | No | unset | Bound resource policy ID. |
| `--additional-info <ADDITIONAL_INFO>` | No | unset | Optional Base64 `additional_info` value or `@file` path. |
| `--content-type <CONTENT_TYPE>` | No | unset | Resource content type: `jwt`, `json`, `text`, `binary`, `jwk`, or `jwe`. |
| `--export-mode <EXPORT_MODE>` | No | unset | Export mode: `plain` or `jwe`. |

Notes:

- At least one updatable field must be provided.

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" \
  res update \
  --provider-name vault \
  --repository-name default \
  --resource-type secret \
  --resource-name my-secret \
  --export-mode jwe
```

### `res delete`

**Usage**

```bash
rbs-cli res delete [OPTIONS] \
  --provider-name <PROVIDER_NAME> \
  --repository-name <REPOSITORY_NAME> \
  --resource-type <RESOURCE_TYPE> \
  --resource-name <RESOURCE_NAME>
```

**Example**

```bash
rbs-cli -b http://127.0.0.1:8080 -t "$RBS_TOKEN" \
  res delete \
  --provider-name vault \
  --repository-name default \
  --resource-type secret \
  --resource-name my-secret
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
