# rbs-cli Usage Guide

## Overview

`rbs-cli` is the operator and client command-line interface for this workspace. It combines:

- admin commands for users, policies, resource metadata, certificates, and reference values
- client commands that reuse the `rbc` command layer for attestation and resource retrieval
- local token utilities such as verification and inspection

The command tree is:

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

## Global Options

Common options accepted by `rbs-cli`:

| Option | Meaning | Default |
|---|---|---|
| `-b`, `--base-url` | Base URL of the target RBS service | `http://localhost:8080` |
| `-t`, `--token` | Bearer token used by admin APIs | from `RBS_TOKEN` when set |
| `--cert` | CA certificate path for TLS verification | unset |
| `--evidence-provider-type` | Client evidence provider type | explicit flag when needed |
| `--evidence-provider-config` | Evidence provider config path | `/etc/attestation_agent/agent_config.yaml` |
| `--token-provider-type` | Client token provider type | explicit flag when needed |
| `--token-provider-config` | Token provider config path | `/etc/attestation_agent/agent_config.yaml` |
| `-f`, `--format` | Output format | `text` |
| `-o`, `--output-file` | Write formatted output to a file | unset |
| `--noout` | Suppress stdout output | `false` |

When `--output-file` is provided, `rbs-cli` writes the rendered output to the target path using the selected output formatter.

## Client Commands

The `client` subcommand reuses the `rbc` command model:

```text
rbs-cli client challenge
rbs-cli client collect-evidence
rbs-cli client attest
rbs-cli client get-token
rbs-cli client get-resource
```

### challenge

Fetch a nonce from RBS:

```bash
rbs-cli -b http://127.0.0.1:8080 client challenge
```

### collect-evidence

Collect local evidence with an explicit nonce and TEE public key:

```bash
rbs-cli -b http://127.0.0.1:8080 \
  client collect-evidence \
  --nonce @/tmp/nonce.txt \
  --attester-pubkey @public_key.pem \
  --output-file /tmp/evidence.json
```

### attest

Submit existing evidence to RBS:

```bash
rbs-cli -b http://127.0.0.1:8080 \
  --token-provider-type rbs \
  client attest \
  --evidence @/tmp/evidence.json \
  --output-file /tmp/token.txt
```

### get-token

Obtain a token from the configured token provider:

```bash
rbs-cli -b http://127.0.0.1:8080 \
  client get-token \
  --attester-pubkey @public_key.pem \
  --output-file /tmp/token.txt
```

### get-resource

Fetch a resource by token:

```bash
rbs-cli -b http://127.0.0.1:8080 \
  client get-resource \
  --uri default/repo/key/test-key \
  --token @/tmp/token.txt \
  --private-key-file private_key.pem \
  --output-file /tmp/resource.txt
```

Or by evidence:

```bash
rbs-cli -b http://127.0.0.1:8080 \
  client get-resource \
  --uri default/repo/key/test-key \
  --evidence @/tmp/evidence.json
```

## Admin Commands

The admin command groups operate on broker-side metadata and identities:

- `user` for user CRUD
- `policy` for attestation policy CRUD
- `res-policy` for resource policy CRUD
- `res` for resource metadata management
- `cert` for certificates and CRLs
- `ref-value` for reference values

Examples:

```bash
rbs-cli -b http://127.0.0.1:8080 user list
rbs-cli -b http://127.0.0.1:8080 policy list
rbs-cli -b http://127.0.0.1:8080 res get --res-provider vault --repository-name default --resource-type secret --resource-name my-secret
```

## Token Utilities

The `token` command group is used for local token generation and verification workflows. Check the built-in help for the exact subcommands supported by the current build:

```bash
rbs-cli token --help
```

## Version

Print service/client version metadata:

```bash
rbs-cli version
```
