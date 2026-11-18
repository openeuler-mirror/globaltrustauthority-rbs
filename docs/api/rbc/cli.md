<!-- Generated from clap command definitions. Run ./scripts/generate-cli-docs.sh. -->

# Command-Line Help for `rbc-cli`

This document contains the help content for the `rbc-cli` command-line program.

**Command Overview:**

* [`rbc-cli`↴](#rbc-cli)
* [`rbc-cli challenge`↴](#rbc-cli-challenge)
* [`rbc-cli collect-evidence`↴](#rbc-cli-collect-evidence)
* [`rbc-cli get-token`↴](#rbc-cli-get-token)
* [`rbc-cli get-resource`↴](#rbc-cli-get-resource)

## `rbc-cli`

Run RBC CLI commands

**Usage:** `rbc-cli [OPTIONS] <COMMAND>`

###### **Subcommands:**

* `challenge` — Request an authentication nonce from the RBS server
* `collect-evidence` — Collect local evidence using the attestation agent
* `get-token` — Obtain an attestation token via the configured token provider
* `get-resource` — Fetch a protected resource using a token or evidence

###### **Options:**

* `-b`, `--base-url <BASE_URL>` — Base URL of the RBS service
* `--cert <CERT>` — CA certificate file used to verify the RBS server
* `--timeout-secs <TIMEOUT_SECS>` — Request timeout in seconds
* `--key-algorithm <KEY_ALGORITHM>` — Key algorithm used for TEE key generation (rsa, ec, sm2)
* `--as-provider <AS_PROVIDER>` — Provider identifier sent to RBS APIs

  Default value: `gta`
* `-f`, `--format <FORMAT>` — Output format

  Default value: `text`

  Possible values: `json`, `text`

* `-o`, `--output-file <OUTPUT_FILE>` — Write command output to a file
* `--noout` — Do not print command output
* `-q`, `--quiet` — Suppress non-essential output
* `-v`, `--verbose` — Enable verbose diagnostics



## `rbc-cli challenge`

Request an authentication nonce from the RBS server

**Usage:** `rbc-cli challenge [OPTIONS]`

###### **Options:**

* `--agent-config <AGENT_CONFIG>` — Path to the attestation agent config file

  Default value: `/etc/attestation_agent/agent_config.yaml`



## `rbc-cli collect-evidence`

Collect local evidence using the attestation agent

**Usage:** `rbc-cli collect-evidence [OPTIONS] --nonce <NONCE> --attester-pubkey <ATTESTER_PUBKEY>`

###### **Options:**

* `--agent-config <AGENT_CONFIG>` — Path to the attestation agent config file

  Default value: `/etc/attestation_agent/agent_config.yaml`
* `--nonce <NONCE>` — Nonce to embed in collected evidence
* `--attester-pubkey <ATTESTER_PUBKEY>` — Attester public key used to populate tee-pubkey in runtime data
* `--attester-data <ATTESTER_DATA>` — Attester-data JSON or @file path merged into the request
* `--runtime-data <RUNTIME_DATA>` — Runtime data entry in key=value form; repeat to add multiple entries



## `rbc-cli get-token`

Obtain an attestation token via the configured token provider

**Usage:** `rbc-cli get-token [OPTIONS] <--evidence <EVIDENCE>|--attester-pubkey <ATTESTER_PUBKEY>>`

###### **Options:**

* `--agent-config <AGENT_CONFIG>` — Path to the attestation agent config file

  Default value: `/etc/attestation_agent/agent_config.yaml`
* `--attester-pubkey <ATTESTER_PUBKEY>` — Attester public key used to populate tee-pubkey in runtime data
* `--attester-data <ATTESTER_DATA>` — Attester-data JSON or @file path merged into the request
* `--runtime-data <RUNTIME_DATA>` — Runtime data entry in key=value form; repeat to add multiple entries
* `--evidence <EVIDENCE>` — Evidence JSON or @file path



## `rbc-cli get-resource`

Fetch a protected resource using a token or evidence

**Usage:** `rbc-cli get-resource [OPTIONS] --uri <URI> <--attest-token <ATTEST_TOKEN>|--evidence <EVIDENCE>|--passport|--background>`

###### **Options:**

* `--agent-config <AGENT_CONFIG>` — Path to the attestation agent config file

  Default value: `/etc/attestation_agent/agent_config.yaml`
* `--uri <URI>` — Resource URI to fetch
* `--attest-token <ATTEST_TOKEN>` — Attestation token used for resource retrieval
* `--evidence <EVIDENCE>` — Evidence JSON or @file path
* `--passport` — Run the passport auto flow: challenge -> native get-token -> get-resource
* `--background` — Run the background auto flow: challenge -> native collect-evidence -> retrieve resource
* `--attester-data <ATTESTER_DATA>` — Attester-data JSON or @file path merged into the auto-flow request
* `--runtime-data <RUNTIME_DATA>` — Runtime data entry in key=value form; repeat to add multiple entries for auto-flow modes
* `--private-key-file <PRIVATE_KEY_FILE>` — Path to a PEM private key used to decrypt returned content when needed
* `--private-key-passphrase <@PATH>` — Read the private key passphrase interactively or from @PATH



<hr/>

<small><i>
    This document was generated automatically by
    <a href="https://crates.io/crates/clap-markdown"><code>clap-markdown</code></a>.
</i></small>
