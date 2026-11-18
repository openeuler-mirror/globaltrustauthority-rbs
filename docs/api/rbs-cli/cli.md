<!-- Generated from clap command definitions. Run ./scripts/generate-cli-docs.sh. -->

# Command-Line Help for `rbs-cli`

This document contains the help content for the `rbs-cli` command-line program.

**Command Overview:**

* [`rbs-cli`↴](#rbs-cli)
* [`rbs-cli cert`↴](#rbs-cli-cert)
* [`rbs-cli cert list`↴](#rbs-cli-cert-list)
* [`rbs-cli cert get`↴](#rbs-cli-cert-get)
* [`rbs-cli cert create`↴](#rbs-cli-cert-create)
* [`rbs-cli cert update`↴](#rbs-cli-cert-update)
* [`rbs-cli cert delete`↴](#rbs-cli-cert-delete)
* [`rbs-cli client`↴](#rbs-cli-client)
* [`rbs-cli client challenge`↴](#rbs-cli-client-challenge)
* [`rbs-cli client collect-evidence`↴](#rbs-cli-client-collect-evidence)
* [`rbs-cli client get-token`↴](#rbs-cli-client-get-token)
* [`rbs-cli client get-resource`↴](#rbs-cli-client-get-resource)
* [`rbs-cli policy`↴](#rbs-cli-policy)
* [`rbs-cli policy list`↴](#rbs-cli-policy-list)
* [`rbs-cli policy get`↴](#rbs-cli-policy-get)
* [`rbs-cli policy create`↴](#rbs-cli-policy-create)
* [`rbs-cli policy update`↴](#rbs-cli-policy-update)
* [`rbs-cli policy delete`↴](#rbs-cli-policy-delete)
* [`rbs-cli ref-value`↴](#rbs-cli-ref-value)
* [`rbs-cli ref-value list`↴](#rbs-cli-ref-value-list)
* [`rbs-cli ref-value get`↴](#rbs-cli-ref-value-get)
* [`rbs-cli ref-value create`↴](#rbs-cli-ref-value-create)
* [`rbs-cli ref-value update`↴](#rbs-cli-ref-value-update)
* [`rbs-cli ref-value delete`↴](#rbs-cli-ref-value-delete)
* [`rbs-cli res`↴](#rbs-cli-res)
* [`rbs-cli res get`↴](#rbs-cli-res-get)
* [`rbs-cli res get-res-info`↴](#rbs-cli-res-get-res-info)
* [`rbs-cli res create`↴](#rbs-cli-res-create)
* [`rbs-cli res update`↴](#rbs-cli-res-update)
* [`rbs-cli res delete`↴](#rbs-cli-res-delete)
* [`rbs-cli res-policy`↴](#rbs-cli-res-policy)
* [`rbs-cli res-policy list`↴](#rbs-cli-res-policy-list)
* [`rbs-cli res-policy get`↴](#rbs-cli-res-policy-get)
* [`rbs-cli res-policy create`↴](#rbs-cli-res-policy-create)
* [`rbs-cli res-policy update`↴](#rbs-cli-res-policy-update)
* [`rbs-cli res-policy delete`↴](#rbs-cli-res-policy-delete)
* [`rbs-cli token`↴](#rbs-cli-token)
* [`rbs-cli token gen`↴](#rbs-cli-token-gen)
* [`rbs-cli user`↴](#rbs-cli-user)
* [`rbs-cli user list`↴](#rbs-cli-user-list)
* [`rbs-cli user get`↴](#rbs-cli-user-get)
* [`rbs-cli user create`↴](#rbs-cli-user-create)
* [`rbs-cli user update`↴](#rbs-cli-user-update)
* [`rbs-cli user delete`↴](#rbs-cli-user-delete)
* [`rbs-cli version`↴](#rbs-cli-version)

## `rbs-cli`

**Usage:** `rbs-cli [OPTIONS] <COMMAND>`

###### **Subcommands:**

* `cert` — Manage GTA certificates and CRLs through RBS
* `client` — Run attestation and protected-resource client commands
* `policy` — Manage GTA attestation policies through RBS
* `ref-value` — Manage GTA reference-value baselines through RBS
* `res` — Manage key, secret, and cert resources
* `res-policy` — Manage resource access policies
* `token` — Generate signed JWT tokens for RBS administration and client access
* `user` — Manage RBS users
* `version` — Print the rbs-cli version

###### **Options:**

* `-b`, `--base-url <BASE_URL>` — Base URL of the RBS service
* `-t`, `--token <TOKEN>` — Bearer token used for authenticated requests
* `--cert <CERT>` — CA certificate file used to verify the RBS server
* `-f`, `--format <FORMAT>` — Output format
* `-o`, `--output-file <OUTPUT_FILE>` — Write command output to a file
* `-v`, `--verbose` — Enable verbose output
* `-q`, `--quiet` — Suppress non-essential output
* `--noout` — Do not print command output



## `rbs-cli cert`

Manage GTA certificates and CRLs through RBS

**Usage:** `rbs-cli cert <COMMAND>`

###### **Subcommands:**

* `list` — List certs or CRLs
* `get` — Get one cert or CRL by ID
* `create` — Create a cert or CRL
* `update` — Update a cert
* `delete` — Delete certs or CRLs



## `rbs-cli cert list`

List current user's certs or CRLs.

**Usage:** `rbs-cli cert list [OPTIONS]`

###### **Options:**

* `--ids <IDS>` — Comma-separated cert or CRL IDs; at most 10 IDs and 500 characters total
* `-t`, `--cert-type <CERT_TYPE>` — Filter by cert type; use `crl` to query CRLs

  Possible values: `refvalue`, `policy`, `tpm_boot`, `tpm`, `tpm_ima`, `ascend_npu`, `crl`

* `--limit <LIMIT>` — Page size (1-10; RBS default is 10)
* `--offset <OFFSET>` — Page offset (0-100000; RBS default is 0)



## `rbs-cli cert get`

Get one cert or CRL by ID

**Usage:** `rbs-cli cert get --id <ID>`

###### **Options:**

* `-i`, `--id <ID>` — Cert or CRL ID



## `rbs-cli cert create`

Create a normal cert or a CRL.

**Usage:** `rbs-cli cert create [OPTIONS] --name <NAME> --type <CERT_TYPE>`

###### **Options:**

* `-n`, `--name <NAME>` — Cert or CRL name
* `-d`, `--description <DESCRIPTION>` — Optional description
* `-t`, `--type <CERT_TYPE>` — Cert type list. `crl` must be used alone
* `-c`, `--content <CONTENT>` — Normal cert content or @file path; required for non-CRL certs
* `--crl-content <CRL_CONTENT>` — CRL content or @file path; required when --type crl
* `--is-default <IS_DEFAULT>` — Whether to mark this cert as default



## `rbs-cli cert update`

Update cert metadata. At least one updatable field must be provided.

**Usage:** `rbs-cli cert update [OPTIONS] --id <ID>`

###### **Options:**

* `-i`, `--id <ID>` — Cert ID
* `-n`, `--name <NAME>` — New cert name
* `-d`, `--description <DESCRIPTION>` — New description
* `-t`, `--type <CERT_TYPE>` — New cert type list; `crl` is not supported here
* `--is-default <IS_DEFAULT>` — Whether to mark this cert as default



## `rbs-cli cert delete`

Delete certs by id, by type, or delete all certs. CRL deletion uses --type crl and optional --ids.

**Usage:** `rbs-cli cert delete [OPTIONS]`

###### **Options:**

* `--delete-type <DELETE_TYPE>` — Delete mode for normal certs: id, type, or all

  Possible values: `id`, `type`, `all`

* `--ids <IDS>` — Comma-separated cert or CRL IDs; at most 10 IDs and 500 characters total
* `-t`, `--type <CERT_TYPE>` — Cert type for delete-by-type, or `crl` for CRL deletion

  Possible values: `refvalue`, `policy`, `tpm_boot`, `tpm`, `tpm_ima`, `ascend_npu`, `crl`




## `rbs-cli client`

Run attestation and protected-resource client commands

**Usage:** `rbs-cli client <COMMAND>`

###### **Subcommands:**

* `challenge` — Request an authentication nonce from the RBS server
* `collect-evidence` — Collect local evidence using the attestation agent
* `get-token` — Obtain an attestation token via the configured token provider
* `get-resource` — Fetch a protected resource using a token or evidence



## `rbs-cli client challenge`

Request an authentication nonce from the RBS server

**Usage:** `rbs-cli client challenge [OPTIONS]`

###### **Options:**

* `--agent-config <AGENT_CONFIG>` — Path to the attestation agent config file

  Default value: `/etc/attestation_agent/agent_config.yaml`



## `rbs-cli client collect-evidence`

Collect local evidence using the attestation agent

**Usage:** `rbs-cli client collect-evidence [OPTIONS] --nonce <NONCE> --attester-pubkey <ATTESTER_PUBKEY>`

###### **Options:**

* `--agent-config <AGENT_CONFIG>` — Path to the attestation agent config file

  Default value: `/etc/attestation_agent/agent_config.yaml`
* `--nonce <NONCE>` — Nonce to embed in collected evidence
* `--attester-pubkey <ATTESTER_PUBKEY>` — Attester public key used to populate tee-pubkey in runtime data
* `--attester-data <ATTESTER_DATA>` — Attester-data JSON or @file path merged into the request
* `--runtime-data <RUNTIME_DATA>` — Runtime data entry in key=value form; repeat to add multiple entries



## `rbs-cli client get-token`

Obtain an attestation token via the configured token provider

**Usage:** `rbs-cli client get-token [OPTIONS] <--evidence <EVIDENCE>|--attester-pubkey <ATTESTER_PUBKEY>>`

###### **Options:**

* `--agent-config <AGENT_CONFIG>` — Path to the attestation agent config file

  Default value: `/etc/attestation_agent/agent_config.yaml`
* `--attester-pubkey <ATTESTER_PUBKEY>` — Attester public key used to populate tee-pubkey in runtime data
* `--attester-data <ATTESTER_DATA>` — Attester-data JSON or @file path merged into the request
* `--runtime-data <RUNTIME_DATA>` — Runtime data entry in key=value form; repeat to add multiple entries
* `--evidence <EVIDENCE>` — Evidence JSON or @file path



## `rbs-cli client get-resource`

Fetch a protected resource using a token or evidence

**Usage:** `rbs-cli client get-resource [OPTIONS] --uri <URI> <--attest-token <ATTEST_TOKEN>|--evidence <EVIDENCE>|--passport|--background>`

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



## `rbs-cli policy`

Manage GTA attestation policies through RBS

**Usage:** `rbs-cli policy <COMMAND>`

###### **Subcommands:**

* `list` — List policies
* `get` — Get one attestation policy by ID
* `create` — Create a policy
* `update` — Update a policy
* `delete` — Delete policies



## `rbs-cli policy list`

List current user's policies.

**Usage:** `rbs-cli policy list [OPTIONS]`

###### **Options:**

* `--ids <IDS>` — Comma-separated policy IDs; at most 10 IDs and 500 characters total
* `-t`, `--attester-type <ATTESTER_TYPE>` — Attester type filter
* `--limit <LIMIT>` — Page size (1-10; RBS default is 10)
* `--offset <OFFSET>` — Page offset (0-100000; RBS default is 0)



## `rbs-cli policy get`

Get one attestation policy by ID

**Usage:** `rbs-cli policy get --id <ID>`

###### **Options:**

* `--id <ID>` — Policy ID



## `rbs-cli policy create`

Create a policy.
For content_type=text, content must be base64 encoded policy text.
For content_type=jwt, content must be a full JWT string.
Use @file to read content from a file.

**Usage:** `rbs-cli policy create [OPTIONS] --name <NAME> --attester-type <ATTESTER_TYPE> --content <CONTENT>`

###### **Options:**

* `--name <NAME>` — Policy name
* `--description <DESCRIPTION>` — Optional description
* `-t`, `--attester-type <ATTESTER_TYPE>` — Applicable attester types
* `--content-type <CONTENT_TYPE>` — Policy content type: text or jwt

  Default value: `text`

  Possible values: `text`, `jwt`

* `--content <CONTENT>` — Policy content or @file path; text expects base64 policy text
* `--is-default <IS_DEFAULT>` — Whether to mark this policy as default

  Possible values: `true`, `false`




## `rbs-cli policy update`

Update a policy. At least one updatable field must be provided.
If content is set, content_type must also be set.

**Usage:** `rbs-cli policy update [OPTIONS] --id <ID>`

###### **Options:**

* `--id <ID>` — Policy ID
* `--name <NAME>` — New policy name
* `--description <DESCRIPTION>` — New description
* `-t`, `--attester-type <ATTESTER_TYPE>` — New attester type list
* `--content-type <CONTENT_TYPE>` — New content type: text or jwt

  Possible values: `text`, `jwt`

* `--content <CONTENT>` — New policy content or @file path
* `--is-default <IS_DEFAULT>` — Whether to mark this policy as default

  Possible values: `true`, `false`




## `rbs-cli policy delete`

Delete policies by id, by attester type, or delete all policies.

**Usage:** `rbs-cli policy delete [OPTIONS] --delete-type <DELETE_TYPE>`

###### **Options:**

* `--delete-type <DELETE_TYPE>` — Delete mode: id, attester_type, or all

  Possible values: `id`, `attester_type`, `all`

* `--ids <IDS>` — Comma-separated policy IDs; at most 10 IDs and 500 characters total; required when --delete-type id
* `-t`, `--attester-type <ATTESTER_TYPE>` — Attester type; required when --delete-type attester_type



## `rbs-cli ref-value`

Manage GTA reference-value baselines through RBS

**Usage:** `rbs-cli ref-value <COMMAND>`

###### **Subcommands:**

* `list` — List ref values
* `get` — Get one ref value by ID
* `create` — Create a ref value
* `update` — Update a ref value
* `delete` — Delete ref values



## `rbs-cli ref-value list`

List current user's ref values.

**Usage:** `rbs-cli ref-value list [OPTIONS]`

###### **Options:**

* `--ids <IDS>` — Comma-separated ref value IDs; at most 10 IDs and 500 characters total
* `-t`, `--attester-type <ATTESTER_TYPE>` — Attester type filter
* `--limit <LIMIT>` — Page size (1-10; RBS default is 10)
* `--offset <OFFSET>` — Page offset (0-100000; RBS default is 0)



## `rbs-cli ref-value get`

Get one ref value by ID

**Usage:** `rbs-cli ref-value get --id <ID>`

###### **Options:**

* `--id <ID>` — Ref value ID



## `rbs-cli ref-value create`

Create a ref value. Content may be a JWT or Base64 payload. Use @file to read content from a file.

**Usage:** `rbs-cli ref-value create [OPTIONS] --name <NAME> --attester-type <ATTESTER_TYPE> --content <CONTENT>`

###### **Options:**

* `--name <NAME>` — Ref value name
* `--description <DESCRIPTION>` — Optional description
* `-t`, `--attester-type <ATTESTER_TYPE>` — Attester type: tpm, tpm_ima, virt_cca, or ascend_npu
* `--content <CONTENT>` — JWT or Base64 content, or @file path; size must be between 1 byte and 10 MiB
* `--content-type <CONTENT_TYPE>` — Reference value content encoding: jwt or base64

  Default value: `jwt`

  Possible values: `jwt`, `base64`




## `rbs-cli ref-value update`

Update a ref value. At least one updatable field must be provided. Content may be a JWT or Base64 payload.

**Usage:** `rbs-cli ref-value update [OPTIONS] --id <ID>`

###### **Options:**

* `--id <ID>` — Ref value ID
* `--name <NAME>` — New ref value name
* `--description <DESCRIPTION>` — New description
* `-t`, `--attester-type <ATTESTER_TYPE>` — New attester type
* `--content <CONTENT>` — New JWT or Base64 content, or @file path; size must be between 1 byte and 10 MiB
* `--content-type <CONTENT_TYPE>` — New reference value content encoding: jwt or base64

  Possible values: `jwt`, `base64`




## `rbs-cli ref-value delete`

Delete ref values by id, by attester type, or delete all ref values.

**Usage:** `rbs-cli ref-value delete [OPTIONS] --delete-type <DELETE_TYPE>`

###### **Options:**

* `--delete-type <DELETE_TYPE>` — Delete mode: all, id, or type

  Possible values: `all`, `id`, `type`

* `--ids <IDS>` — Comma-separated ref value IDs; at most 10 IDs and 500 characters total; required when --delete-type id
* `-t`, `--attester-type <ATTESTER_TYPE>` — Attester type; required when --delete-type type



## `rbs-cli res`

Manage key, secret, and cert resources

**Usage:** `rbs-cli res <COMMAND>`

###### **Subcommands:**

* `get` — Get and decrypt resource content
* `get-res-info` — Get resource metadata
* `create` — Create a resource binding
* `update` — Update a resource binding
* `delete` — Delete a resource



## `rbs-cli res get`

Get resource content and decrypt the JWE payload with a private key.

Example:
  rbs-cli res get --uri vault/default/secret/my-secret --private-key-file tee-private.pem

**Usage:** `rbs-cli res get [OPTIONS] --uri <URI> --private-key-file <PRIVATE_KEY_FILE>`

###### **Options:**

* `--uri <URI>` — Resource URI in provider/repository/type/name form
* `--private-key-file <PRIVATE_KEY_FILE>` — Path to the PEM private key used to decrypt the resource JWE
* `--private-key-passphrase <@PATH>` — Read the private key passphrase interactively or from @PATH



## `rbs-cli res get-res-info`

Get resource metadata without returning resource content.

Example:
  rbs-cli res get-res-info --uri vault/default/secret/my-secret

**Usage:** `rbs-cli res get-res-info --uri <URI>`

###### **Options:**

* `--uri <URI>` — Resource URI in provider/repository/type/name form



## `rbs-cli res create`

Create resource metadata for a key, secret, or cert resource.

Example:
  rbs-cli res create --uri vault/default/secret/my-secret --policy-id policy-1 --content-type text --export-mode jwe

With --content, the Base64-decoded payload is stored in backends that support writes (e.g. HSM):
  rbs-cli res create --uri hsm/default/key/my-key --policy-id policy-1 --content-type binary --content @key.b64

**Usage:** `rbs-cli res create [OPTIONS] --uri <URI> --policy-id <POLICY_ID>`

###### **Options:**

* `--uri <URI>` — Resource URI in provider/repository/type/name form
* `--policy-id <POLICY_ID>` — Bound resource policy ID
* `--additional-info <ADDITIONAL_INFO>` — Optional Base64 additional_info value or @file path
* `--content <CONTENT>` — Optional Base64 content value or @file path; raw content is Base64-encoded automatically
* `--content-type <CONTENT_TYPE>` — Resource content type: jwt, json, text, binary, jwk, or jwe

  Possible values: `jwt`, `json`, `text`, `binary`, `jwk`, `jwe`

* `--export-mode <EXPORT_MODE>` — Export mode: jwe

  Possible values: `jwe`




## `rbs-cli res update`

Update resource metadata for a key, secret, or cert resource.

Example:
  rbs-cli res update --uri vault/default/secret/my-secret --policy-id policy-1 --content-type text --export-mode jwe

With --content, the Base64-decoded payload replaces the stored value in backends that support writes (e.g. HSM):
  rbs-cli res update --uri hsm/default/key/my-key --content-type binary --content @key.b64

**Usage:** `rbs-cli res update [OPTIONS] --uri <URI>`

###### **Options:**

* `--uri <URI>` — Resource URI in provider/repository/type/name form
* `--policy-id <POLICY_ID>` — New policy ID to rebind the resource to; omit to keep the current binding
* `--additional-info <ADDITIONAL_INFO>` — Optional Base64 additional_info value or @file path
* `--content <CONTENT>` — Optional Base64 content value or @file path; raw content is Base64-encoded automatically
* `--content-type <CONTENT_TYPE>` — Resource content type: jwt, json, text, binary, jwk, or jwe

  Possible values: `jwt`, `json`, `text`, `binary`, `jwk`, `jwe`

* `--export-mode <EXPORT_MODE>` — Export mode: jwe

  Possible values: `jwe`




## `rbs-cli res delete`

Delete a key, secret, or cert resource.

Example:
  rbs-cli res delete --uri vault/default/secret/my-secret

**Usage:** `rbs-cli res delete --uri <URI>`

###### **Options:**

* `--uri <URI>` — Resource URI in provider/repository/type/name form



## `rbs-cli res-policy`

Manage resource access policies

**Usage:** `rbs-cli res-policy <COMMAND>`

###### **Subcommands:**

* `list` — List resource policies
* `get` — Get a resource policy
* `create` — Create a resource policy
* `update` — Update a resource policy
* `delete` — Delete resource policies



## `rbs-cli res-policy list`

List resource policies with optional ID and pagination filters.

Example:
  rbs-cli res-policy list --ids policy-1,policy-2 --limit 10 --offset 0

**Usage:** `rbs-cli res-policy list [OPTIONS]`

###### **Options:**

* `--ids <IDS>` — Comma-separated resource policy IDs
* `--limit <LIMIT>` — Page size (1-100; RBS default is 10)
* `--offset <OFFSET>` — Page offset (0-100000; RBS default is 0)



## `rbs-cli res-policy get`

Get one resource policy by ID.

Example:
  rbs-cli res-policy get policy-1

**Usage:** `rbs-cli res-policy get --id <ID>`

###### **Options:**

* `--id <ID>` — Resource policy ID



## `rbs-cli res-policy create`

Create a resource policy. Use @file to read Base64 policy content from a file.

Example:
  rbs-cli res-policy create --name allow-secret --content @policy.txt --content-type base64

**Usage:** `rbs-cli res-policy create [OPTIONS] --name <NAME> --content <CONTENT>`

###### **Options:**

* `--name <NAME>` — Resource policy name
* `--content <CONTENT>` — Base64 policy content or @file path; raw content is Base64-encoded automatically
* `--content-type <CONTENT_TYPE>` — Policy content type

  Default value: `base64`

  Possible values: `base64`




## `rbs-cli res-policy update`

Replace a resource policy by ID.

Example:
  rbs-cli res-policy update policy-1 --name allow-secret-v2 --content @policy.txt --content-type base64

**Usage:** `rbs-cli res-policy update [OPTIONS] --id <ID> --name <NAME> --content <CONTENT>`

###### **Options:**

* `--id <ID>` — Resource policy ID
* `--name <NAME>` — Resource policy name
* `--content <CONTENT>` — Base64 policy content or @file path; raw content is Base64-encoded automatically
* `--content-type <CONTENT_TYPE>` — Policy content type

  Default value: `base64`

  Possible values: `base64`




## `rbs-cli res-policy delete`

Delete one resource policy by ID or multiple policies with --ids.

Example:
  rbs-cli res-policy delete --id policy-1
  rbs-cli res-policy delete --ids policy-1,policy-2

**Usage:** `rbs-cli res-policy delete <--id <ID>|--ids <IDS>>`

###### **Options:**

* `--id <ID>` — Single resource policy ID
* `--ids <IDS>` — Comma-separated resource policy IDs



## `rbs-cli token`

Generate signed JWT tokens for RBS administration and client access

**Usage:** `rbs-cli token <COMMAND>`

###### **Subcommands:**

* `gen` — Generate a JWT from a private key and claim inputs



## `rbs-cli token gen`

Generate a signed JWT using a PEM private key. Standard claims such as iss, sub, aud, exp, nbf, iat, and jti can be set explicitly, and extra custom claims can be merged from JSON input.

**Usage:** `rbs-cli token gen [OPTIONS] --private-key-file <PRIVATE_KEY_FILE>`

###### **Options:**

* `--private-key-file <PRIVATE_KEY_FILE>` — Path to the PEM private key used for signing
* `--private-key-passphrase <@PATH>` — Read the private key passphrase interactively or from @PATH
* `--iss <ISS>` — JWT issuer claim

  Default value: `rbs-cli`
* `--sub <SUB>` — Username stored in the JWT sub claim

  Default value: `Administrator`
* `--aud <AUD>` — JWT audience claim; repeat to add multiple audiences

  Default value: `globaltrustauthority-rbs`
* `--exp <EXP>` — JWT expiration time as a Unix timestamp in seconds
* `--nbf <NBF>` — JWT not-before time as a Unix timestamp in seconds
* `--iat <IAT>` — JWT issued-at time as a Unix timestamp in seconds
* `--jti <JTI>` — JWT ID claim
* `--alg <ALG>` — Signing algorithm; defaults to a value inferred from the private key

  Possible values: `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`, `EdDSA`, `SM2`

* `--kid <KID>` — JWT header key ID
* `--claims <CLAIMS>` — Additional custom claims as JSON text or @file path



## `rbs-cli user`

Manage RBS users

**Usage:** `rbs-cli user <COMMAND>`

###### **Subcommands:**

* `list` — List users with pagination
* `get` — Get one user by username
* `create` — Create a user with a public key or JWK
* `update` — Update a user's role, enabled flag, or key material
* `delete` — Delete a user by username



## `rbs-cli user list`

List users with pagination

**Usage:** `rbs-cli user list [OPTIONS]`

###### **Options:**

* `--limit <LIMIT>` — Maximum number of users to return
* `--offset <OFFSET>` — Pagination offset



## `rbs-cli user get`

Get one user by username

**Usage:** `rbs-cli user get --username <USERNAME>`

###### **Options:**

* `-u`, `--username <USERNAME>` — Username to query



## `rbs-cli user create`

Create a user with a public key or JWK

**Usage:** `rbs-cli user create [OPTIONS] --username <USERNAME> <--public-key <PUBLIC_KEY>|--jwk <JWK>>`

###### **Options:**

* `--username <USERNAME>` — Username to create
* `--role <ROLE>` — User role

  Default value: `user`

  Possible values: `user`, `admin`

* `--enabled <ENABLED>` — Whether the user is enabled after creation

  Possible values: `true`, `false`

* `--public-key <PUBLIC_KEY>` — PEM public key or @file path
* `--jwk <JWK>` — JWK JSON or @file path



## `rbs-cli user update`

Update a user's role, enabled flag, or key material

**Usage:** `rbs-cli user update [OPTIONS] --username <USERNAME>`

###### **Options:**

* `-u`, `--username <USERNAME>` — Username to update
* `--role <ROLE>` — New user role

  Possible values: `user`, `admin`

* `--enabled <ENABLED>` — Whether the user is enabled

  Possible values: `true`, `false`

* `--public-key <PUBLIC_KEY>` — PEM public key or @file path
* `--jwk <JWK>` — JWK JSON or @file path



## `rbs-cli user delete`

Delete a user by username

**Usage:** `rbs-cli user delete --username <USERNAME>`

###### **Options:**

* `-u`, `--username <USERNAME>` — Username to delete



## `rbs-cli version`

Print the rbs-cli version

**Usage:** `rbs-cli version`



<hr/>

<small><i>
    This document was generated automatically by
    <a href="https://crates.io/crates/clap-markdown"><code>clap-markdown</code></a>.
</i></small>
