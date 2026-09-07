# RBS REST API

API version: `0` · OpenAPI: `3.1.0`

Resource Broker Service (RBS) HTTP API.

License: [Mulan Permissive Software License, Version 2](http://license.coscl.org.cn/MulanPSL2)

## Servers

| URL | Description |
|---|---|
| `http://localhost:6666` | Default local development (see `rbs.yaml` `rest.listen_addr`) |

## Authentication

- **attestAuth** — HTTP bearer token (Attest). Attest token. Send as `Authorization: Attest <token>`. Obtain via `POST /rbs/v0/attest`.
- **bearerAuth** — HTTP bearer token (JWT). JWT Bearer token. Send as `Authorization: Bearer <token>`. Obtain via Admin API or attestation.

## Endpoints

| Method | Path | Summary |
|---|---|---|
| POST | [`/rbs/v0/attest`](#post-rbsv0attest) | Submit attestation evidence and obtain token |
| GET | [`/rbs/v0/attestation/cert`](#get-rbsv0attestationcert) | List certificates (default provider) |
| PUT | [`/rbs/v0/attestation/cert`](#put-rbsv0attestationcert) | Update a certificate (default provider) |
| POST | [`/rbs/v0/attestation/cert`](#post-rbsv0attestationcert) | Create a certificate (default provider) |
| DELETE | [`/rbs/v0/attestation/cert`](#delete-rbsv0attestationcert) | Batch delete certificates (default provider) |
| GET | [`/rbs/v0/attestation/cert/{id}`](#get-rbsv0attestationcertid) | Get a single certificate (default provider) |
| DELETE | [`/rbs/v0/attestation/cert/{id}`](#delete-rbsv0attestationcertid) | Delete a single certificate (default provider) |
| GET | [`/rbs/v0/attestation/policy`](#get-rbsv0attestationpolicy) | List attestation policies (default provider) |
| PUT | [`/rbs/v0/attestation/policy`](#put-rbsv0attestationpolicy) | Update an attestation policy (default provider) |
| POST | [`/rbs/v0/attestation/policy`](#post-rbsv0attestationpolicy) | Create an attestation policy (default provider) |
| DELETE | [`/rbs/v0/attestation/policy`](#delete-rbsv0attestationpolicy) | Batch delete attestation policies (default provider) |
| GET | [`/rbs/v0/attestation/policy/{id}`](#get-rbsv0attestationpolicyid) | Get a single attestation policy (default provider) |
| DELETE | [`/rbs/v0/attestation/policy/{id}`](#delete-rbsv0attestationpolicyid) | Delete a single attestation policy (default provider) |
| GET | [`/rbs/v0/attestation/ref_value`](#get-rbsv0attestationref_value) | List reference value baselines (default provider) |
| PUT | [`/rbs/v0/attestation/ref_value`](#put-rbsv0attestationref_value) | Update a reference value baseline (default provider) |
| POST | [`/rbs/v0/attestation/ref_value`](#post-rbsv0attestationref_value) | Create a reference value baseline (default provider) |
| DELETE | [`/rbs/v0/attestation/ref_value`](#delete-rbsv0attestationref_value) | Batch delete reference value baselines (default provider) |
| GET | [`/rbs/v0/attestation/ref_value/{id}`](#get-rbsv0attestationref_valueid) | Get a single reference value baseline (default provider) |
| DELETE | [`/rbs/v0/attestation/ref_value/{id}`](#delete-rbsv0attestationref_valueid) | Delete a single reference value baseline (default provider) |
| GET | [`/rbs/v0/attestation/{as_provider}/cert`](#get-rbsv0attestationas_providercert) | List certificates |
| PUT | [`/rbs/v0/attestation/{as_provider}/cert`](#put-rbsv0attestationas_providercert) | Update a certificate |
| POST | [`/rbs/v0/attestation/{as_provider}/cert`](#post-rbsv0attestationas_providercert) | Create a certificate |
| DELETE | [`/rbs/v0/attestation/{as_provider}/cert`](#delete-rbsv0attestationas_providercert) | Batch delete certificates |
| GET | [`/rbs/v0/attestation/{as_provider}/cert/{id}`](#get-rbsv0attestationas_providercertid) | Get a single certificate |
| DELETE | [`/rbs/v0/attestation/{as_provider}/cert/{id}`](#delete-rbsv0attestationas_providercertid) | Delete a single certificate |
| GET | [`/rbs/v0/attestation/{as_provider}/policy`](#get-rbsv0attestationas_providerpolicy) | List attestation policies |
| PUT | [`/rbs/v0/attestation/{as_provider}/policy`](#put-rbsv0attestationas_providerpolicy) | Update an attestation policy |
| POST | [`/rbs/v0/attestation/{as_provider}/policy`](#post-rbsv0attestationas_providerpolicy) | Create an attestation policy |
| DELETE | [`/rbs/v0/attestation/{as_provider}/policy`](#delete-rbsv0attestationas_providerpolicy) | Batch delete attestation policies |
| GET | [`/rbs/v0/attestation/{as_provider}/policy/{id}`](#get-rbsv0attestationas_providerpolicyid) | Get a single attestation policy |
| DELETE | [`/rbs/v0/attestation/{as_provider}/policy/{id}`](#delete-rbsv0attestationas_providerpolicyid) | Delete a single attestation policy |
| GET | [`/rbs/v0/attestation/{as_provider}/ref_value`](#get-rbsv0attestationas_providerref_value) | List reference value baselines |
| PUT | [`/rbs/v0/attestation/{as_provider}/ref_value`](#put-rbsv0attestationas_providerref_value) | Update a reference value baseline |
| POST | [`/rbs/v0/attestation/{as_provider}/ref_value`](#post-rbsv0attestationas_providerref_value) | Create a reference value baseline |
| DELETE | [`/rbs/v0/attestation/{as_provider}/ref_value`](#delete-rbsv0attestationas_providerref_value) | Batch delete reference value baselines |
| GET | [`/rbs/v0/attestation/{as_provider}/ref_value/{id}`](#get-rbsv0attestationas_providerref_valueid) | Get a single reference value baseline |
| DELETE | [`/rbs/v0/attestation/{as_provider}/ref_value/{id}`](#delete-rbsv0attestationas_providerref_valueid) | Delete a single reference value baseline |
| GET | [`/rbs/v0/challenge`](#get-rbsv0challenge) | Obtain an attestation challenge (nonce) |
| GET | [`/rbs/v0/resource/policy`](#get-rbsv0resourcepolicy) | List policies |
| POST | [`/rbs/v0/resource/policy`](#post-rbsv0resourcepolicy) | Create a policy |
| DELETE | [`/rbs/v0/resource/policy`](#delete-rbsv0resourcepolicy) | Batch delete policies |
| GET | [`/rbs/v0/resource/policy/{policy_id}`](#get-rbsv0resourcepolicypolicy_id) | Get policy detail |
| PUT | [`/rbs/v0/resource/policy/{policy_id}`](#put-rbsv0resourcepolicypolicy_id) | Update a policy |
| DELETE | [`/rbs/v0/resource/policy/{policy_id}`](#delete-rbsv0resourcepolicypolicy_id) | Delete a policy |
| GET | [`/rbs/v0/users`](#get-rbsv0users) | List users (admin only) |
| POST | [`/rbs/v0/users`](#post-rbsv0users) | Create a user (admin only) |
| GET | [`/rbs/v0/users/{username}`](#get-rbsv0usersusername) | Get a user (admin or self) |
| PUT | [`/rbs/v0/users/{username}`](#put-rbsv0usersusername) | Update a user (admin or self) |
| DELETE | [`/rbs/v0/users/{username}`](#delete-rbsv0usersusername) | Delete a user (admin only) |
| GET | [`/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}`](#get-rbsv0res_providerrepository_nameresource_typeresource_name) | Get resource content |
| PUT | [`/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}`](#put-rbsv0res_providerrepository_nameresource_typeresource_name) | Update or create resource |
| POST | [`/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}`](#post-rbsv0res_providerrepository_nameresource_typeresource_name) | Create resource |
| DELETE | [`/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}`](#delete-rbsv0res_providerrepository_nameresource_typeresource_name) | Delete resource |
| GET | [`/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/info`](#get-rbsv0res_providerrepository_nameresource_typeresource_nameinfo) | Get resource metadata |
| POST | [`/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/retrieve`](#post-rbsv0res_providerrepository_nameresource_typeresource_nameretrieve) | Retrieve resource with attestation evidence |
| GET | [`/rbs/version`](#get-rbsversion) | Get service name, API version, and build metadata |

## System

`RbsCore::system` — service identity and API/build version via `GET /rbs/version` (system metadata). Does not require authentication.

### GET /rbs/version

**Get service name, API version, and build metadata**

Return the service name, API contract version, and build metadata (version, git hash, build time). No authentication required.

Operation ID: `rbsVersion`

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Version payload: service name, API contract version, and build metadata (JSON). | [RbsVersion](#rbsversion) |

Example response (200):

```json
{
  "service_name": "globaltrustauthority-rbs",
  "api_version": "0",
  "build": {
    "version": "0.1.0",
    "git_hash": "",
    "build_date": ""
  }
}
```

## Admin

User management CRUD — `GET/POST/PUT/DELETE /rbs/v0/users` (admin or self). Requires BearerToken.

### GET /rbs/v0/users

**List users (admin only)**

List users with pagination and optional `role` / `enabled` filters, ordered by username. Requires an enabled admin Bearer token.

Operation ID: `listUsers`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `limit` | query | integer(int64) | no | Page size (1..100, default 10). |
| `offset` | query | integer(int64) | no | Offset (0..100000, default 0). |
| `role` | query | [Role](#role) | no | Filter by role (admin or user). |
| `enabled` | query | boolean | no | Filter by enabled status. |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Paginated user list | [UserListResponse](#userlistresponse) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "users": [
    {
      "id": "string",
      "username": "string",
      "role": "admin",
      "enabled": true,
      "created_at": "string",
      "updated_at": "string"
    }
  ],
  "total_count": 0,
  "limit": 0,
  "offset": 0
}
```

### POST /rbs/v0/users

**Create a user (admin only)**

Create a user with authentication key material. Only the `user` role can be assigned here — the `admin` role is pre-configured and rejected (400). Exactly one of `public_key` / `jwk` is required (they are mutually exclusive). `username` is immutable after creation; 409 when it already exists or the configured `max_users` quota is reached.

Operation ID: `createUser`

Security: **bearerAuth**

#### Request Body

Content type: `application/json` · Required: yes

New user record: username, optional role/enabled, auth type, and exactly one of `public_key` or `jwk`.

Schema: [UserCreateRequest](#usercreaterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `username` | string | yes | Login or unique handle. Immutable. |
| `role` | [Role](#role) | no | Optional role; only `user` is allowed via API (admin is pre-configured). |
| `enabled` | boolean | no | Whether the account is enabled. |
| `auth_type` | [AuthType](#authtype) | yes | Authentication method; currently only `jwt` is supported. |
| `public_key` | string | no | Base64-encoded PEM public key (mutually exclusive with `jwk`). |
| `jwk` | any | no | JWK public key JSON object (mutually exclusive with `public_key`). |

Example request:

```json
{
  "username": "string",
  "role": null,
  "enabled": true,
  "auth_type": "jwt",
  "public_key": "string",
  "jwk": null
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 201 | User created | [UserResponse](#userresponse) |
| 400 | Invalid request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 409 | Username already exists | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |

Example response (201):

```json
{
  "id": "string",
  "username": "string",
  "role": "admin",
  "enabled": true,
  "created_at": "string",
  "updated_at": "string"
}
```

### GET /rbs/v0/users/{username}

**Get a user (admin or self)**

Fetch one user by username. Admins may fetch any user; non-admin callers may only fetch themselves (403 otherwise).

Operation ID: `getUser`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `username` | path | string | yes | Username |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | User found | [UserResponse](#userresponse) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | User not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "id": "string",
  "username": "string",
  "role": "admin",
  "enabled": true,
  "created_at": "string",
  "updated_at": "string"
}
```

### PUT /rbs/v0/users/{username}

**Update a user (admin or self)**

Update a user; at least one field is required and `username` itself is immutable (path parameter only). Non-admin self-updates may only change key material (`public_key` / `jwk`) and `auth_type` — a changed `role` or `enabled: false` is rejected with 403. The `admin` role is not API-assignable, and the built-in Administrator's `role` / `enabled` cannot be changed.

Operation ID: `updateUser`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `username` | path | string | yes | Username |

#### Request Body

Content type: `application/json` · Required: yes

Fields to update; at least one required. `public_key` and `jwk` are mutually exclusive.

Schema: [UserUpdateRequest](#userupdaterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `role` | [Role](#role) | no | New role; only the target's current role is accepted — any other value is rejected with 403. |
| `enabled` | boolean | no | Whether the account can authenticate. |
| `auth_type` | [AuthType](#authtype) | no | New authentication method; currently only `jwt` is supported. |
| `public_key` | string | no | Base64-encoded PEM public key (mutually exclusive with `jwk`). |
| `jwk` | any | no | JWK public key JSON object (mutually exclusive with `public_key`). |

Example request:

```json
{
  "role": null,
  "enabled": true,
  "auth_type": null,
  "public_key": "string",
  "jwk": null
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | User updated | [UserResponse](#userresponse) |
| 400 | Invalid request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden — caller is neither admin nor self; a non-admin self-update attempted to change `role`/`enabled`; an attempt to modify the built-in Administrator's `role`/`enabled`; or an attempt to assign the `admin` role (pre-configured, no-op on the built-in admin only) | [ErrorBody](#errorbody) |
| 404 | User not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "id": "string",
  "username": "string",
  "role": "admin",
  "enabled": true,
  "created_at": "string",
  "updated_at": "string"
}
```

### DELETE /rbs/v0/users/{username}

**Delete a user (admin only)**

Delete a user. Admin only; self-deletion is rejected with 403. Blocked with 409 while the user still owns policies or resources — delete those first.

Operation ID: `deleteUser`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `username` | path | string | yes | Username |

#### Responses

| Status | Description | Content |
|---|---|---|
| 204 | User deleted (no body) | — |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | User not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |

## Policy

Policy CRUD — `GET/POST/PUT/DELETE /rbs/v0/resource/policy`. Requires BearerToken.

### GET /rbs/v0/resource/policy

**List policies**

List the caller's own policies with optional `ids` filter and pagination; policies are user-scoped and other users' policies are never returned. When `ids` is present, only those are returned and pagination is ignored.

Operation ID: `listPolicies`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `ids` | query | string | no | Comma-separated policy IDs (UUIDs); when present, only these are returned and pagination is ignored. |
| `limit` | query | integer(int64) | no | Page size (1..100, default 10). |
| `offset` | query | integer(int64) | no | Offset (0..100000, default 0). |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Policy list | [PolicyListResponse](#policylistresponse) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "items": [
    {
      "policy_id": "string",
      "policy_name": "string",
      "policy_version": 0,
      "content_type": "string",
      "created_at": "string",
      "updated_at": "string",
      "applied_resources": [
        "string"
      ]
    }
  ],
  "total_count": 0,
  "limit": 0,
  "offset": 0
}
```

### POST /rbs/v0/resource/policy

**Create a policy**

Create a policy owned by the caller. `content` must be base64-encoded Rego that decodes to valid UTF-8 within the configured size limit; the name must be unique per user. 409 on duplicate name or when the per-user policy quota is reached.

Operation ID: `createPolicy`

Security: **bearerAuth**

#### Request Body

Content type: `application/json` · Required: yes

Policy name, content encoding (`base64`), and base64-encoded Rego content.

Schema: [CreatePolicyRequest](#createpolicyrequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Policy name, unique per user (1-255 chars; `<>\"'&\|\\/*?` and backtick are forbidden). |
| `content_type` | string | yes | Encoding of `content`; only `base64` is supported. |
| `content` | string | yes | Base64-encoded Rego policy text; must decode to valid UTF-8 within the configured size limit. |

Example request:

```json
{
  "name": "string",
  "content_type": "string",
  "content": "string"
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 201 | Policy created | [PolicyResponse](#policyresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 409 | Conflict (name duplicate / count exceeded) | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |

Example response (201):

```json
{
  "policy_id": "string",
  "policy_name": "string",
  "policy_version": 0,
  "content_type": "string",
  "created_at": "string",
  "updated_at": "string",
  "applied_resources": [
    "string"
  ]
}
```

### DELETE /rbs/v0/resource/policy

**Batch delete policies**

Delete up to 10 policies in a single transaction. All IDs must exist and belong to the caller; rejected with 409 (nothing deleted) when any listed policy is still referenced by a resource.

Operation ID: `batchDeletePolicies`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `ids` | query | string | yes | Comma-separated policy IDs (maximum 10 IDs) |

#### Responses

| Status | Description | Content |
|---|---|---|
| 204 | Policies deleted | — |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 409 | Policy is referenced by resources | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |

### GET /rbs/v0/resource/policy/{policy_id}

**Get policy detail**

Fetch a single policy including `applied_resources` (URIs of resources bound to it). User-scoped: 403 when the policy belongs to another user.

Operation ID: `getPolicy`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `policy_id` | path | string | yes | Policy ID |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Policy detail | [PolicyResponse](#policyresponse) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "policy_id": "string",
  "policy_name": "string",
  "policy_version": 0,
  "content_type": "string",
  "created_at": "string",
  "updated_at": "string",
  "applied_resources": [
    "string"
  ]
}
```

### PUT /rbs/v0/resource/policy/{policy_id}

**Update a policy**

Replace a policy (name, content_type, and content are all required — full replacement, not a patch). The version increments on every update; a concurrent update loses the race and fails with 409 (optimistic locking). User-scoped: 403 when owned by another user.

Operation ID: `updatePolicy`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `policy_id` | path | string | yes | Policy ID |

#### Request Body

Content type: `application/json` · Required: yes

Full replacement values: new name, content encoding (`base64`), and base64-encoded Rego content.

Schema: [UpdatePolicyRequest](#updatepolicyrequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | New policy name, unique per user (1-255 chars; `<>\"'&\|\\/*?` and backtick are forbidden). |
| `content_type` | string | yes | New encoding of `content`; only `base64` is supported. |
| `content` | string | yes | New base64-encoded Rego policy text; must decode to valid UTF-8 within the configured size limit. |

Example request:

```json
{
  "name": "string",
  "content_type": "string",
  "content": "string"
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Policy updated | [PolicyResponse](#policyresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 409 | Version conflict | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "policy_id": "string",
  "policy_name": "string",
  "policy_version": 0,
  "content_type": "string",
  "created_at": "string",
  "updated_at": "string",
  "applied_resources": [
    "string"
  ]
}
```

### DELETE /rbs/v0/resource/policy/{policy_id}

**Delete a policy**

Delete one policy owned by the caller. Rejected with 409 while any resource still references the policy — delete or rebind those resources first.

Operation ID: `deletePolicy`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `policy_id` | path | string | yes | Policy ID |

#### Responses

| Status | Description | Content |
|---|---|---|
| 204 | Policy deleted | — |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 409 | Policy is referenced by resources | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |

## Resource

Resource CRUD — `GET/POST/PUT/DELETE /rbs/v0/{provider}/{repo}/{type}/{name}`. Supports AttestToken and BearerToken.

### GET /rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}

**Get resource content**

Read resource content with owner Bearer or attest token authorization; the bound Rego policy is evaluated and `hsm`/`ca` content requires an attest token. The content is always JWE-encrypted to the caller's key (`enc-pubkey` Bearer claim or `tee-pubkey` attest claim) and base64-encoded. Missing and denied reads are collapsed into the same 404.

Operation ID: `getResource`

Security: **bearerAuth**, **attestAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `res_provider` | path | string | yes | Backend provider name; must be configured under `resource.backends` in `rbs.yaml` (e.g. `vault`, `ca`, `hsm`); reserved names (`admin`, `attestation`, `resource`, `health`) are rejected |
| `repository_name` | path | string | yes | Repository name (1-32 chars; only letters, digits, `_` and `-`) |
| `resource_type` | path | string | yes | Resource type; must be in the provider's configured `allowed_resource_types` (e.g. `secret`, `cert`, `key`) |
| `resource_name` | path | string | yes | Resource name (1-32 chars; only letters, digits, `_`, `-` and `.`) |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Resource content (base64-encoded JWE) | [ResourceContentResponse](#resourcecontentresponse) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Resource not found or access denied | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "uri": "string",
  "content": "string",
  "content_type": "string",
  "export_mode": "string"
}
```

### PUT /rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}

**Update or create resource**

Upsert a resource owned by the caller. Omitted optional fields keep their current values; an explicit `policy_id` rebinds the resource (must be caller-owned) while omitting it keeps the current binding — a new resource created via this path requires `policy_id`. Returns 201 when created, 200 when updated, and 409 on a concurrent update (optimistic locking).

Operation ID: `updateResource`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `res_provider` | path | string | yes | Backend provider name; must be configured under `resource.backends` in `rbs.yaml` (e.g. `vault`, `ca`, `hsm`); reserved names (`admin`, `attestation`, `resource`, `health`) are rejected |
| `repository_name` | path | string | yes | Repository name (1-32 chars; only letters, digits, `_` and `-`) |
| `resource_type` | path | string | yes | Resource type; must be in the provider's configured `allowed_resource_types` (e.g. `secret`, `cert`, `key`) |
| `resource_name` | path | string | yes | Resource name (1-32 chars; only letters, digits, `_`, `-` and `.`) |

#### Request Body

Content type: `application/json` · Required: yes

Fields to change; omitted optional fields keep their current values. `policy_id` is required when the upsert creates a new resource.

Schema: [UpdateResourceRequest](#updateresourcerequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `policy_id` | string | no | New policy binding (must be caller-owned); omitted keeps the current binding. Required when the upsert creates a new resource. |
| `content_type` | string | no | New content type label (`jwt`, `json`, `text`, `binary`, `jwk`, `jwe`); omitted keeps the current value. |
| `export_mode` | string | no | New export mode; only `jwe` is accepted; omitted keeps the current value. |
| `additional_info` | string | no | New description (when present, 1-512 chars); omitted keeps the current value. |
| `content` | string | no | Base64-encoded replacement content; omitted leaves the backend content unchanged. |

Example request:

```json
{
  "policy_id": "string",
  "content_type": "string",
  "export_mode": "string",
  "additional_info": "string",
  "content": "string"
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Resource updated | [ResourceResponse](#resourceresponse) |
| 201 | Resource created | [ResourceResponse](#resourceresponse) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 409 | Conflict (version conflict / resource already exists / count exceeded) | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "uri": "string",
  "provider_name": "string",
  "repository_name": "string",
  "resource_type": "string",
  "resource_name": "string",
  "created_at": "string",
  "updated_at": "string",
  "content_type": "string",
  "export_mode": "string",
  "policy_id": "string",
  "additional_info": "string"
}
```

### POST /rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}

**Create resource**

Register a resource owned by the caller. `policy_id` must reference one of the caller's policies and governs reads of this resource. `content` (base64) is stored via the backend when it supports PUT; for CHECK backends the object must already exist; metadata-only backends (e.g. CA) need no content. 409 on duplicate URI or per-user resource quota.

Operation ID: `createResource`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `res_provider` | path | string | yes | Backend provider name; must be configured under `resource.backends` in `rbs.yaml` (e.g. `vault`, `ca`, `hsm`); reserved names (`admin`, `attestation`, `resource`, `health`) are rejected |
| `repository_name` | path | string | yes | Repository name (1-32 chars; only letters, digits, `_` and `-`) |
| `resource_type` | path | string | yes | Resource type; must be in the provider's configured `allowed_resource_types` (e.g. `secret`, `cert`, `key`) |
| `resource_name` | path | string | yes | Resource name (1-32 chars; only letters, digits, `_`, `-` and `.`) |

#### Request Body

Content type: `application/json` · Required: yes

Policy binding (required) plus optional content_type, export_mode, additional_info, and base64-encoded content.

Schema: [CreateResourceRequest](#createresourcerequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `policy_id` | string | yes | UUID of the caller-owned policy that governs reads of this resource. |
| `content_type` | string | no | Content type label; one of `jwt`, `json`, `text`, `binary`, `jwk`, `jwe` (fixed whitelist). |
| `export_mode` | string | no | Export mode on read; only `jwe` is accepted (plaintext export is rejected); defaults to `jwe`. |
| `additional_info` | string | no | Free-form description of the resource; when present, 1-512 chars (empty string rejected). |
| `content` | string | no | Base64-encoded content, stored via the backend when it supports PUT. Optional for backends that generate the object themselves (e.g. CA) or require it to pre-exist. |

Example request:

```json
{
  "policy_id": "string",
  "content_type": "string",
  "export_mode": "string",
  "additional_info": "string",
  "content": "string"
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 201 | Resource created | [ResourceResponse](#resourceresponse) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 409 | Conflict (resource already exists / count exceeded) | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |

Example response (201):

```json
{
  "uri": "string",
  "provider_name": "string",
  "repository_name": "string",
  "resource_type": "string",
  "resource_name": "string",
  "created_at": "string",
  "updated_at": "string",
  "content_type": "string",
  "export_mode": "string",
  "policy_id": "string",
  "additional_info": "string"
}
```

### DELETE /rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}

**Delete resource**

Delete a resource owned by the caller. The backend object is removed first (when the backend supports DELETE), then the DB record.

Operation ID: `deleteResource`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `res_provider` | path | string | yes | Backend provider name; must be configured under `resource.backends` in `rbs.yaml` (e.g. `vault`, `ca`, `hsm`); reserved names (`admin`, `attestation`, `resource`, `health`) are rejected |
| `repository_name` | path | string | yes | Repository name (1-32 chars; only letters, digits, `_` and `-`) |
| `resource_type` | path | string | yes | Resource type; must be in the provider's configured `allowed_resource_types` (e.g. `secret`, `cert`, `key`) |
| `resource_name` | path | string | yes | Resource name (1-32 chars; only letters, digits, `_`, `-` and `.`) |

#### Responses

| Status | Description | Content |
|---|---|---|
| 204 | Resource deleted | — |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Resource not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |

### GET /rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/info

**Get resource metadata**

Read resource metadata only — no secret content and no backend fetch. Owner Bearer or attest token plus the bound Rego policy check; missing and denied reads are collapsed into the same 404.

Operation ID: `getResourceInfo`

Security: **bearerAuth**, **attestAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `res_provider` | path | string | yes | Backend provider name; must be configured under `resource.backends` in `rbs.yaml` (e.g. `vault`, `ca`, `hsm`); reserved names (`admin`, `attestation`, `resource`, `health`) are rejected |
| `repository_name` | path | string | yes | Repository name (1-32 chars; only letters, digits, `_` and `-`) |
| `resource_type` | path | string | yes | Resource type; must be in the provider's configured `allowed_resource_types` (e.g. `secret`, `cert`, `key`) |
| `resource_name` | path | string | yes | Resource name (1-32 chars; only letters, digits, `_`, `-` and `.`) |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Resource metadata | [ResourceResponse](#resourceresponse) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Resource not found or access denied | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "uri": "string",
  "provider_name": "string",
  "repository_name": "string",
  "resource_type": "string",
  "resource_name": "string",
  "created_at": "string",
  "updated_at": "string",
  "content_type": "string",
  "export_mode": "string",
  "policy_id": "string",
  "additional_info": "string"
}
```

### POST /rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}/retrieve

**Retrieve resource with attestation evidence**

The client submits RBC evidences in the request body.

The service calls the configured attestation backend to verify the evidence
and obtain an attest token, then uses the token claims (including
`tee-pubkey`) for Rego policy evaluation and JWE encryption of the resource
content.

Operation ID: `retrieveResource`

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `res_provider` | path | string | yes | Backend provider name; must be configured under `resource.backends` in `rbs.yaml` (e.g. `vault`, `ca`, `hsm`); reserved names (`admin`, `attestation`, `resource`, `health`) are rejected |
| `repository_name` | path | string | yes | Repository name (1-32 chars; only letters, digits, `_` and `-`) |
| `resource_type` | path | string | yes | Resource type; must be in the provider's configured `allowed_resource_types` (e.g. `secret`, `cert`, `key`) |
| `resource_name` | path | string | yes | Resource name (1-32 chars; only letters, digits, `_`, `-` and `.`) |

#### Request Body

Content type: `application/json` · Required: yes

Evidence bundle (same shape as `POST /rbs/v0/attest`) including the nonce from `GET /rbs/v0/challenge`; the token's `tee-pubkey` claim is used to JWE-encrypt the returned content.

Schema: [AttestRequest](#attestrequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `as_provider` | string | no | Optional attestation backend id (e.g. gta); default is deployment-specific. |
| `rbc_evidences` | [RbcEvidencesPayload](#rbcevidencespayload) | no | Evidence bundle from RBC. |

Example request:

```json
{
  "as_provider": "string",
  "rbc_evidences": {
    "agent_version": "string",
    "measurements": [
      {
        "nonce": "string",
        "node_id": "string",
        "nonce_type": "string",
        "token_fmt": "string",
        "attester_data": null,
        "evidences": [
          null
        ]
      }
    ]
  }
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Resource content (base64-encoded JWE) | [ResourceContentResponse](#resourcecontentresponse) |
| 404 | Resource not found or access denied | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 502 | Attestation backend returned a non-2xx; RBS forwards GTA's status code and wraps GTA's body in the error field. | [ErrorBody](#errorbody) |
| 503 | Attestation provider unreachable or timed out. | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "uri": "string",
  "content": "string",
  "content_type": "string",
  "export_mode": "string"
}
```

## Attestation

Attestation challenge/token issuance (`GET /rbs/v0/challenge`, `POST /rbs/v0/attest`, no auth) and attestation management CRUD for ref_value/cert/policy (`/rbs/v0/attestation/{as_provider}/{type}`, Bearer + admin only).

### POST /rbs/v0/attest

**Submit attestation evidence and obtain token**

Submit the RBC evidence bundle to the attestation backend; on success an attest token is returned for resource reads (`GET .../{resource}` and `POST .../retrieve`). The token is replayable until it expires. No authentication required.

Operation ID: `postAttest`

#### Request Body

Content type: `application/json` · Required: yes

Evidence bundle including the nonce obtained from `GET /rbs/v0/challenge`; `attester_data.runtime_data.tee-pubkey` (JWK) is used to JWE-encrypt returned resources.

Schema: [AttestRequest](#attestrequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `as_provider` | string | no | Optional attestation backend id (e.g. gta); default is deployment-specific. |
| `rbc_evidences` | [RbcEvidencesPayload](#rbcevidencespayload) | no | Evidence bundle from RBC. |

Example request:

```json
{
  "as_provider": "string",
  "rbc_evidences": {
    "agent_version": "string",
    "measurements": [
      {
        "nonce": "string",
        "node_id": "string",
        "nonce_type": "string",
        "token_fmt": "string",
        "attester_data": null,
        "evidences": [
          null
        ]
      }
    ]
  }
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Attestation token (JSON). | [AttestResponse](#attestresponse) |
| 400 | Invalid request. | [ErrorBody](#errorbody) |
| 500 | Internal server error. | [ErrorBody](#errorbody) |
| 502 | Attestation backend returned a non-2xx; RBS forwards GTA's status code and wraps GTA's body in the error field. | [ErrorBody](#errorbody) |
| 503 | Attestation provider unreachable or timed out. | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "token": "string"
}
```

### GET /rbs/v0/attestation/cert

**List certificates (default provider)**

Uses the configured default attestation provider. List certificates and CRLs: `ids` returns up to 10 full records (pagination ignored); otherwise paged summaries filtered by `cert_type`. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `listCertsDefault`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `ids` | query | string | no | Comma-separated certificate IDs (at most 100, GTA-enforced). |
| `cert_type` | query | string | no | Filter by certificate type; one of `refvalue`, `policy`, `tpm_boot`, `tpm`, `tpm_ima`, `crl`, `ascend_npu` (query param `cert_type`, JSON field `type`). |
| `limit` | query | integer(int64) | no | Page size (1-10, default 10). |
| `offset` | query | integer(int64) | no | Page offset (0-100000, default 0). |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Certificate list | [CertListResponse](#certlistresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Provider not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "certs": [
    {
      "cert_id": "C1",
      "cert_name": "cert1",
      "description": "string",
      "content": "string",
      "cert_type": [
        "string"
      ],
      "is_default": true,
      "version": 1,
      "create_time": 1700000000000,
      "update_time": 1700000000000,
      "valid_code": 0,
      "cert_revoked_date": 1700000000,
      "cert_revoked_reason": "string"
    }
  ],
  "crls": [
    {
      "crl_id": "L1",
      "crl_name": "crl1",
      "crl_content": "string"
    }
  ],
  "total_count": 0,
  "limit": 0,
  "offset": 0
}
```

### PUT /rbs/v0/attestation/cert

**Update a certificate (default provider)**

Uses the configured default attestation provider. Update a certificate/CRL record identified by in-body `id`; other fields are optional pass-through. GTA rejects `content` changes on update. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `updateCertDefault`

Security: **bearerAuth**

#### Request Body

Content type: `application/json` · Required: yes

ID of the certificate to update plus optional new field values; `content` changes are rejected by GTA.

Schema: [CertUpdateRequest](#certupdaterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | ID of the certificate to update (1-32 chars, GTA-enforced). |
| `name` | string | no | New name (1-255 chars). |
| `description` | string | no | New description (at most 512 chars). |
| `type` | array of string | no | New certificate type list (JSON field name `type`); 1-7 items, each one of `refvalue`, `policy`, `tpm_boot`, `tpm`, `tpm_ima`, `ascend_npu` — `crl` cannot be set on update. |
| `content` | string | no | Certificate content — GTA rejects this on update. |
| `is_default` | boolean | no | Whether to set as default certificate. |

Example request:

```json
{
  "id": "C1",
  "name": "string",
  "description": "string",
  "type": [
    "string"
  ],
  "content": "string",
  "is_default": true
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Certificate updated | [CertMutationResponse](#certmutationresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "cert": null,
  "crl": null
}
```

### POST /rbs/v0/attestation/cert

**Create a certificate (default provider)**

Uses the configured default attestation provider. Create a certificate or CRL record (`crl_content` required when `type` contains `crl`, otherwise `content`). Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `createCertDefault`

Security: **bearerAuth**

#### Request Body

Content type: `application/json` · Required: yes

Certificate or CRL record: when `type` contains `crl`, `crl_content` is required; otherwise `content` is required.

Schema: [CertCreateRequest](#certcreaterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Certificate name (1-255 chars, GTA-enforced). |
| `type` | array of string | yes | Certificate type list (JSON field name `type`); 1-7 items, each one of `refvalue`, `policy`, `tpm_boot`, `tpm`, `tpm_ima`, `crl`, `ascend_npu`; `crl` must be the only entry. |
| `description` | string | no | Optional description (at most 512 chars). |
| `content` | string | no | Certificate content; required when `cert_type` does not contain `crl`. |
| `crl_content` | string | no | CRL content; required when `cert_type` contains `crl` (which must then be the only entry). |
| `is_default` | boolean | no | Whether to set as default certificate. |

Example request:

```json
{
  "name": "cert1",
  "type": "[\"tpm\"]",
  "description": "string",
  "content": "string",
  "crl_content": "string",
  "is_default": true
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 201 | Certificate created | [CertMutationResponse](#certmutationresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Provider not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (201):

```json
{
  "cert": null,
  "crl": null
}
```

### DELETE /rbs/v0/attestation/cert

**Batch delete certificates (default provider)**

Uses the configured default attestation provider. Delete certificates/CRLs by mode: `id` (ID list), `all`, or `type` (cert type filter). Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `deleteCertsDefault`

Security: **bearerAuth**

#### Request Body

Content type: `application/json` · Required: yes

Delete mode (`id` / `all` / `type`) with the matching `ids` or cert type filter.

Schema: [CertDeleteRequest](#certdeleterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `delete_type` | [AttestationDeleteType](#attestationdeletetype) | yes | Delete mode. |
| `ids` | array of string | no | IDs to delete (required when `delete_type` is `Id`; at most 10 IDs). |
| `type` | string | no | Cert type filter (required when `delete_type` is `Type`; JSON field name `type`); one of `refvalue`, `policy`, `tpm_boot`, `tpm`, `tpm_ima`, `crl`, `ascend_npu`. |

Example request:

```json
{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "type": "refvalue"
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 204 | Certificates deleted | — |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

### GET /rbs/v0/attestation/cert/{id}

**Get a single certificate (default provider)**

Uses the configured default attestation provider. Fetch one certificate or CRL by ID. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `getCertDefault`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `id` | path | string | yes | Certificate or CRL ID (1-32 chars, GTA-enforced) |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Certificate detail | [CertListResponse](#certlistresponse) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "certs": [
    {
      "cert_id": "C1",
      "cert_name": "cert1",
      "description": "string",
      "content": "string",
      "cert_type": [
        "string"
      ],
      "is_default": true,
      "version": 1,
      "create_time": 1700000000000,
      "update_time": 1700000000000,
      "valid_code": 0,
      "cert_revoked_date": 1700000000,
      "cert_revoked_reason": "string"
    }
  ],
  "crls": [
    {
      "crl_id": "L1",
      "crl_name": "crl1",
      "crl_content": "string"
    }
  ],
  "total_count": 0,
  "limit": 0,
  "offset": 0
}
```

### DELETE /rbs/v0/attestation/cert/{id}

**Delete a single certificate (default provider)**

Uses the configured default attestation provider. Delete one certificate or CRL by ID. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `deleteCertDefault`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `id` | path | string | yes | Certificate or CRL ID (1-32 chars, GTA-enforced) |

#### Responses

| Status | Description | Content |
|---|---|---|
| 204 | Certificate deleted | — |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

### GET /rbs/v0/attestation/policy

**List attestation policies (default provider)**

Uses the configured default attestation provider. List GTA attestation policies: `ids` returns up to 10 full records (pagination ignored); otherwise paged summaries filtered by `attester_type`. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `listAttestationPoliciesDefault`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `ids` | query | string | no | Comma-separated policy IDs (at most 10, GTA-enforced). |
| `attester_type` | query | string | no | Filter by attester_type (e.g. `tpm`, `tpm_ima`, `itrustee`, `dice`). |
| `limit` | query | integer(int64) | no | Page size (1-10, default 10). |
| `offset` | query | integer(int64) | no | Page offset (0-100000, default 0). |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Policy list | [AttestationPolicyListResponse](#attestationpolicylistresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Provider not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "policies": [
    {
      "id": "P1",
      "name": "policy1",
      "description": "string",
      "content": "string",
      "attester_type": "[\"tpm\",\"sgx\"]",
      "is_default": true,
      "version": 1,
      "update_time": 1700000000000,
      "valid_code": 0
    }
  ],
  "total_count": 0,
  "limit": 0,
  "offset": 0
}
```

### PUT /rbs/v0/attestation/policy

**Update an attestation policy (default provider)**

Uses the configured default attestation provider. Update a GTA attestation policy identified by in-body `id`; other fields are optional pass-through. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `updateAttestationPolicyDefault`

Security: **bearerAuth**

#### Request Body

Content type: `application/json` · Required: yes

ID of the policy to update plus optional new field values.

Schema: [PolicyUpdateRequest](#policyupdaterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | ID of the policy to update (1-36 chars, GTA-enforced). |
| `name` | string | no | New name (1-255 chars; GTA rejects the special characters `< > " ' & \| \ / * ?` and backtick). |
| `description` | string | no | New description (at most 512 chars). |
| `attester_type` | array of string | no | New attester type list (1-9 items, each at most 255 chars). |
| `content_type` | string | no | New content encoding: `jwt` or `text`. |
| `content` | string | no | New policy content (base64-encoded; decoded size limited as on create). |
| `is_default` | boolean | no | Whether to set as default policy. |

Example request:

```json
{
  "id": "P1",
  "name": "string",
  "description": "string",
  "attester_type": [
    "string"
  ],
  "content_type": "string",
  "content": "string",
  "is_default": true
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Policy updated | [PolicyMutationResponse](#policymutationresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "policy": {
    "id": "P1",
    "name": "policy1",
    "version": 2
  }
}
```

### POST /rbs/v0/attestation/policy

**Create an attestation policy (default provider)**

Uses the configured default attestation provider. Create a GTA attestation policy (`name`, `attester_type`, `content_type`, `content` required). Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `createAttestationPolicyDefault`

Security: **bearerAuth**

#### Request Body

Content type: `application/json` · Required: yes

Policy definition: name, attester type list, content encoding (`jwt` or `text`), and content.

Schema: [PolicyCreateRequest](#policycreaterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Policy name (1-255 chars; GTA rejects the special characters `< > " ' & \| \ / * ?` and backtick). |
| `attester_type` | array of string | yes | Attester type list (1-9 items, each at most 255 chars); supported values: `all`, `tpm`, `tpm_boot`, `tpm_ima`, `virt_cca`, `ascend_npu`, `itrustee`, `cca`, `dice`. |
| `content_type` | string | yes | Content encoding (required): `jwt` or `text` (GTA-enforced). |
| `content` | string | yes | Policy content (base64-encoded); the decoded size is bounded by GTA's `policy_content_size_limit` (shipped default 500 KB). |
| `is_default` | boolean | no | Whether to set as default policy. |
| `description` | string | no | Optional description (at most 512 chars). |

Example request:

```json
{
  "name": "policy1",
  "attester_type": "[\"tpm\"]",
  "content_type": "jwt",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "is_default": true,
  "description": "string"
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 201 | Policy created | [PolicyMutationResponse](#policymutationresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Provider not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (201):

```json
{
  "policy": {
    "id": "P1",
    "name": "policy1",
    "version": 2
  }
}
```

### DELETE /rbs/v0/attestation/policy

**Batch delete attestation policies (default provider)**

Uses the configured default attestation provider. Delete GTA attestation policies by mode: `id` (ID list), `all`, or `attester_type` filter. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `deleteAttestationPoliciesDefault`

Security: **bearerAuth**

#### Request Body

Content type: `application/json` · Required: yes

Delete mode (`id` / `all` / `attester_type`) with the matching `ids` or `attester_type` filter.

Schema: [PolicyDeleteRequest](#policydeleterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `delete_type` | [PolicyDeleteType](#policydeletetype) | yes | Delete mode. |
| `ids` | array of string | no | IDs to delete (required when `delete_type` is `Id`; at most 10 IDs, each at most 36 chars). |
| `attester_type` | string | no | Attester type filter (required when `delete_type` is `AttesterType`; at most 255 chars). |

Example request:

```json
{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "attester_type": "tpm"
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 204 | Policies deleted | — |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

### GET /rbs/v0/attestation/policy/{id}

**Get a single attestation policy (default provider)**

Uses the configured default attestation provider. Fetch one GTA attestation policy by ID (full record). Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `getAttestationPolicyDefault`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `id` | path | string | yes | Policy ID (1-36 chars, GTA-enforced) |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Policy detail | [AttestationPolicyListResponse](#attestationpolicylistresponse) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "policies": [
    {
      "id": "P1",
      "name": "policy1",
      "description": "string",
      "content": "string",
      "attester_type": "[\"tpm\",\"sgx\"]",
      "is_default": true,
      "version": 1,
      "update_time": 1700000000000,
      "valid_code": 0
    }
  ],
  "total_count": 0,
  "limit": 0,
  "offset": 0
}
```

### DELETE /rbs/v0/attestation/policy/{id}

**Delete a single attestation policy (default provider)**

Uses the configured default attestation provider. Delete one GTA attestation policy by ID. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `deleteAttestationPolicyDefault`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `id` | path | string | yes | Policy ID (1-36 chars, GTA-enforced) |

#### Responses

| Status | Description | Content |
|---|---|---|
| 204 | Policy deleted | — |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

### GET /rbs/v0/attestation/ref_value

**List reference value baselines (default provider)**

Uses the configured default attestation provider. List reference value baselines: `ids` returns up to 10 full records (pagination ignored); otherwise paged summaries filtered by `attester_type`. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `listRefValuesDefault`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `ids` | query | string | no | Comma-separated ref_value IDs (1-10, each 1-36 chars); when present, pagination is ignored. |
| `attester_type` | query | string | no | Filter by attester_type; one of `tpm`, `tpm_ima`, `virt_cca`, `ascend_npu`, `cca`. |
| `limit` | query | integer(int64) | no | Page size (1-10, default 10). Ignored when `ids` is present. |
| `offset` | query | integer(int64) | no | Page offset (0-100000, default 0). Ignored when `ids` is present. |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Ref_value list | [RefValueListResponse](#refvaluelistresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Provider not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "ref_values": [
    {
      "id": "rv-001",
      "uid": "test_01",
      "name": "tpm-baseline",
      "attester_type": "tpm",
      "description": "TPM reference baseline",
      "content": "eyJhbGciOiJSUzI1NiJ9...",
      "content_type": "jwt",
      "version": 1,
      "valid_code": 0
    }
  ],
  "total_count": 0,
  "limit": 0,
  "offset": 0
}
```

### PUT /rbs/v0/attestation/ref_value

**Update a reference value baseline (default provider)**

Uses the configured default attestation provider. Update a reference value baseline identified by in-body `id`; other fields are optional pass-through. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `updateRefValueDefault`

Security: **bearerAuth**

#### Request Body

Content type: `application/json` · Required: yes

ID of the baseline to update plus optional new field values.

Schema: [RefValueUpdateRequest](#refvalueupdaterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | ID of the ref_value to update (1-36 chars, GTA-enforced). |
| `name` | string | no | New name (1-255 chars). |
| `description` | string | no | New description (at most 512 chars). |
| `attester_type` | string | no | New attester_type; one of `tpm`, `tpm_ima`, `virt_cca`, `ascend_npu`, `cca`. |
| `content` | string | no | New content (at most 100 MiB). |
| `content_type` | string | no | New content encoding: `jwt` or `base64`. |

Example request:

```json
{
  "id": "rv-001",
  "name": "updated-baseline",
  "description": "string",
  "attester_type": "tpm",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "content_type": "base64"
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Ref_value updated | [RefValueMutationResponse](#refvaluemutationresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "ref_value": {
    "id": "rv-001",
    "name": "tpm-baseline",
    "version": 2
  }
}
```

### POST /rbs/v0/attestation/ref_value

**Create a reference value baseline (default provider)**

Uses the configured default attestation provider. Create a reference value baseline (`name`, `attester_type`, `content` required; `content_type` defaults to `jwt`). Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `createRefValueDefault`

Security: **bearerAuth**

#### Request Body

Content type: `application/json` · Required: yes

Baseline definition: name, attester type, content (JWT or base64), optional encoding (defaults to `jwt`) and description.

Schema: [RefValueCreateRequest](#refvaluecreaterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Baseline name (1-255 chars, GTA-enforced). |
| `attester_type` | string | yes | Attester type; one of `tpm`, `tpm_ima`, `virt_cca`, `ascend_npu`, `cca` (GTA-enforced). |
| `content` | string | yes | Baseline content — JWT or base64-encoded payload; at most 100 MiB (GTA-enforced). |
| `content_type` | string | no | Content encoding: `jwt` (default when omitted) or `base64`. |
| `description` | string | no | Optional description (at most 512 chars, GTA-enforced). |

Example request:

```json
{
  "name": "tpm-baseline",
  "attester_type": "tpm",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "content_type": "jwt",
  "description": "TPM reference baseline"
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 201 | Ref_value created | [RefValueMutationResponse](#refvaluemutationresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Provider not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (201):

```json
{
  "ref_value": {
    "id": "rv-001",
    "name": "tpm-baseline",
    "version": 2
  }
}
```

### DELETE /rbs/v0/attestation/ref_value

**Batch delete reference value baselines (default provider)**

Uses the configured default attestation provider. Delete reference value baselines by mode: `id` (ID list), `all`, or `type` (`attester_type` filter). Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `deleteRefValuesDefault`

Security: **bearerAuth**

#### Request Body

Content type: `application/json` · Required: yes

Delete mode (`id` / `all` / `type`) with the matching `ids` or `attester_type` filter.

Schema: [RefValueDeleteRequest](#refvaluedeleterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `delete_type` | [AttestationDeleteType](#attestationdeletetype) | yes | Delete mode. |
| `ids` | array of string | no | IDs to delete (required when `delete_type` is `Id`; 1-10 IDs, each 1-36 chars). |
| `attester_type` | string | no | Attester type filter (required when `delete_type` is `Type`); one of `tpm`, `tpm_ima`, `virt_cca`, `ascend_npu`, `cca`. |

Example request:

```json
{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "attester_type": "tpm"
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 204 | Ref_values deleted | — |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

### GET /rbs/v0/attestation/ref_value/{id}

**Get a single reference value baseline (default provider)**

Uses the configured default attestation provider. Fetch one reference value baseline by ID (full record). Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `getRefValueDefault`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `id` | path | string | yes | Ref_value ID (1-36 chars, GTA-enforced) |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Ref_value detail | [RefValueListResponse](#refvaluelistresponse) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "ref_values": [
    {
      "id": "rv-001",
      "uid": "test_01",
      "name": "tpm-baseline",
      "attester_type": "tpm",
      "description": "TPM reference baseline",
      "content": "eyJhbGciOiJSUzI1NiJ9...",
      "content_type": "jwt",
      "version": 1,
      "valid_code": 0
    }
  ],
  "total_count": 0,
  "limit": 0,
  "offset": 0
}
```

### DELETE /rbs/v0/attestation/ref_value/{id}

**Delete a single reference value baseline (default provider)**

Uses the configured default attestation provider. Delete one reference value baseline by ID. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `deleteRefValueDefault`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `id` | path | string | yes | Ref_value ID (1-36 chars, GTA-enforced) |

#### Responses

| Status | Description | Content |
|---|---|---|
| 204 | Ref_value deleted | — |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

### GET /rbs/v0/attestation/{as_provider}/cert

**List certificates**

List certificates and CRLs. With `ids`, up to 10 full records are returned and pagination is ignored; otherwise paged summaries, filterable by `cert_type`. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `listCerts`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | path | string | yes | Attestation provider name; must be configured under `attestation.backends` in `rbs.yaml` (e.g. `gta`) |
| `ids` | query | string | no | Comma-separated certificate IDs (at most 100, GTA-enforced). |
| `cert_type` | query | string | no | Filter by certificate type; one of `refvalue`, `policy`, `tpm_boot`, `tpm`, `tpm_ima`, `crl`, `ascend_npu` (query param `cert_type`, JSON field `type`). |
| `limit` | query | integer(int64) | no | Page size (1-10, default 10). |
| `offset` | query | integer(int64) | no | Page offset (0-100000, default 0). |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Certificate list | [CertListResponse](#certlistresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Provider not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "certs": [
    {
      "cert_id": "C1",
      "cert_name": "cert1",
      "description": "string",
      "content": "string",
      "cert_type": [
        "string"
      ],
      "is_default": true,
      "version": 1,
      "create_time": 1700000000000,
      "update_time": 1700000000000,
      "valid_code": 0,
      "cert_revoked_date": 1700000000,
      "cert_revoked_reason": "string"
    }
  ],
  "crls": [
    {
      "crl_id": "L1",
      "crl_name": "crl1",
      "crl_content": "string"
    }
  ],
  "total_count": 0,
  "limit": 0,
  "offset": 0
}
```

### PUT /rbs/v0/attestation/{as_provider}/cert

**Update a certificate**

Update a certificate/CRL record identified by in-body `id`; all other fields are optional pass-through. GTA rejects `content` changes on update. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `updateCert`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | path | string | yes | Attestation provider name; must be configured under `attestation.backends` in `rbs.yaml` (e.g. `gta`) |

#### Request Body

Content type: `application/json` · Required: yes

ID of the certificate to update plus optional new field values; `content` changes are rejected by GTA.

Schema: [CertUpdateRequest](#certupdaterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | ID of the certificate to update (1-32 chars, GTA-enforced). |
| `name` | string | no | New name (1-255 chars). |
| `description` | string | no | New description (at most 512 chars). |
| `type` | array of string | no | New certificate type list (JSON field name `type`); 1-7 items, each one of `refvalue`, `policy`, `tpm_boot`, `tpm`, `tpm_ima`, `ascend_npu` — `crl` cannot be set on update. |
| `content` | string | no | Certificate content — GTA rejects this on update. |
| `is_default` | boolean | no | Whether to set as default certificate. |

Example request:

```json
{
  "id": "C1",
  "name": "string",
  "description": "string",
  "type": [
    "string"
  ],
  "content": "string",
  "is_default": true
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Certificate updated | [CertMutationResponse](#certmutationresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "cert": null,
  "crl": null
}
```

### POST /rbs/v0/attestation/{as_provider}/cert

**Create a certificate**

Create a certificate or CRL record: when `type` contains `crl`, `crl_content` is required; otherwise `content` is required. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `createCert`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | path | string | yes | Attestation provider name; must be configured under `attestation.backends` in `rbs.yaml` (e.g. `gta`) |

#### Request Body

Content type: `application/json` · Required: yes

Certificate or CRL record: when `type` contains `crl`, `crl_content` is required; otherwise `content` is required.

Schema: [CertCreateRequest](#certcreaterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Certificate name (1-255 chars, GTA-enforced). |
| `type` | array of string | yes | Certificate type list (JSON field name `type`); 1-7 items, each one of `refvalue`, `policy`, `tpm_boot`, `tpm`, `tpm_ima`, `crl`, `ascend_npu`; `crl` must be the only entry. |
| `description` | string | no | Optional description (at most 512 chars). |
| `content` | string | no | Certificate content; required when `cert_type` does not contain `crl`. |
| `crl_content` | string | no | CRL content; required when `cert_type` contains `crl` (which must then be the only entry). |
| `is_default` | boolean | no | Whether to set as default certificate. |

Example request:

```json
{
  "name": "cert1",
  "type": "[\"tpm\"]",
  "description": "string",
  "content": "string",
  "crl_content": "string",
  "is_default": true
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 201 | Certificate created | [CertMutationResponse](#certmutationresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Provider not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (201):

```json
{
  "cert": null,
  "crl": null
}
```

### DELETE /rbs/v0/attestation/{as_provider}/cert

**Batch delete certificates**

Delete certificates/CRLs by mode: `id` (ID list), `all`, or `type` (cert type filter). Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `deleteCerts`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | path | string | yes | Attestation provider name; must be configured under `attestation.backends` in `rbs.yaml` (e.g. `gta`) |

#### Request Body

Content type: `application/json` · Required: yes

Delete mode (`id` / `all` / `type`) with the matching `ids` or cert type filter.

Schema: [CertDeleteRequest](#certdeleterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `delete_type` | [AttestationDeleteType](#attestationdeletetype) | yes | Delete mode. |
| `ids` | array of string | no | IDs to delete (required when `delete_type` is `Id`; at most 10 IDs). |
| `type` | string | no | Cert type filter (required when `delete_type` is `Type`; JSON field name `type`); one of `refvalue`, `policy`, `tpm_boot`, `tpm`, `tpm_ima`, `crl`, `ascend_npu`. |

Example request:

```json
{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "type": "refvalue"
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 204 | Certificates deleted | — |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

### GET /rbs/v0/attestation/{as_provider}/cert/{id}

**Get a single certificate**

Fetch one certificate or CRL by ID. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `getCert`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | path | string | yes | Attestation provider name; must be configured under `attestation.backends` in `rbs.yaml` (e.g. `gta`) |
| `id` | path | string | yes | Certificate or CRL ID (1-32 chars, GTA-enforced) |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Certificate detail | [CertListResponse](#certlistresponse) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "certs": [
    {
      "cert_id": "C1",
      "cert_name": "cert1",
      "description": "string",
      "content": "string",
      "cert_type": [
        "string"
      ],
      "is_default": true,
      "version": 1,
      "create_time": 1700000000000,
      "update_time": 1700000000000,
      "valid_code": 0,
      "cert_revoked_date": 1700000000,
      "cert_revoked_reason": "string"
    }
  ],
  "crls": [
    {
      "crl_id": "L1",
      "crl_name": "crl1",
      "crl_content": "string"
    }
  ],
  "total_count": 0,
  "limit": 0,
  "offset": 0
}
```

### DELETE /rbs/v0/attestation/{as_provider}/cert/{id}

**Delete a single certificate**

Delete one certificate or CRL by ID. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `deleteCert`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | path | string | yes | Attestation provider name; must be configured under `attestation.backends` in `rbs.yaml` (e.g. `gta`) |
| `id` | path | string | yes | Certificate or CRL ID (1-32 chars, GTA-enforced) |

#### Responses

| Status | Description | Content |
|---|---|---|
| 204 | Certificate deleted | — |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

### GET /rbs/v0/attestation/{as_provider}/policy

**List attestation policies**

List GTA attestation policies. With `ids`, up to 10 full records are returned and pagination is ignored; otherwise paged summaries, filterable by `attester_type`. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `listAttestationPolicies`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | path | string | yes | Attestation provider name; must be configured under `attestation.backends` in `rbs.yaml` (e.g. `gta`) |
| `ids` | query | string | no | Comma-separated policy IDs (at most 10, GTA-enforced). |
| `attester_type` | query | string | no | Filter by attester_type (e.g. `tpm`, `tpm_ima`, `itrustee`, `dice`). |
| `limit` | query | integer(int64) | no | Page size (1-10, default 10). |
| `offset` | query | integer(int64) | no | Page offset (0-100000, default 0). |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Policy list | [AttestationPolicyListResponse](#attestationpolicylistresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Provider not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "policies": [
    {
      "id": "P1",
      "name": "policy1",
      "description": "string",
      "content": "string",
      "attester_type": "[\"tpm\",\"sgx\"]",
      "is_default": true,
      "version": 1,
      "update_time": 1700000000000,
      "valid_code": 0
    }
  ],
  "total_count": 0,
  "limit": 0,
  "offset": 0
}
```

### PUT /rbs/v0/attestation/{as_provider}/policy

**Update an attestation policy**

Update a GTA attestation policy identified by in-body `id`; all other fields are optional pass-through. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `updateAttestationPolicy`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | path | string | yes | Attestation provider name; must be configured under `attestation.backends` in `rbs.yaml` (e.g. `gta`) |

#### Request Body

Content type: `application/json` · Required: yes

ID of the policy to update plus optional new field values.

Schema: [PolicyUpdateRequest](#policyupdaterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | ID of the policy to update (1-36 chars, GTA-enforced). |
| `name` | string | no | New name (1-255 chars; GTA rejects the special characters `< > " ' & \| \ / * ?` and backtick). |
| `description` | string | no | New description (at most 512 chars). |
| `attester_type` | array of string | no | New attester type list (1-9 items, each at most 255 chars). |
| `content_type` | string | no | New content encoding: `jwt` or `text`. |
| `content` | string | no | New policy content (base64-encoded; decoded size limited as on create). |
| `is_default` | boolean | no | Whether to set as default policy. |

Example request:

```json
{
  "id": "P1",
  "name": "string",
  "description": "string",
  "attester_type": [
    "string"
  ],
  "content_type": "string",
  "content": "string",
  "is_default": true
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Policy updated | [PolicyMutationResponse](#policymutationresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "policy": {
    "id": "P1",
    "name": "policy1",
    "version": 2
  }
}
```

### POST /rbs/v0/attestation/{as_provider}/policy

**Create an attestation policy**

Create a GTA attestation policy: `name`, `attester_type` (non-empty list), `content_type` (`jwt` or `text`), and `content` are required. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `createAttestationPolicy`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | path | string | yes | Attestation provider name; must be configured under `attestation.backends` in `rbs.yaml` (e.g. `gta`) |

#### Request Body

Content type: `application/json` · Required: yes

Policy definition: name, attester type list, content encoding (`jwt` or `text`), and content.

Schema: [PolicyCreateRequest](#policycreaterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Policy name (1-255 chars; GTA rejects the special characters `< > " ' & \| \ / * ?` and backtick). |
| `attester_type` | array of string | yes | Attester type list (1-9 items, each at most 255 chars); supported values: `all`, `tpm`, `tpm_boot`, `tpm_ima`, `virt_cca`, `ascend_npu`, `itrustee`, `cca`, `dice`. |
| `content_type` | string | yes | Content encoding (required): `jwt` or `text` (GTA-enforced). |
| `content` | string | yes | Policy content (base64-encoded); the decoded size is bounded by GTA's `policy_content_size_limit` (shipped default 500 KB). |
| `is_default` | boolean | no | Whether to set as default policy. |
| `description` | string | no | Optional description (at most 512 chars). |

Example request:

```json
{
  "name": "policy1",
  "attester_type": "[\"tpm\"]",
  "content_type": "jwt",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "is_default": true,
  "description": "string"
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 201 | Policy created | [PolicyMutationResponse](#policymutationresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Provider not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (201):

```json
{
  "policy": {
    "id": "P1",
    "name": "policy1",
    "version": 2
  }
}
```

### DELETE /rbs/v0/attestation/{as_provider}/policy

**Batch delete attestation policies**

Delete GTA attestation policies by mode: `id` (ID list), `all`, or `attester_type` filter. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `deleteAttestationPolicies`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | path | string | yes | Attestation provider name; must be configured under `attestation.backends` in `rbs.yaml` (e.g. `gta`) |

#### Request Body

Content type: `application/json` · Required: yes

Delete mode (`id` / `all` / `attester_type`) with the matching `ids` or `attester_type` filter.

Schema: [PolicyDeleteRequest](#policydeleterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `delete_type` | [PolicyDeleteType](#policydeletetype) | yes | Delete mode. |
| `ids` | array of string | no | IDs to delete (required when `delete_type` is `Id`; at most 10 IDs, each at most 36 chars). |
| `attester_type` | string | no | Attester type filter (required when `delete_type` is `AttesterType`; at most 255 chars). |

Example request:

```json
{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "attester_type": "tpm"
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 204 | Policies deleted | — |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

### GET /rbs/v0/attestation/{as_provider}/policy/{id}

**Get a single attestation policy**

Fetch one GTA attestation policy by ID (full record). Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `getAttestationPolicy`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | path | string | yes | Attestation provider name; must be configured under `attestation.backends` in `rbs.yaml` (e.g. `gta`) |
| `id` | path | string | yes | Policy ID (1-36 chars, GTA-enforced) |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Policy detail | [AttestationPolicyListResponse](#attestationpolicylistresponse) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "policies": [
    {
      "id": "P1",
      "name": "policy1",
      "description": "string",
      "content": "string",
      "attester_type": "[\"tpm\",\"sgx\"]",
      "is_default": true,
      "version": 1,
      "update_time": 1700000000000,
      "valid_code": 0
    }
  ],
  "total_count": 0,
  "limit": 0,
  "offset": 0
}
```

### DELETE /rbs/v0/attestation/{as_provider}/policy/{id}

**Delete a single attestation policy**

Delete one GTA attestation policy by ID. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `deleteAttestationPolicy`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | path | string | yes | Attestation provider name; must be configured under `attestation.backends` in `rbs.yaml` (e.g. `gta`) |
| `id` | path | string | yes | Policy ID (1-36 chars, GTA-enforced) |

#### Responses

| Status | Description | Content |
|---|---|---|
| 204 | Policy deleted | — |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

### GET /rbs/v0/attestation/{as_provider}/ref_value

**List reference value baselines**

List reference value baselines (trusted measurements compared against attestation evidence). With `ids`, up to 10 full records are returned and pagination is ignored; otherwise paged summaries, filterable by `attester_type`. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `listRefValues`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | path | string | yes | Attestation provider name; must be configured under `attestation.backends` in `rbs.yaml` (e.g. `gta`) |
| `ids` | query | string | no | Comma-separated ref_value IDs (1-10, each 1-36 chars); when present, pagination is ignored. |
| `attester_type` | query | string | no | Filter by attester_type; one of `tpm`, `tpm_ima`, `virt_cca`, `ascend_npu`, `cca`. |
| `limit` | query | integer(int64) | no | Page size (1-10, default 10). Ignored when `ids` is present. |
| `offset` | query | integer(int64) | no | Page offset (0-100000, default 0). Ignored when `ids` is present. |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Ref_value list | [RefValueListResponse](#refvaluelistresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Provider not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "ref_values": [
    {
      "id": "rv-001",
      "uid": "test_01",
      "name": "tpm-baseline",
      "attester_type": "tpm",
      "description": "TPM reference baseline",
      "content": "eyJhbGciOiJSUzI1NiJ9...",
      "content_type": "jwt",
      "version": 1,
      "valid_code": 0
    }
  ],
  "total_count": 0,
  "limit": 0,
  "offset": 0
}
```

### PUT /rbs/v0/attestation/{as_provider}/ref_value

**Update a reference value baseline**

Update a reference value baseline identified by in-body `id`; all other fields are optional pass-through. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `updateRefValue`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | path | string | yes | Attestation provider name; must be configured under `attestation.backends` in `rbs.yaml` (e.g. `gta`) |

#### Request Body

Content type: `application/json` · Required: yes

ID of the baseline to update plus optional new field values.

Schema: [RefValueUpdateRequest](#refvalueupdaterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | ID of the ref_value to update (1-36 chars, GTA-enforced). |
| `name` | string | no | New name (1-255 chars). |
| `description` | string | no | New description (at most 512 chars). |
| `attester_type` | string | no | New attester_type; one of `tpm`, `tpm_ima`, `virt_cca`, `ascend_npu`, `cca`. |
| `content` | string | no | New content (at most 100 MiB). |
| `content_type` | string | no | New content encoding: `jwt` or `base64`. |

Example request:

```json
{
  "id": "rv-001",
  "name": "updated-baseline",
  "description": "string",
  "attester_type": "tpm",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "content_type": "base64"
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Ref_value updated | [RefValueMutationResponse](#refvaluemutationresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "ref_value": {
    "id": "rv-001",
    "name": "tpm-baseline",
    "version": 2
  }
}
```

### POST /rbs/v0/attestation/{as_provider}/ref_value

**Create a reference value baseline**

Create a reference value baseline: `name`, `attester_type`, and `content` are required; `content_type` defaults to `jwt` when omitted. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `createRefValue`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | path | string | yes | Attestation provider name; must be configured under `attestation.backends` in `rbs.yaml` (e.g. `gta`) |

#### Request Body

Content type: `application/json` · Required: yes

Baseline definition: name, attester type, content (JWT or base64), optional encoding (defaults to `jwt`) and description.

Schema: [RefValueCreateRequest](#refvaluecreaterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Baseline name (1-255 chars, GTA-enforced). |
| `attester_type` | string | yes | Attester type; one of `tpm`, `tpm_ima`, `virt_cca`, `ascend_npu`, `cca` (GTA-enforced). |
| `content` | string | yes | Baseline content — JWT or base64-encoded payload; at most 100 MiB (GTA-enforced). |
| `content_type` | string | no | Content encoding: `jwt` (default when omitted) or `base64`. |
| `description` | string | no | Optional description (at most 512 chars, GTA-enforced). |

Example request:

```json
{
  "name": "tpm-baseline",
  "attester_type": "tpm",
  "content": "eyJhbGciOiJSUzI1NiJ9...",
  "content_type": "jwt",
  "description": "TPM reference baseline"
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 201 | Ref_value created | [RefValueMutationResponse](#refvaluemutationresponse) |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Provider not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (201):

```json
{
  "ref_value": {
    "id": "rv-001",
    "name": "tpm-baseline",
    "version": 2
  }
}
```

### DELETE /rbs/v0/attestation/{as_provider}/ref_value

**Batch delete reference value baselines**

Delete reference value baselines by mode: `id` (ID list), `all`, or `type` (`attester_type` filter). Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `deleteRefValues`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | path | string | yes | Attestation provider name; must be configured under `attestation.backends` in `rbs.yaml` (e.g. `gta`) |

#### Request Body

Content type: `application/json` · Required: yes

Delete mode (`id` / `all` / `type`) with the matching `ids` or `attester_type` filter.

Schema: [RefValueDeleteRequest](#refvaluedeleterequest)

| Property | Type | Required | Description |
|---|---|---|---|
| `delete_type` | [AttestationDeleteType](#attestationdeletetype) | yes | Delete mode. |
| `ids` | array of string | no | IDs to delete (required when `delete_type` is `Id`; 1-10 IDs, each 1-36 chars). |
| `attester_type` | string | no | Attester type filter (required when `delete_type` is `Type`); one of `tpm`, `tpm_ima`, `virt_cca`, `ascend_npu`, `cca`. |

Example request:

```json
{
  "delete_type": "id",
  "ids": [
    "string"
  ],
  "attester_type": "tpm"
}
```

#### Responses

| Status | Description | Content |
|---|---|---|
| 204 | Ref_values deleted | — |
| 400 | Bad request | [ErrorBody](#errorbody) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

### GET /rbs/v0/attestation/{as_provider}/ref_value/{id}

**Get a single reference value baseline**

Fetch one reference value baseline by ID (full record). Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `getRefValue`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | path | string | yes | Attestation provider name; must be configured under `attestation.backends` in `rbs.yaml` (e.g. `gta`) |
| `id` | path | string | yes | Ref_value ID (1-36 chars, GTA-enforced) |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Ref_value detail | [RefValueListResponse](#refvaluelistresponse) |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "ref_values": [
    {
      "id": "rv-001",
      "uid": "test_01",
      "name": "tpm-baseline",
      "attester_type": "tpm",
      "description": "TPM reference baseline",
      "content": "eyJhbGciOiJSUzI1NiJ9...",
      "content_type": "jwt",
      "version": 1,
      "valid_code": 0
    }
  ],
  "total_count": 0,
  "limit": 0,
  "offset": 0
}
```

### DELETE /rbs/v0/attestation/{as_provider}/ref_value/{id}

**Delete a single reference value baseline**

Delete one reference value baseline by ID. Admin Bearer only; RBS proxies to GTA (503 when unreachable, other GTA statuses forwarded as-is).

Operation ID: `deleteRefValue`

Security: **bearerAuth**

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | path | string | yes | Attestation provider name; must be configured under `attestation.backends` in `rbs.yaml` (e.g. `gta`) |
| `id` | path | string | yes | Ref_value ID (1-36 chars, GTA-enforced) |

#### Responses

| Status | Description | Content |
|---|---|---|
| 204 | Ref_value deleted | — |
| 401 | Unauthorized | [ErrorBody](#errorbody) |
| 403 | Forbidden | [ErrorBody](#errorbody) |
| 404 | Not found | [ErrorBody](#errorbody) |
| 500 | Internal error | [ErrorBody](#errorbody) |
| 503 | GTA unreachable or timeout; other GTA statuses forwarded as-is | [ErrorBody](#errorbody) |

### GET /rbs/v0/challenge

**Obtain an attestation challenge (nonce)**

Obtain a one-time attestation challenge (nonce) from the attestation backend (GTA). Echo the nonce verbatim in `rbc_evidences.measurements[].nonce` when calling `POST /rbs/v0/attest` or `POST .../retrieve`. No authentication required.

Operation ID: `getAuthChallenge`

#### Parameters

| Name | In | Type | Required | Description |
|---|---|---|---|---|
| `as_provider` | query | string | no | Target provider ID for challenge |

#### Responses

| Status | Description | Content |
|---|---|---|
| 200 | Challenge payload with nonce (JSON). | [AuthChallengeResponse](#authchallengeresponse) |
| 500 | Internal server error. | [ErrorBody](#errorbody) |
| 502 | Attestation backend returned a non-2xx; RBS forwards GTA's status code and wraps GTA's body in the error field. | [ErrorBody](#errorbody) |
| 503 | Attestation provider unreachable or timed out. | [ErrorBody](#errorbody) |

Example response (200):

```json
{
  "nonce": "string"
}
```

## Schemas

### AttestRequest

Request body for POST /rbs/v0/attest.

| Property | Type | Required | Description |
|---|---|---|---|
| `as_provider` | string | no | Optional attestation backend id (e.g. gta); default is deployment-specific. |
| `rbc_evidences` | [RbcEvidencesPayload](#rbcevidencespayload) | no | Evidence bundle from RBC. |

### AttestResponse

Response for POST /rbs/v0/attest.

| Property | Type | Required | Description |
|---|---|---|---|
| `token` | string | yes | AttestToken or session JWT for subsequent Bearer resource access. |

### AttestationDeleteType

Delete mode for ref_value/cert DELETE operations: `"id"`, `"all"`, or `"type"`.

Type: string — enum: `"id"`, `"all"`, `"type"`

### AttestationPolicy

Attestation policy entity returned by GTA; fields beyond `id`/`name`/`attester_type` appear only in by_ids.

| Property | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Stable policy identifier. |
| `name` | string | yes | Policy name. |
| `description` | string | no | Optional description (by_ids path only). |
| `content` | string | no | Policy content (JWT or text) (by_ids path only). |
| `attester_type` | array of string | yes | Attester type list (array, unlike ref_value's scalar attester_type). |
| `is_default` | boolean | no | Whether this is the default policy (by_ids path only). |
| `version` | integer(int32) | no | Policy version (by_ids path only). |
| `update_time` | integer(int64) | no | Last update timestamp as Unix epoch seconds or milliseconds, depending on the GTA response. |
| `valid_code` | integer(int32) | no | Validity code: 0 = valid, 1 = invalid (by_ids path only). |

### AttestationPolicyListResponse

Paginated response for GET attestation policy list.

| Property | Type | Required | Description |
|---|---|---|---|
| `policies` | array of [AttestationPolicy](#attestationpolicy) | yes | List of policies matching the query. |
| `total_count` | integer(int64) | no | Total matching count. |
| `limit` | integer(int64) | no | Effective page size returned by GTA. |
| `offset` | integer(int64) | no | Effective page offset returned by GTA. |

### AttesterData

Optional attester-supplied metadata, carried per measurement.

| Property | Type | Required | Description |
|---|---|---|---|
| `runtime_data` | object | no | Key/value runtime fields; excludes nonce. |

### AuthChallengeResponse

Response for GET /rbs/v0/challenge (attestation challenge).

| Property | Type | Required | Description |
|---|---|---|---|
| `nonce` | string | yes | Challenge value for binding attestation (opaque; often Base64). |

### AuthType

Authentication method for the user; currently only `jwt` is supported.

Type: string — enum: `"jwt"`

### BuildMetadata

Build-time identity for the running binary.

| Property | Type | Required | Description |
|---|---|---|---|
| `version` | string | yes | Cargo package / release version (semver). |
| `git_hash` | string | yes | Git commit hash at build time (hex), or empty when not embedded at build. |
| `build_date` | string | yes | Build timestamp (UTC), typically RFC 3339, or empty when not embedded at build. |

### CertCreateRequest

Request body for POST cert (create).

| Property | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Certificate name (1-255 chars, GTA-enforced). |
| `type` | array of string | yes | Certificate type list (JSON field name `type`); 1-7 items, each one of `refvalue`, `policy`, `tpm_boot`, `tpm`, `tpm_ima`, `crl`, `ascend_npu`; `crl` must be the only entry. |
| `description` | string | no | Optional description (at most 512 chars). |
| `content` | string | no | Certificate content; required when `cert_type` does not contain `crl`. |
| `crl_content` | string | no | CRL content; required when `cert_type` contains `crl` (which must then be the only entry). |
| `is_default` | boolean | no | Whether to set as default certificate. |

### CertDeleteRequest

Request body for DELETE cert (batch delete).

| Property | Type | Required | Description |
|---|---|---|---|
| `delete_type` | [AttestationDeleteType](#attestationdeletetype) | yes | Delete mode. |
| `ids` | array of string | no | IDs to delete (required when `delete_type` is `Id`; at most 10 IDs). |
| `type` | string | no | Cert type filter (required when `delete_type` is `Type`; JSON field name `type`); one of `refvalue`, `policy`, `tpm_boot`, `tpm`, `tpm_ima`, `crl`, `ascend_npu`. |

### CertListResponse

Paginated response for GET cert list.

| Property | Type | Required | Description |
|---|---|---|---|
| `certs` | array of [CertRecord](#certrecord) | no | List of certificates matching the query. |
| `crls` | array of [CrlRecord](#crlrecord) | no | List of CRL records matching the query. |
| `total_count` | integer(int64) | no | Total matching count. |
| `limit` | integer(int64) | no | Effective page size returned by GTA. |
| `offset` | integer(int64) | no | Effective page offset returned by GTA. |

### CertMutationResponse

Response for POST/PUT cert (create/update mutation).

| Property | Type | Required | Description |
|---|---|---|---|
| `cert` | [CertMutationResult](#certmutationresult) | no | Present when a cert was created/updated. |
| `crl` | [CrlMutationResult](#crlmutationresult) | no | Present when a CRL was created/updated. |

### CertMutationResult

Inner mutation result for cert create/update.

| Property | Type | Required | Description |
|---|---|---|---|
| `cert_id` | string | no | Certificate ID. |
| `cert_name` | string | no | Certificate name. |
| `version` | integer(int32) | no | New version after mutation. |

### CertRecord

Certificate record returned by GTA.

| Property | Type | Required | Description |
|---|---|---|---|
| `cert_id` | string | no | Stable certificate identifier. |
| `cert_name` | string | no | Certificate name. |
| `description` | string | no | Optional description. |
| `content` | string | no | Certificate content (PEM etc.). |
| `cert_type` | array of string | no | Certificate type list. |
| `is_default` | boolean | no | Whether this is the default certificate. |
| `version` | integer(int32) | no | Certificate version. |
| `create_time` | integer(int64) | no | Creation timestamp as Unix epoch seconds or milliseconds, depending on the GTA response. |
| `update_time` | integer(int64) | no | Last update timestamp as Unix epoch seconds or milliseconds, depending on the GTA response. |
| `valid_code` | integer(int32) | no | Validity code. |
| `cert_revoked_date` | integer(int64) | no | Revocation date (Unix epoch seconds). |
| `cert_revoked_reason` | string | no | Revocation reason. |

### CertUpdateRequest

Request body for PUT cert (update).

| Property | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | ID of the certificate to update (1-32 chars, GTA-enforced). |
| `name` | string | no | New name (1-255 chars). |
| `description` | string | no | New description (at most 512 chars). |
| `type` | array of string | no | New certificate type list (JSON field name `type`); 1-7 items, each one of `refvalue`, `policy`, `tpm_boot`, `tpm`, `tpm_ima`, `ascend_npu` — `crl` cannot be set on update. |
| `content` | string | no | Certificate content — GTA rejects this on update. |
| `is_default` | boolean | no | Whether to set as default certificate. |

### ChallengeRequest

Query parameter for GET /rbs/v0/challenge (challenge request).

| Property | Type | Required | Description |
|---|---|---|---|
| `as_provider` | string | no | Optional attestation backend id (e.g. gta); default is deployment-specific. |

### CreatePolicyRequest

Policy create request body.

| Property | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Policy name, unique per user (1-255 chars; `<>\"'&\|\\/*?` and backtick are forbidden). |
| `content_type` | string | yes | Encoding of `content`; only `base64` is supported. |
| `content` | string | yes | Base64-encoded Rego policy text; must decode to valid UTF-8 within the configured size limit. |

### CreateResourceRequest

Request body for `POST /rbs/v0/{uri}` — create a resource.

| Property | Type | Required | Description |
|---|---|---|---|
| `policy_id` | string | yes | UUID of the caller-owned policy that governs reads of this resource. |
| `content_type` | string | no | Content type label; one of `jwt`, `json`, `text`, `binary`, `jwk`, `jwe` (fixed whitelist). |
| `export_mode` | string | no | Export mode on read; only `jwe` is accepted (plaintext export is rejected); defaults to `jwe`. |
| `additional_info` | string | no | Free-form description of the resource; when present, 1-512 chars (empty string rejected). |
| `content` | string | no | Base64-encoded content, stored via the backend when it supports PUT. Optional for backends that generate the object themselves (e.g. CA) or require it to pre-exist. |

### CrlMutationResult

Inner mutation result for CRL create.

| Property | Type | Required | Description |
|---|---|---|---|
| `crl_id` | string | no | CRL ID. |
| `crl_name` | string | no | CRL name. |

### CrlRecord

CRL (Certificate Revocation List) record returned by GTA.

| Property | Type | Required | Description |
|---|---|---|---|
| `crl_id` | string | no | Stable CRL identifier. |
| `crl_name` | string | no | CRL name. |
| `crl_content` | string | no | CRL content. |

### ErrorBody

Error payload for HTTP error responses (e.g. 500).

| Property | Type | Required | Description |
|---|---|---|---|
| `error` | string | yes | Error string for the caller. |

### PolicyCreateRequest

Request body for POST attestation policy (create).

| Property | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Policy name (1-255 chars; GTA rejects the special characters `< > " ' & \| \ / * ?` and backtick). |
| `attester_type` | array of string | yes | Attester type list (1-9 items, each at most 255 chars); supported values: `all`, `tpm`, `tpm_boot`, `tpm_ima`, `virt_cca`, `ascend_npu`, `itrustee`, `cca`, `dice`. |
| `content_type` | string | yes | Content encoding (required): `jwt` or `text` (GTA-enforced). |
| `content` | string | yes | Policy content (base64-encoded); the decoded size is bounded by GTA's `policy_content_size_limit` (shipped default 500 KB). |
| `is_default` | boolean | no | Whether to set as default policy. |
| `description` | string | no | Optional description (at most 512 chars). |

### PolicyDeleteRequest

Request body for DELETE policy (batch delete).

| Property | Type | Required | Description |
|---|---|---|---|
| `delete_type` | [PolicyDeleteType](#policydeletetype) | yes | Delete mode. |
| `ids` | array of string | no | IDs to delete (required when `delete_type` is `Id`; at most 10 IDs, each at most 36 chars). |
| `attester_type` | string | no | Attester type filter (required when `delete_type` is `AttesterType`; at most 255 chars). |

### PolicyDeleteType

Delete mode for policy DELETE operations.

Type: string — enum: `"id"`, `"all"`, `"attester_type"`

### PolicyListResponse

Policy list response.

| Property | Type | Required | Description |
|---|---|---|---|
| `items` | array of [PolicyResponse](#policyresponse) | yes | Current page of policies. |
| `total_count` | integer(int64) | yes | Total matching policies (not only this page). |
| `limit` | integer(int64) | yes | Effective page size (mirrors the request `limit`). |
| `offset` | integer(int64) | yes | Effective page offset (mirrors the request `offset`). |

### PolicyMutation

Inner mutation result for policy create/update.

| Property | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | ID of the mutated policy. |
| `name` | string | yes | Name of the mutated policy. |
| `version` | integer(int32) | yes | New version after mutation. |

### PolicyMutationResponse

Response for POST/PUT policy (create/update).

| Property | Type | Required | Description |
|---|---|---|---|
| `policy` | [PolicyMutation](#policymutation) | yes | Mutation result. |

### PolicyResponse

Policy response returned to callers.

| Property | Type | Required | Description |
|---|---|---|---|
| `policy_id` | string | yes | Policy ID (UUID v4), generated by RBS. |
| `policy_name` | string | yes | Policy name, unique per user. |
| `policy_version` | integer(int32) | yes | Monotonic version: starts at 1 and increments on every update (optimistic-lock token). |
| `content_type` | string | yes | Encoding of the stored policy content (always `base64`). |
| `created_at` | string | yes | Creation time (RFC 3339). |
| `updated_at` | string | yes | Last update time (RFC 3339). |
| `applied_resources` | array of string | no | URIs of resources bound to this policy; only returned by single-policy GET (omitted elsewhere). |

### PolicyUpdateRequest

Request body for PUT attestation policy (update).

| Property | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | ID of the policy to update (1-36 chars, GTA-enforced). |
| `name` | string | no | New name (1-255 chars; GTA rejects the special characters `< > " ' & \| \ / * ?` and backtick). |
| `description` | string | no | New description (at most 512 chars). |
| `attester_type` | array of string | no | New attester type list (1-9 items, each at most 255 chars). |
| `content_type` | string | no | New content encoding: `jwt` or `text`. |
| `content` | string | no | New policy content (base64-encoded; decoded size limited as on create). |
| `is_default` | boolean | no | Whether to set as default policy. |

### RbcEvidenceItem

Single attestation artifact within a measurement (backend-specific detail).

| Property | Type | Required | Description |
|---|---|---|---|
| `attester_type` | string | no | Plugin or attester kind (e.g. tpm_boot). |
| `evidence` | any | no | Evidence payload (string or object per attestation backend). |
| `policy_ids` | array of string | no | Policy identifiers evaluated for this evidence. |
| `ref_value_id` | string | no | Optional reference value ID for precise baseline matching. |

### RbcEvidencesPayload

Evidence JSON produced by RBC (`collect_evidence`) or equivalent.

| Property | Type | Required | Description |
|---|---|---|---|
| `agent_version` | string | no | Optional agent or collector version string. |
| `measurements` | array of [RbcMeasurement](#rbcmeasurement) | no | At least one entry required for standard attest flows; each entry carries nonce and evidences. |

### RbcMeasurement

One node or attestation unit inside the evidence bundle.

| Property | Type | Required | Description |
|---|---|---|---|
| `nonce` | string | yes | Must equal the `nonce` field from GET /rbs/v0/challenge (same string, no transformation). |
| `node_id` | string | no | Optional node or workload identifier. |
| `nonce_type` | string | no | Optional hint for nonce interpretation (backend-specific). |
| `token_fmt` | string | no | Optional desired token format hint (backend-specific). |
| `attester_data` | [AttesterData](#attesterdata) | no | Attester-supplied metadata for this measurement. |
| `evidences` | array of [RbcEvidenceItem](#rbcevidenceitem) | no | Collected attestation artifacts for this measurement. |

### RbsVersion

JSON emitted by `GET /rbs/version` (`service_name`, `api_version`, structured `build`).

| Property | Type | Required | Description |
|---|---|---|---|
| `service_name` | string | yes | Logical service display name. |
| `api_version` | string | yes | Published API contract version string. |
| `build` | [BuildMetadata](#buildmetadata) | yes | Build metadata (`version`, `git_hash`, `build_date`) for this binary; same shape as in the exported `OpenAPI` schema. |

### RefValue

Reference value (baseline) entity returned by GTA.

| Property | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Stable ref_value identifier. |
| `uid` | string | no | User-scoped identifier (by_ids path only). |
| `name` | string | yes | Human-readable baseline name. |
| `attester_type` | string | yes | Attester type (e.g. tpm, tpm_ima, virt_cca). |
| `description` | string | no | Optional description (by_ids path only). |
| `content` | string | no | Baseline content (JWT or base64-encoded payload) (by_ids path only). |
| `content_type` | string | no | Content encoding: "jwt" (default) or "base64" (by_ids path only). |
| `version` | integer(int32) | no | Baseline version (by_ids path only). |
| `valid_code` | integer(int32) | no | Validity code: 0 = valid, 1 = invalid (by_ids path only). |

### RefValueCreateRequest

Request body for POST ref_value (create).

| Property | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Baseline name (1-255 chars, GTA-enforced). |
| `attester_type` | string | yes | Attester type; one of `tpm`, `tpm_ima`, `virt_cca`, `ascend_npu`, `cca` (GTA-enforced). |
| `content` | string | yes | Baseline content — JWT or base64-encoded payload; at most 100 MiB (GTA-enforced). |
| `content_type` | string | no | Content encoding: `jwt` (default when omitted) or `base64`. |
| `description` | string | no | Optional description (at most 512 chars, GTA-enforced). |

### RefValueDeleteRequest

Request body for DELETE ref_value (batch delete).

| Property | Type | Required | Description |
|---|---|---|---|
| `delete_type` | [AttestationDeleteType](#attestationdeletetype) | yes | Delete mode. |
| `ids` | array of string | no | IDs to delete (required when `delete_type` is `Id`; 1-10 IDs, each 1-36 chars). |
| `attester_type` | string | no | Attester type filter (required when `delete_type` is `Type`); one of `tpm`, `tpm_ima`, `virt_cca`, `ascend_npu`, `cca`. |

### RefValueListResponse

Paginated response for GET ref_value list.

| Property | Type | Required | Description |
|---|---|---|---|
| `ref_values` | array of [RefValue](#refvalue) | yes | List of ref_values matching the query. |
| `total_count` | integer(int64) | no | Total matching count (present in by_type/all paths; absent in by_ids path). |
| `limit` | integer(int64) | no | Effective page size returned by GTA. |
| `offset` | integer(int64) | no | Effective page offset returned by GTA. |

### RefValueMutation

Inner mutation result for ref_value create/update.

| Property | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | ID of the mutated ref_value. |
| `name` | string | yes | Name of the mutated ref_value. |
| `version` | integer(int32) | yes | New version after mutation. |

### RefValueMutationResponse

Response for POST/PUT ref_value (create/update).

| Property | Type | Required | Description |
|---|---|---|---|
| `ref_value` | [RefValueMutation](#refvaluemutation) | yes | Mutation result. |

### RefValueUpdateRequest

Request body for PUT ref_value (update).

| Property | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | ID of the ref_value to update (1-36 chars, GTA-enforced). |
| `name` | string | no | New name (1-255 chars). |
| `description` | string | no | New description (at most 512 chars). |
| `attester_type` | string | no | New attester_type; one of `tpm`, `tpm_ima`, `virt_cca`, `ascend_npu`, `cca`. |
| `content` | string | no | New content (at most 100 MiB). |
| `content_type` | string | no | New content encoding: `jwt` or `base64`. |

### ResourceContentResponse

Resource content returned by GET and POST .../retrieve.

| Property | Type | Required | Description |
|---|---|---|---|
| `uri` | string | yes | Canonical resource URI for the returned object. |
| `content` | string | yes | Base64-encoded JWE ciphertext. |
| `content_type` | string | no | Content type label (`jwt`, `json`, `text`, `binary`, `jwk`, `jwe`) for decoding the decrypted content. |
| `export_mode` | string | yes | Export mode; always `jwe`. |

### ResourceInfoResponse

Resource metadata returned by GET .../info (no secret material).

| Property | Type | Required | Description |
|---|---|---|---|
| `uri` | string | yes | Canonical resource URI. |
| `user_id` | string | yes | Username of the resource owner. |
| `policy_id` | string | yes | UUID of the policy bound to this resource. |
| `created_at` | string | yes | Creation time (RFC 3339). |
| `updated_at` | string | yes | Last update time (RFC 3339). |
| `content_type` | string | no | Content type label (`jwt`, `json`, `text`, `binary`, `jwk`, `jwe`), if set. |
| `export_mode` | string | yes | Export mode of the resource; always `jwe`. |

### ResourceResponse

Resource metadata returned after create or update.

| Property | Type | Required | Description |
|---|---|---|---|
| `uri` | string | yes | Canonical resource URI: `/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}`. |
| `provider_name` | string | yes | Backend provider name (first URI segment). |
| `repository_name` | string | yes | Backend repository name (second URI segment). |
| `resource_type` | string | yes | Resource type (third URI segment), e.g. `secret`, `cert`, `key`. |
| `resource_name` | string | yes | Resource name (fourth URI segment). |
| `created_at` | string | yes | Creation time (RFC 3339). |
| `updated_at` | string | yes | Last update time (RFC 3339). |
| `content_type` | string | no | Content type label (`jwt`, `json`, `text`, `binary`, `jwk`, `jwe`), if set. |
| `export_mode` | string | yes | Export mode of the resource; always `jwe`. |
| `policy_id` | string | yes | UUID of the policy bound to this resource. |
| `additional_info` | string | no | Free-form description (1-512 chars), if set. |

### Role

User role. `Admin` is pre-configured and cannot be created via the API.

Type: string — enum: `"admin"`, `"user"`

### UpdatePolicyRequest

Policy update request body. All fields are required (full replacement).

| Property | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | New policy name, unique per user (1-255 chars; `<>\"'&\|\\/*?` and backtick are forbidden). |
| `content_type` | string | yes | New encoding of `content`; only `base64` is supported. |
| `content` | string | yes | New base64-encoded Rego policy text; must decode to valid UTF-8 within the configured size limit. |

### UpdateResourceRequest

Request body for `PUT /rbs/v0/{uri}` — update or create a resource.

| Property | Type | Required | Description |
|---|---|---|---|
| `policy_id` | string | no | New policy binding (must be caller-owned); omitted keeps the current binding. Required when the upsert creates a new resource. |
| `content_type` | string | no | New content type label (`jwt`, `json`, `text`, `binary`, `jwk`, `jwe`); omitted keeps the current value. |
| `export_mode` | string | no | New export mode; only `jwe` is accepted; omitted keeps the current value. |
| `additional_info` | string | no | New description (when present, 1-512 chars); omitted keeps the current value. |
| `content` | string | no | Base64-encoded replacement content; omitted leaves the backend content unchanged. |

### UserCreateRequest

Request body for POST /rbs/v0/users (create user).

| Property | Type | Required | Description |
|---|---|---|---|
| `username` | string | yes | Login or unique handle. Immutable. |
| `role` | [Role](#role) | no | Optional role; only `user` is allowed via API (admin is pre-configured). |
| `enabled` | boolean | no | Whether the account is enabled. |
| `auth_type` | [AuthType](#authtype) | yes | Authentication method; currently only `jwt` is supported. |
| `public_key` | string | no | Base64-encoded PEM public key (mutually exclusive with `jwk`). |
| `jwk` | any | no | JWK public key JSON object (mutually exclusive with `public_key`). |

### UserListResponse

Paginated response for GET /rbs/v0/users.

| Property | Type | Required | Description |
|---|---|---|---|
| `users` | array of [UserResponse](#userresponse) | yes | Page of users. |
| `total_count` | integer(int64) | yes | Total matching users (not only this page). |
| `limit` | integer(int64) | yes | Effective page size (may mirror request `limit`). |
| `offset` | integer(int64) | yes | Effective skip count (may mirror request `offset`). |

### UserResponse

Response for user retrieval, creation, and update.

| Property | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Stable user ID (UUID). |
| `username` | string | yes | Human-facing login or handle. |
| `role` | [Role](#role) | yes | User role. |
| `enabled` | boolean | yes | Whether the account is enabled. |
| `created_at` | string | yes | Creation time (RFC 3339). |
| `updated_at` | string | yes | Last modification time (RFC 3339). |

### UserUpdateRequest

Request body for PUT /rbs/v0/users/{username} (update user).

| Property | Type | Required | Description |
|---|---|---|---|
| `role` | [Role](#role) | no | New role; only the target's current role is accepted — any other value is rejected with 403. |
| `enabled` | boolean | no | Whether the account can authenticate. |
| `auth_type` | [AuthType](#authtype) | no | New authentication method; currently only `jwt` is supported. |
| `public_key` | string | no | Base64-encoded PEM public key (mutually exclusive with `jwk`). |
| `jwk` | any | no | JWK public key JSON object (mutually exclusive with `public_key`). |

---

_Generated by [oas-to-markdown](https://www.npmjs.com/package/oas-to-markdown)._
