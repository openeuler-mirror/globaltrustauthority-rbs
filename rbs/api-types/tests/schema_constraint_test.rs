/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You may use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A
 * PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Schema/param constraint consistency tests.
//!
//! Every `#[validate(length|range)]` rule on an OpenAPI-documented type must be
//! mirrored in its utoipa `#[schema]` / `#[param]` constraints so the generated
//! OpenAPI contract (`docs/proto/rbs_rest_api.yaml`) and the docs rendered from
//! it carry the real validation rules. When a `#[validate]` annotation changes,
//! update the matching expectation here — and the corresponding `#[schema]` /
//! `#[param]` attribute — in the same change.
//!
//! Custom validators that cannot be expressed as OpenAPI constraints are mapped
//! to `pattern` only where the mapping is exact:
//! - `validate_username_chars`  -> `^[a-zA-Z0-9_-]+$`
//! - `validate_policy_name`     -> blacklist of `POLICY_NAME_BLACKLIST`
//! - `validate_content_type`    -> whitelist (`base64`)
//! `validate_create_role` (create rejects `role: admin`) is semantic and stays
//! in the field description.

use rbs_api_types::policy::{POLICY_IDS_QUERY_MAX_LEN, POLICY_NAME_MAX_LEN};
use rbs_api_types::{
    CertCreateRequest, CertListQuery, CreatePolicyRequest, CreateResourceRequest, PolicyCreateRequest,
    PolicyListQuery as ResourcePolicyListQuery, RefValueCreateRequest, RefValueListQuery,
    UpdatePolicyRequest, UpdateResourceRequest, UserCreateRequest, UserListQuery, USERNAME_MAX_LEN,
};
use rbs_api_types::attestation_mgmt::PolicyListQuery as AttestationPolicyListQuery;
use utoipa::{IntoParams, ToSchema};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn schema_of<T: ToSchema>() -> serde_json::Value {
    serde_json::to_value(T::schema()).expect("serialize ToSchema::schema()")
}

fn prop<'a>(schema: &'a serde_json::Value, field: &str) -> &'a serde_json::Value {
    schema
        .get("properties")
        .and_then(|p| p.as_object())
        .unwrap_or_else(|| panic!("schema has no properties"))
        .get(field)
        .unwrap_or_else(|| panic!("schema has no property `{field}`"))
}

/// Serialize a query struct's params the way the `#[utoipa::path]` macro does
/// (no `parameter_in` provider: `|| None`). The container attribute
/// `#[into_params(parameter_in = Query)]` must keep them in `query`.
fn params_of<T: IntoParams>() -> Vec<serde_json::Value> {
    T::into_params(|| None)
        .iter()
        .map(|p| serde_json::to_value(p).expect("serialize Parameter"))
        .collect()
}

fn param<'a>(params: &'a [serde_json::Value], name: &str) -> &'a serde_json::Value {
    params
        .iter()
        .find(|p| p.get("name").and_then(|n| n.as_str()) == Some(name))
        .unwrap_or_else(|| panic!("no parameter `{name}`"))
}

fn expect_str(v: &serde_json::Value, key: &str, want: &str) {
    let got = v.get(key).and_then(|k| k.as_str());
    assert_eq!(got, Some(want), "unexpected `{key}`: got {got:?}, want {want:?}");
}

fn expect_u64(v: &serde_json::Value, key: &str, want: u64) {
    let got = v.get(key).and_then(|k| k.as_u64());
    assert_eq!(got, Some(want), "unexpected `{key}`: got {got:?}, want {want}");
}

fn expect_query_optional(v: &serde_json::Value) {
    expect_str(v, "in", "query");
    assert_eq!(v.get("required").and_then(|r| r.as_bool()), Some(false));
}

// ── Body schemas ─────────────────────────────────────────────────────────────

#[test]
fn user_create_username_constraints() {
    let s = schema_of::<UserCreateRequest>();
    let username = prop(&s, "username");
    expect_u64(username, "minLength", 1);
    expect_u64(username, "maxLength", USERNAME_MAX_LEN as u64);
    expect_str(username, "pattern", "^[a-zA-Z0-9_-]+$");
}

#[test]
fn resource_policy_id_constraints() {
    let create = schema_of::<CreateResourceRequest>();
    expect_u64(prop(&create, "policy_id"), "minLength", 1);
    expect_u64(prop(&create, "policy_id"), "maxLength", 36);

    let update = schema_of::<UpdateResourceRequest>();
    expect_u64(prop(&update, "policy_id"), "minLength", 1);
    expect_u64(prop(&update, "policy_id"), "maxLength", 36);
}

#[test]
fn rbs_policy_request_constraints() {
    for schema in [schema_of::<CreatePolicyRequest>(), schema_of::<UpdatePolicyRequest>()] {
        let name = prop(&schema, "name");
        expect_u64(name, "minLength", 1);
        expect_u64(name, "maxLength", POLICY_NAME_MAX_LEN);
        expect_str(name, "pattern", "^[^<>\"'&|\\\\/*?`]*$");
        expect_str(prop(&schema, "content_type"), "pattern", "^base64$");
        expect_u64(prop(&schema, "content"), "minLength", 1);
    }
}

#[test]
fn ref_value_create_constraints() {
    let s = schema_of::<RefValueCreateRequest>();
    expect_u64(prop(&s, "name"), "minLength", 1);
    expect_u64(prop(&s, "attester_type"), "minLength", 1);
    expect_u64(prop(&s, "content"), "minLength", 1);
}

#[test]
fn cert_create_name_constraint() {
    expect_u64(prop(&schema_of::<CertCreateRequest>(), "name"), "minLength", 1);
}

#[test]
fn attestation_policy_create_constraints() {
    let s = schema_of::<PolicyCreateRequest>();
    expect_u64(prop(&s, "name"), "minLength", 1);
    expect_u64(prop(&s, "attester_type"), "minItems", 1);
    expect_u64(prop(&s, "content_type"), "minLength", 1);
    expect_u64(prop(&s, "content"), "minLength", 1);
}

// ── Query parameters ─────────────────────────────────────────────────────────

#[test]
fn user_list_query_constraints() {
    let params = params_of::<UserListQuery>();
    expect_query_optional(param(&params, "limit"));
    expect_query_optional(param(&params, "offset"));

    let limit = param(&params, "limit").get("schema").expect("limit schema");
    expect_u64(limit, "minimum", 1);
    expect_u64(limit, "maximum", 100);
    let offset = param(&params, "offset").get("schema").expect("offset schema");
    expect_u64(offset, "minimum", 0);
    expect_u64(offset, "maximum", 100_000);
}

#[test]
fn resource_policy_list_query_constraints() {
    let params = params_of::<ResourcePolicyListQuery>();
    expect_query_optional(param(&params, "ids"));
    expect_query_optional(param(&params, "limit"));
    expect_query_optional(param(&params, "offset"));

    let ids = param(&params, "ids").get("schema").expect("ids schema");
    expect_u64(ids, "minLength", 1);
    expect_u64(ids, "maxLength", POLICY_IDS_QUERY_MAX_LEN);
    let limit = param(&params, "limit").get("schema").expect("limit schema");
    expect_u64(limit, "minimum", 1);
    expect_u64(limit, "maximum", 100);
    let offset = param(&params, "offset").get("schema").expect("offset schema");
    expect_u64(offset, "minimum", 0);
    expect_u64(offset, "maximum", 100_000);
}

#[test]
fn attestation_list_query_constraints() {
    for (name, params) in [
        ("RefValueListQuery", params_of::<RefValueListQuery>()),
        ("CertListQuery", params_of::<CertListQuery>()),
        ("AttestationPolicyListQuery", params_of::<AttestationPolicyListQuery>()),
    ] {
        let limit = param(&params, "limit");
        let offset = param(&params, "offset");
        expect_query_optional(limit);
        expect_query_optional(offset);
        let limit_schema = limit.get("schema").unwrap_or_else(|| panic!("{name} limit schema"));
        expect_u64(limit_schema, "minimum", 1);
        expect_u64(limit_schema, "maximum", 10);
        let offset_schema = offset.get("schema").unwrap_or_else(|| panic!("{name} offset schema"));
        expect_u64(offset_schema, "minimum", 0);
        expect_u64(offset_schema, "maximum", 100_000);
    }
}

#[test]
fn query_structs_keep_provider_independent_query_location() {
    // Regression guard: without `#[into_params(parameter_in = Query)]`, a bare
    // struct in `params(...)` resolves `ParameterIn::default()` (Path) and
    // marks every field required — breaking the published contract.
    for p in params_of::<UserListQuery>() {
        expect_query_optional(&p);
    }
    for p in params_of::<ResourcePolicyListQuery>() {
        expect_query_optional(&p);
    }
}
