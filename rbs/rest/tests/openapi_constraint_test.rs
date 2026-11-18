/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A
 * PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Spot checks that `ApiDoc` (the source of `docs/proto/rbs_rest_api.yaml`)
//! actually carries the field constraints asserted per-type in
//! `rbs-api-types` (`tests/schema_constraint_test.rs`). This guards the
//! `components(schemas(...))` registration list in `api_doc/document.rs`:
//! a schema dropped there would silently lose its constraints in the
//! published contract even though the per-type tests still pass.

use rbs_rest::ApiDoc;
use utoipa::OpenApi;

fn component(name: &str) -> serde_json::Value {
    let doc = serde_json::to_value(ApiDoc::openapi()).expect("serialize OpenAPI document");
    let schemas = &doc["components"]["schemas"];
    schemas.get(name).unwrap_or_else(|| panic!("`{name}` is not registered in ApiDoc components")).clone()
}

fn prop<'a>(schema: &'a serde_json::Value, field: &str) -> &'a serde_json::Value {
    schema["properties"].get(field).unwrap_or_else(|| panic!("`{field}` property missing"))
}

#[test]
fn api_doc_carries_user_and_resource_constraints() {
    let user_create = component("UserCreateRequest");
    let username = prop(&user_create, "username");
    assert_eq!(username["minLength"].as_u64(), Some(1));
    assert_eq!(username["maxLength"].as_u64(), Some(36));
    assert_eq!(username["pattern"].as_str(), Some("^[a-zA-Z0-9_-]+$"));

    let create_resource = component("CreateResourceRequest");
    let policy_id = prop(&create_resource, "policy_id");
    assert_eq!(policy_id["minLength"].as_u64(), Some(1));
    assert_eq!(policy_id["maxLength"].as_u64(), Some(36));
}

#[test]
fn api_doc_carries_policy_and_attestation_constraints() {
    let create_policy = component("CreatePolicyRequest");
    let name = prop(&create_policy, "name");
    assert_eq!(name["maxLength"].as_u64(), Some(255));
    assert_eq!(name["pattern"].as_str(), Some("^[^<>\"'&|\\\\/*?`]*$"));

    let att_policy = component("PolicyCreateRequest");
    let attester_type = prop(&att_policy, "attester_type");
    assert_eq!(attester_type["minItems"].as_u64(), Some(1));
}

#[test]
fn api_doc_query_params_stay_optional_query_constraints() {
    let doc = serde_json::to_value(ApiDoc::openapi()).expect("serialize OpenAPI document");
    let users_get = &doc["paths"]["/rbs/v0/users"]["get"];
    let params = users_get["parameters"].as_array().expect("listUsers parameters");

    let limit = params.iter().find(|p| p["name"] == "limit").expect("limit parameter");
    assert_eq!(limit["in"].as_str(), Some("query"));
    assert_eq!(limit["required"].as_bool(), Some(false));
    assert_eq!(limit["schema"]["minimum"].as_u64(), Some(1));
    assert_eq!(limit["schema"]["maximum"].as_u64(), Some(100));
}

#[test]
fn api_doc_carries_resource_list_endpoint_and_constraints() {
    let doc = serde_json::to_value(ApiDoc::openapi()).expect("serialize OpenAPI document");

    // Path registered with the listResources operation.
    let list_get = &doc["paths"]["/rbs/v0/resource"]["get"];
    assert_eq!(
        list_get["operationId"].as_str(),
        Some("listResources"),
        "GET /rbs/v0/resource must be registered as listResources"
    );
    let params = list_get["parameters"].as_array().expect("listResources parameters");
    let limit = params.iter().find(|p| p["name"] == "limit").expect("limit parameter");
    assert_eq!(limit["in"].as_str(), Some("query"));
    assert_eq!(limit["required"].as_bool(), Some(false));
    assert_eq!(limit["schema"]["minimum"].as_u64(), Some(1));
    assert_eq!(limit["schema"]["maximum"].as_u64(), Some(100));
    let offset = params.iter().find(|p| p["name"] == "offset").expect("offset parameter");
    assert_eq!(offset["in"].as_str(), Some("query"));
    assert_eq!(offset["schema"]["minimum"].as_u64(), Some(0));
    assert_eq!(offset["schema"]["maximum"].as_u64(), Some(100_000));

    // Response schema registered in components.
    let list_resp = component("ResourceListResponse");
    assert!(list_resp["properties"].get("items").is_some(), "ResourceListResponse must expose items");
    assert_eq!(list_resp["properties"]["total_count"]["format"].as_str(), Some("int64"));
}

/// Compare the Actix registrations to the published method/path set. Keep the
/// wildcard expansion here because OpenAPI describes its four validated segments.
#[test]
fn api_doc_covers_registered_routes() {
    use std::collections::BTreeSet;

    fn registrations(source: &str, prefix: &str) -> BTreeSet<(String, String)> {
        let mut routes = BTreeSet::new();
        let mut current = String::new();
        for line in source.lines().map(str::trim) {
            if line.starts_with("//") {
                continue;
            }
            if let Some(rest) = line.strip_prefix("web::resource(\"") {
                current = rest.split('"').next().unwrap().to_string();
            }
            if let Some(rest) = line.strip_prefix(".route(\"") {
                current = rest.split('"').next().unwrap().to_string();
            }
            if !line.contains(".to(") {
                continue;
            }
            for method in ["get", "post", "put", "delete", "patch", "head", "options", "trace"] {
                if line.contains(&format!("web::{method}().to(")) {
                    assert!(!current.is_empty(), "unrecognized route registration: {line}");
                    let path =
                        current.replace("{uri:.+}", "{res_provider}/{repository_name}/{resource_type}/{resource_name}");
                    assert!(routes.insert((format!("{prefix}{path}"), method.to_string())));
                }
            }
        }
        routes
    }

    let mut expected = registrations(include_str!("../src/routes/mod.rs"), "/rbs/v0");
    expected.extend(registrations(include_str!("../src/server/http.rs"), "/rbs"));
    assert!(!expected.is_empty());
    let doc = serde_json::to_value(ApiDoc::openapi()).unwrap();
    let actual: BTreeSet<_> = doc["paths"]
        .as_object()
        .unwrap()
        .iter()
        .flat_map(|(path, item)| {
            item.as_object()
                .unwrap()
                .keys()
                .filter(|method| {
                    ["get", "post", "put", "delete", "patch", "head", "options", "trace"].contains(&method.as_str())
                })
                .map(move |method| (path.clone(), method.clone()))
        })
        .collect();
    assert_eq!(actual, expected, "Actix routes and OpenAPI operations must agree");
}

#[test]
fn api_doc_references_resolve_and_security_matches_headers() {
    fn check_refs(value: &serde_json::Value, doc: &serde_json::Value) {
        match value {
            serde_json::Value::Object(fields) => {
                if let Some(reference) = fields.get("$ref").and_then(|v| v.as_str()) {
                    let pointer = reference.strip_prefix('#').expect("local OpenAPI reference");
                    assert!(doc.pointer(pointer).is_some(), "unresolved reference: {reference}");
                }
                for child in fields.values() {
                    check_refs(child, doc);
                }
            },
            serde_json::Value::Array(items) => {
                for child in items {
                    check_refs(child, doc);
                }
            },
            _ => {},
        }
    }
    let doc = serde_json::to_value(ApiDoc::openapi()).unwrap();
    check_refs(&doc, &doc);
    let schemes = &doc["components"]["securitySchemes"];
    assert_eq!(schemes["attestAuth"]["type"], "apiKey");
    assert_eq!(schemes["attestAuth"]["in"], "header");
    assert_eq!(schemes["attestAuth"]["name"], "Authorization");
    assert!(schemes["attestAuth"]["description"].as_str().unwrap().contains("Attest <token>"));
    assert_eq!(schemes["bearerAuth"]["scheme"], "bearer");
    assert_eq!(doc["paths"]["/rbs/v0/challenge"]["get"]["security"], serde_json::json!([{}]));
    assert_eq!(doc["paths"]["/rbs/v0/users"]["get"]["security"], serde_json::json!([{"bearerAuth": []}]));
    let resource = "/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}";
    assert_eq!(doc["paths"][resource]["get"]["security"], serde_json::json!([{"bearerAuth": []}, {"attestAuth": []}]));
    assert_eq!(doc["paths"][format!("{resource}/retrieve")]["post"]["security"], serde_json::json!([{}]));
}

#[test]
fn api_doc_documents_validation_and_resource_backend_errors() {
    let doc = serde_json::to_value(ApiDoc::openapi()).unwrap();
    for (path, item) in doc["paths"].as_object().unwrap() {
        for (method, operation) in item.as_object().unwrap() {
            let Some(responses) = operation.get("responses") else {
                continue;
            };
            for status in ["414", "429"] {
                assert!(responses.get(status).is_some(), "{method} {path}: missing {status}");
            }
            if operation.get("requestBody").is_some()
                || operation["parameters"].as_array().is_some_and(|params| params.iter().any(|p| p["in"] == "query"))
            {
                assert!(responses.get("400").is_some(), "{method} {path}: missing 400");
            }
        }
    }
    for method in ["get", "put", "delete"] {
        assert!(doc["paths"]["/rbs/v0/resource/policy/{policy_id}"][method]["responses"].get("400").is_some(),
            "{method} policy detail: invalid path IDs must document 400");
    }
    let resource = "/rbs/v0/{res_provider}/{repository_name}/{resource_type}/{resource_name}";
    for method in ["get", "post", "put", "delete"] {
        for status in ["400", "502"] {
            assert!(doc["paths"][resource][method]["responses"].get(status).is_some());
        }
    }
    assert_eq!(
        doc["paths"][format!("{resource}/info")]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
            ["$ref"],
        "#/components/schemas/ResourceResponse"
    );
    assert!(doc["components"]["schemas"].get("ResourceInfoResponse").is_none());
}
