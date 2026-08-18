/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You may use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

//! Integration tests for attestation management API types.
//!
//! Covers TC1–TC4, TC7, TC11–TC13, TC16 from the module test design.

use rbs_api_types::error::RbsError;
use rbs_api_types::{
    AttestationDeleteType, ErrorBody,
    PolicyMutation, PolicyMutationResponse, RefValue, RefValueCreateRequest,
    RefValueDeleteRequest, RefValueListQuery, RefValueListResponse, RefValueMutation,
    RefValueMutationResponse, RefValueUpdateRequest,
};
use validator::Validate;

// ===========================================================================
// TC1: RefValue serialization round-trip
// ===========================================================================

#[test]
fn tc1_ref_value_round_trip() {
    let json = r#"{"id":"R1","uid":"U1","name":"baseline1","description":"desc","attester_type":"tpm","content":"base64data","content_type":"base64","version":1,"valid_code":0}"#;
    let rv: RefValue = serde_json::from_str(json).unwrap();
    assert_eq!(rv.id, "R1");
    assert_eq!(rv.uid.as_deref(), Some("U1"));
    assert_eq!(rv.name, "baseline1");
    assert_eq!(rv.description.as_deref(), Some("desc"));
    assert_eq!(rv.attester_type, "tpm");
    assert_eq!(rv.content.as_deref(), Some("base64data"));
    assert_eq!(rv.content_type.as_deref(), Some("base64"));
    assert_eq!(rv.version, Some(1));
    assert_eq!(rv.valid_code, Some(0));

    // Re-serialize and verify snake_case keys
    let out = serde_json::to_string(&rv).unwrap();
    assert!(out.contains("\"attester_type\""));
    assert!(out.contains("\"content_type\""));
    assert!(out.contains("\"valid_code\""));
}

// ===========================================================================
// TC1b: GTA by_type/all summary shape — only id/name/attester_type present
// (regression for missing-field deserialization failure)
// ===========================================================================

#[test]
fn tc1b_ref_value_summary_shape_no_extra_fields() {
    let json = r#"{"id":"R1","name":"baseline1","attester_type":"tpm"}"#;
    let rv: RefValue = serde_json::from_str(json).unwrap();
    assert_eq!(rv.id, "R1");
    assert_eq!(rv.name, "baseline1");
    assert_eq!(rv.attester_type, "tpm");
    assert!(rv.uid.is_none());
    assert!(rv.description.is_none());
    assert!(rv.content.is_none());
    assert!(rv.content_type.is_none());
    assert!(rv.version.is_none());
    assert!(rv.valid_code.is_none());

    // Unknown fields (e.g. stray "uid") are ignored, not rejected
    let json_with_uid = r#"{"id":"R1","name":"baseline1","attester_type":"tpm","uid":"U1"}"#;
    let rv2: RefValue = serde_json::from_str(json_with_uid).unwrap();
    assert_eq!(rv2.id, "R1");

    // Missing mandatory field (id) → deserialization fails
    assert!(serde_json::from_str::<RefValue>(r#"{"name":"x","attester_type":"t"}"#).is_err());
}

// ===========================================================================
// TC2: RefValueListQuery with all optional fields
// ===========================================================================

#[test]
fn tc2_list_query_with_optional_fields() {
    let json = r#"{"ids":"R1,R2","attester_type":"tpm","limit":10,"offset":0}"#;
    let query: RefValueListQuery = serde_json::from_str(json).unwrap();
    assert_eq!(query.ids.as_deref(), Some("R1,R2"));
    assert_eq!(query.attester_type.as_deref(), Some("tpm"));
    assert_eq!(query.limit, Some(10));
    assert_eq!(query.offset, Some(0));
}

// ===========================================================================
// TC3: AttestationDeleteType enum serialization
// ===========================================================================

#[test]
fn tc3_delete_type_serialization() {
    assert_eq!(
        serde_json::to_string(&AttestationDeleteType::Id).unwrap(),
        "\"id\""
    );
    assert_eq!(
        serde_json::to_string(&AttestationDeleteType::All).unwrap(),
        "\"all\""
    );
    assert_eq!(
        serde_json::to_string(&AttestationDeleteType::Type).unwrap(),
        "\"type\""
    );

    // Round-trip deserialization
    let id_val: AttestationDeleteType = serde_json::from_str("\"id\"").unwrap();
    assert_eq!(id_val, AttestationDeleteType::Id);
    let all_val: AttestationDeleteType = serde_json::from_str("\"all\"").unwrap();
    assert_eq!(all_val, AttestationDeleteType::All);
    let by_type_val: AttestationDeleteType = serde_json::from_str("\"type\"").unwrap();
    assert_eq!(by_type_val, AttestationDeleteType::Type);
}

// ===========================================================================
// TC4: Mutation response serialization
// ===========================================================================

#[test]
fn tc4_mutation_response_serialization() {
    let resp = RefValueMutationResponse {
        ref_value: RefValueMutation {
            id: "R1".to_string(),
            name: "baseline1".to_string(),
            version: 2,
        },
    };
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("\"ref_value\""));
    assert!(json.contains("\"id\":\"R1\""));
    assert!(json.contains("\"name\":\"baseline1\""));
    assert!(json.contains("\"version\":2"));

    // Round-trip: GTA-style response
    let gta_json = r#"{"ref_value":{"id":"rv-1","name":"tpm-baseline","version":1}}"#;
    let parsed: RefValueMutationResponse = serde_json::from_str(gta_json).unwrap();
    assert_eq!(parsed.ref_value.id, "rv-1");
    assert_eq!(parsed.ref_value.version, 1);

    let gta_policy_json = r#"{"policy":{"id":"P1","name":"policy1","version":3}}"#;
    let parsed_p: PolicyMutationResponse = serde_json::from_str(gta_policy_json).unwrap();
    assert_eq!(parsed_p.policy.id, "P1");
    assert_eq!(parsed_p.policy.version, 3);
}

// ===========================================================================
// TC7: RefValueCreateRequest missing required field → validation fails
// ===========================================================================

#[test]
fn tc7_create_request_empty_name_fails_validation() {
    let req = RefValueCreateRequest {
        name: "".to_string(),
        attester_type: "tpm".to_string(),
        content: "data".to_string(),
        content_type: None,
        description: None,
    };
    assert!(req.validate().is_err());
}

#[test]
fn tc7_create_request_valid_passes_validation() {
    let req = RefValueCreateRequest {
        name: "baseline1".to_string(),
        attester_type: "tpm".to_string(),
        content: "data".to_string(),
        content_type: None,
        description: None,
    };
    assert!(req.validate().is_ok());
}

// ===========================================================================
// TC8: ManagementProviderNotFound → HTTP 404 mapping
// ===========================================================================

#[test]
fn tc8_management_provider_not_found_maps_404() {
    let err = RbsError::ManagementProviderNotFound("unknown".to_string());
    assert_eq!(err.http_status(), 404);
    assert!(err.external_message().contains("unknown"));

    let body = ErrorBody::from(&err);
    assert!(body.error.contains("unknown"));
}

// ===========================================================================
// TC11: limit boundary validation (0/1/10/11)
// ===========================================================================

#[test]
fn tc11_limit_boundary_values() {
    // limit=0 → fail
    let q = RefValueListQuery {
        ids: None,
        attester_type: None,
        limit: Some(0),
        offset: None,
    };
    assert!(q.validate().is_err());

    // limit=1 → pass
    let q = RefValueListQuery {
        ids: None,
        attester_type: None,
        limit: Some(1),
        offset: None,
    };
    assert!(q.validate().is_ok());

    // limit=10 → pass
    let q = RefValueListQuery {
        ids: None,
        attester_type: None,
        limit: Some(10),
        offset: None,
    };
    assert!(q.validate().is_ok());

    // limit=11 → fail
    let q = RefValueListQuery {
        ids: None,
        attester_type: None,
        limit: Some(11),
        offset: None,
    };
    assert!(q.validate().is_err());
}

// ===========================================================================
// TC12: offset boundary validation (-1/0/100000/100001)
// ===========================================================================

#[test]
fn tc12_offset_boundary_values() {
    // offset=-1 → fail
    let q = RefValueListQuery {
        ids: None,
        attester_type: None,
        limit: None,
        offset: Some(-1),
    };
    assert!(q.validate().is_err());

    // offset=0 → pass
    let q = RefValueListQuery {
        ids: None,
        attester_type: None,
        limit: None,
        offset: Some(0),
    };
    assert!(q.validate().is_ok());

    // offset=100000 → pass
    let q = RefValueListQuery {
        ids: None,
        attester_type: None,
        limit: None,
        offset: Some(100_000),
    };
    assert!(q.validate().is_ok());

    // offset=100001 → fail
    let q = RefValueListQuery {
        ids: None,
        attester_type: None,
        limit: None,
        offset: Some(100_001),
    };
    assert!(q.validate().is_err());
}

// ===========================================================================
// TC13: RefValueUpdateRequest with only id (all optionals None)
// ===========================================================================

#[test]
fn tc13_update_request_only_id() {
    let json = r#"{"id":"R1"}"#;
    let req: RefValueUpdateRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.id, "R1");
    assert!(req.name.is_none());
    assert!(req.description.is_none());
    assert!(req.attester_type.is_none());
    assert!(req.content.is_none());
    assert!(req.content_type.is_none());
}

// ===========================================================================
// TC16: lib.rs exports — all new types accessible from crate root
// ===========================================================================

#[test]
fn tc16_crate_root_exports() {
    // If this compiles, the types are exported at crate root.
    let _rv: RefValue = RefValue {
        id: String::new(),
        uid: None,
        name: String::new(),
        attester_type: String::new(),
        description: None,
        content: None,
        content_type: None,
        version: None,
        valid_code: None,
    };
    let _q: RefValueListQuery = RefValueListQuery {
        ids: None,
        attester_type: None,
        limit: None,
        offset: None,
    };
    let _r: RefValueListResponse = RefValueListResponse {
        ref_values: vec![],
        total_count: None,
        limit: None,
        offset: None,
    };
    let _c: RefValueCreateRequest = RefValueCreateRequest {
        name: String::new(),
        attester_type: String::new(),
        content: String::new(),
        content_type: None,
        description: None,
    };
    let _u: RefValueUpdateRequest = RefValueUpdateRequest {
        id: String::new(),
        name: None,
        description: None,
        attester_type: None,
        content: None,
        content_type: None,
    };
    let _d: RefValueDeleteRequest = RefValueDeleteRequest {
        delete_type: AttestationDeleteType::All,
        ids: None,
        attester_type: None,
    };
    let _m: RefValueMutationResponse = RefValueMutationResponse {
        ref_value: RefValueMutation {
            id: String::new(),
            name: String::new(),
            version: 1,
        },
    };
}

// ===========================================================================
// Supplementary: RefValueDeleteRequest serialization
// ===========================================================================

#[test]
fn delete_request_serialization_id_mode() {
    let req = RefValueDeleteRequest {
        delete_type: AttestationDeleteType::Id,
        ids: Some(vec!["R1".to_string(), "R2".to_string()]),
        attester_type: None,
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("\"delete_type\":\"id\""));
    assert!(json.contains("\"ids\""));
    assert!(!json.contains("\"attester_type\""));
}

#[test]
fn delete_request_serialization_by_type_mode() {
    let req = RefValueDeleteRequest {
        delete_type: AttestationDeleteType::Type,
        ids: None,
        attester_type: Some("tpm".to_string()),
    };
    let json = serde_json::to_string(&req).unwrap();
    assert!(json.contains("\"delete_type\":\"type\""));
    assert!(json.contains("\"attester_type\":\"tpm\""));
    assert!(!json.contains("\"ids\""));
}
