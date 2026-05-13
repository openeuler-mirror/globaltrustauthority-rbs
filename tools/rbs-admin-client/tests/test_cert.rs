/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
 * Global Trust Authority Resource Broker Service is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

use rbs_admin_client::attestation::cert::{
    CertClient, CertCreateRequest, CertDeleteRequest, CertListParams, CertService, CertUpdateRequest,
};
use rbs_admin_client::AdminClient;

fn unusable_admin_client() -> AdminClient {
    AdminClient::new("data:text/plain,not-a-base-url", "test-token", &None)
        .expect("admin client should accept syntactically valid URLs")
}

#[tokio::test]
async fn cert_operations_report_url_build_failure() {
    let client = CertClient::new(unusable_admin_client(), None);
    let create = CertCreateRequest {
        name: "cert-1".to_string(),
        description: Some("demo cert".to_string()),
        cert_type: vec!["tpm".to_string()],
        content: Some("pem".to_string()),
        crl_content: None,
        is_default: Some(false),
    };
    let update = CertUpdateRequest {
        id: "cert-1".to_string(),
        name: Some("cert-2".to_string()),
        description: None,
        cert_type: Some(vec!["tpm".to_string()]),
        is_default: Some(true),
    };
    let delete = CertDeleteRequest {
        delete_type: "id".to_string(),
        ids: Some(vec!["cert-1".to_string()]),
        cert_type: None,
    };

    let err = client.list_certs(&CertListParams::default()).await.expect_err("list should fail");
    assert_eq!(err.to_string(), "base URL cannot be used to build cert path");
    assert_eq!(
        client.create_cert(&create).await.expect_err("create should fail").to_string(),
        "base URL cannot be used to build cert path"
    );
    assert_eq!(
        client.update_cert(&update).await.expect_err("update should fail").to_string(),
        "base URL cannot be used to build cert path"
    );
    assert_eq!(
        client
            .delete_certs(&delete)
            .await
            .expect_err("delete should fail")
            .to_string(),
        "base URL cannot be used to build cert path"
    );
}
