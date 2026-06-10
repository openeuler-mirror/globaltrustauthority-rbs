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

use reqwest::Url;

use crate::error::RbsAdminClientError;

pub(crate) fn build_path_url(base_url: &Url, segments: &[&str], build_error: &str) -> Result<Url, RbsAdminClientError> {
    for segment in segments {
        validate_path_segment(segment)?;
    }

    let mut url = base_url.clone();
    {
        let mut path =
            url.path_segments_mut().map_err(|_| RbsAdminClientError::ClientError(build_error.to_string()))?;
        path.clear();
        for segment in segments {
            path.push(segment);
        }
    }
    Ok(url)
}

fn validate_path_segment(segment: &str) -> Result<(), RbsAdminClientError> {
    if segment.trim().is_empty() {
        return Err(RbsAdminClientError::ClientError("path segment must not be empty".to_string()));
    }
    if segment == "." || segment == ".." || segment.contains(['/', '?', '#', '\\', '%']) {
        return Err(RbsAdminClientError::ClientError(
            "path segment must not contain '/', '.', '..', query, fragment, backslash, or percent encoding".to_string(),
        ));
    }
    if segment.chars().any(char::is_control) {
        return Err(RbsAdminClientError::ClientError("path segment must not contain control characters".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_path_url_encodes_segments_without_changing_path_structure() {
        let base = Url::parse("https://example.com/base").expect("valid base URL");
        let url = build_path_url(&base, &["rbs", "v0", "users", "ops user"], "build failed").expect("url");

        assert_eq!(url.as_str(), "https://example.com/rbs/v0/users/ops%20user");
    }

    #[test]
    fn build_path_url_rejects_ambiguous_segments() {
        let base = Url::parse("https://example.com").expect("valid base URL");

        for segment in ["", " ", ".", "..", "ops/user", "ops?debug=true", "ops#fragment", "ops\\user", "%2e%2e"] {
            let err = build_path_url(&base, &["rbs", "v0", segment], "build failed").expect_err("invalid segment");
            assert!(matches!(err, RbsAdminClientError::ClientError(_)), "unexpected error: {err:?}");
        }
    }
}
