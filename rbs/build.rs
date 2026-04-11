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

//! Emit `docs/proto/rbs_rest_api.yaml` from `rbs_rest::ApiDoc` when building this crate.
//!
//! Only runs when the `rest` feature is enabled (default). When `rest` is disabled (e.g.
//! `cargo build -p rbs --no-default-features`) the build script is a no-op and neither
//! `rbs-rest-build` nor `utoipa` are compiled as build-dependencies.
//!
//! Markdown and HTML (`rbs_rest_api.md` / `rbs_rest_api.html`) under `docs/api/rbs/md/`
//! and `docs/api/rbs/html/` are produced from that YAML via `./scripts/generate-api-docs.sh`
//! (Widdershins + Redocly; see `scripts/conf/openapi-docs/package.json`).

#[cfg(feature = "rest")]
use rbs_rest::ApiDoc;
#[cfg(feature = "rest")]
use utoipa::OpenApi;

fn main() -> anyhow::Result<()> {
    #[cfg(feature = "rest")]
    openapi_generate()?;
    Ok(())
}

#[cfg(feature = "rest")]
fn openapi_generate() -> anyhow::Result<()> {
    use std::env;
    use std::path::Path;
    use anyhow::Context;

    let manifest_dir_str = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let manifest_dir = Path::new(&manifest_dir_str);
    let workspace_root =
        manifest_dir.parent().expect("rbs crate manifest should have a parent (workspace root)");

    // rbs-rest: OpenAPI document definition and every route that contributes to it.
    let rest = workspace_root.join("rest");
    println!("cargo:rerun-if-changed={}", rest.join("src").display());

    // rbs-api-types: `utoipa::ToSchema` types included in `ApiDoc`; without these, Cargo may skip
    // rerunning this script when only api-types changes, leaving `docs/proto/rbs_rest_api.yaml` stale.
    let api_types = workspace_root.join("api-types");
    println!("cargo:rerun-if-changed={}", api_types.join("src").display());

    let yaml_path = workspace_root.join("docs/proto/rbs_rest_api.yaml");

    if let Some(p) = yaml_path.parent() {
        std::fs::create_dir_all(p).with_context(|| format!("create {}", p.display()))?;
    }

    let openapi = ApiDoc::openapi();
    let yaml = serde_yaml::to_string(&openapi).context("serialize OpenAPI to YAML")?;
    std::fs::write(&yaml_path, yaml).with_context(|| format!("write {}", yaml_path.display()))?;

    Ok(())
}
