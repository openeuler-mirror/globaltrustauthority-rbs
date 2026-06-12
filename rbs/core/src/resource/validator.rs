use super::config::ResourceConfig;
use super::error::ResourceError;

/// Parsed URI components.
#[derive(Debug, Clone)]
pub struct ParsedUri {
    pub res_provider: String,
    pub repository_name: String,
    pub resource_type: String,
    pub resource_name: String,
}

/// ResourceValidator - pure validation functions.
#[derive(Debug, Clone)]
pub struct ResourceValidator {
    config: ResourceConfig,
    reserved_providers: Vec<&'static str>,
}

impl ResourceValidator {
    pub fn new(config: ResourceConfig) -> Self {
        Self { config, reserved_providers: vec!["admin", "attestation", "resource", "health"] }
    }

    /// Validate complete resource URI.
    pub fn validate_uri(&self, uri: &str) -> Result<ParsedUri, ResourceError> {
        let path = uri.trim_start_matches("/rbs/v0/");
        let segments: Vec<&str> = path.split('/').collect();
        let expected_segments = 4;
        if segments.len() < expected_segments {
            log::error!("Resource URI validation failed: uri='{}' has {} segments, expected {}", uri, segments.len(), expected_segments);
            return Err(ResourceError::ParamInvalid { field: "uri" });
        }
        if segments.len() > expected_segments {
            log::error!("Resource URI validation failed: uri='{}' has {} segments, expected {}", uri, segments.len(), expected_segments);
            return Err(ResourceError::ParamInvalid { field: "uri" });
        }

        let res_provider = segments[0].to_string();
        let repository_name = segments[1].to_string();
        let resource_type = segments[2].to_string();
        let resource_name = segments[3].to_string();

        // Validate each segment
        self.validate_res_provider(&res_provider)?;
        self.validate_repository_name(&repository_name)?;
        self.validate_resource_type(&resource_type)?;
        self.validate_resource_name(&resource_name)?;

        Ok(ParsedUri { res_provider, repository_name, resource_type, resource_name })
    }

    pub fn validate_res_provider(&self, name: &str) -> Result<(), ResourceError> {
        if name.is_empty() {
            log::error!("Resource validation failed: res_provider is empty");
            return Err(ResourceError::ParamInvalid { field: "res_provider" });
        }
        if self.reserved_providers.contains(&name) {
            log::error!("Resource validation failed: res_provider '{}' is reserved", name);
            return Err(ResourceError::ParamInvalid { field: "res_provider" });
        }
        if !self.config.configured_backends.contains(&name.to_string()) {
            log::error!("Resource validation failed: res_provider '{}' is not a configured backend", name);
            return Err(ResourceError::BackendUnsupported { provider: name.to_string() });
        }
        Ok(())
    }

    pub fn validate_repository_name(&self, name: &str) -> Result<(), ResourceError> {
        if name.is_empty() || name.len() > self.config.max_repo_name_len {
            log::error!("Resource validation failed: repository_name '{}' length out of range (1..{})", name, self.config.max_repo_name_len);
            return Err(ResourceError::ParamInvalid { field: "repository_name" });
        }
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            log::error!("Resource validation failed: repository_name '{}' contains invalid characters", name);
            return Err(ResourceError::ParamInvalid { field: "repository_name" });
        }
        Ok(())
    }

    pub fn validate_resource_type(&self, res_type: &str) -> Result<(), ResourceError> {
        if !self.config.allowed_resource_types.contains(&res_type.to_string()) {
            log::error!("Resource validation failed: resource_type '{}' is not allowed", res_type);
            return Err(ResourceError::ParamInvalid { field: "resource_type" });
        }
        Ok(())
    }

    pub fn validate_resource_name(&self, name: &str) -> Result<(), ResourceError> {
        if name.is_empty() || name.len() > self.config.max_resource_name_len {
            log::error!("Resource validation failed: resource_name '{}' length out of range (1..{})", name, self.config.max_resource_name_len);
            return Err(ResourceError::ParamInvalid { field: "resource_name" });
        }
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
            log::error!("Resource validation failed: resource_name '{}' contains invalid characters", name);
            return Err(ResourceError::ParamInvalid { field: "resource_name" });
        }
        Ok(())
    }

    pub fn validate_content_type(&self, ct: &str) -> Result<(), ResourceError> {
        if !self.config.allowed_content_types.contains(&ct.to_string()) {
            log::error!("Resource validation failed: content_type '{}' is not allowed", ct);
            return Err(ResourceError::ParamInvalid { field: "content_type" });
        }
        Ok(())
    }

    pub fn validate_export_mode(&self, mode: &str) -> Result<(), ResourceError> {
        if !self.config.allowed_export_modes.contains(&mode.to_string()) {
            log::error!("Resource validation failed: export_mode '{}' is not allowed", mode);
            return Err(ResourceError::ParamInvalid { field: "export_mode" });
        }
        Ok(())
    }

    pub fn validate_additional_info(&self, info: Option<&str>) -> Result<(), ResourceError> {
        match info {
            None => Ok(()),
            Some(s) if s.is_empty() => {
                log::error!("Resource validation failed: additional_info is empty");
                Err(ResourceError::ParamInvalid { field: "additional_info" })
            }
            Some(s) => {
                if s.chars().count() > self.config.max_additional_info_len {
                    log::error!("Resource validation failed: additional_info length {} exceeds max {}", s.chars().count(), self.config.max_additional_info_len);
                    return Err(ResourceError::ParamInvalid { field: "additional_info" });
                }
                Ok(())
            },
        }
    }
}