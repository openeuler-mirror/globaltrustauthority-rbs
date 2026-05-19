use thiserror::Error;

/// Resource module errors.
#[derive(Debug, Clone, Error)]
pub enum ResourceError {
    #[error("permission denied")]
    PermissionDenied,

    #[error("invalid parameter: {field}")]
    ParamInvalid { field: &'static str },

    #[error("policy ID is invalid or not found: {0}")]
    PolicyIdInvalid(String),

    #[error("resource already exists: {uri}")]
    AlreadyExists { uri: String },

    #[error("resource not found")]
    NotFound,

    #[error("version conflict: resource was modified by another request")]
    VersionConflict,

    #[error("backend not found for resource")]
    BackendNotFound,

    #[error("backend error: {detail}")]
    BackendError { detail: String },

    #[error("backend unsupported: {provider}")]
    BackendUnsupported { provider: String },

    #[error("JWE encryption failed: {reason}")]
    JweEncryptionFailed { reason: String },
}

impl ResourceError {
    pub fn http_status(&self) -> u16 {
        match self {
            ResourceError::PermissionDenied => 403,
            ResourceError::AlreadyExists { .. } | ResourceError::VersionConflict => 409,
            ResourceError::ParamInvalid { .. }
            | ResourceError::PolicyIdInvalid(_)
            | ResourceError::BackendNotFound
            | ResourceError::BackendUnsupported { .. }
            | ResourceError::JweEncryptionFailed { .. } => 400,
            ResourceError::NotFound => 404,
            ResourceError::BackendError { .. } => 502,
        }
    }

    pub fn external_message(&self) -> String {
        self.to_string()
    }
}
