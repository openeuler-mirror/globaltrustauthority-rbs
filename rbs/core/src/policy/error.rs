use thiserror::Error;

/// Policy module errors.
#[derive(Debug, Clone, Error)]
pub enum PolicyError {
    #[error("permission denied")]
    PermissionDenied,

    #[error("policy name is invalid: {reason}")]
    NameInvalid { reason: String },

    #[error("policy name already exists: {name}")]
    NameDuplicate { name: String },

    #[error("policy count exceeded: max {max}, current {current}")]
    CountExceed { max: usize, current: usize },

    #[error("unsupported content type: {content_type}")]
    UnsupportedContentType { content_type: String },

    #[error("failed to decode policy content: {reason}")]
    ContentDecodeError { reason: String },

    #[error("policy content too large: {size_kb}KB exceeds max {max_kb}KB")]
    ContentTooLarge { size_kb: usize, max_kb: usize },

    #[error("Rego syntax error: {details}")]
    RegoSyntaxError { details: String },

    #[error("policy not found")]
    NotFound,

    #[error("version conflict: expected {expected}, current {current}")]
    VersionConflict { expected: i32, current: i32 },

    #[error("policy is being referenced by resources: {policy_names:?}")]
    BeingReferenced { policy_names: Vec<String> },

    #[error("invalid parameter: {field}")]
    ParamInvalid { field: &'static str },
}

impl PolicyError {
    pub fn http_status(&self) -> u16 {
        match self {
            PolicyError::PermissionDenied => 403,
            PolicyError::NameInvalid { .. }
            | PolicyError::NameDuplicate { .. }
            | PolicyError::CountExceed { .. }
            | PolicyError::UnsupportedContentType { .. }
            | PolicyError::ContentDecodeError { .. }
            | PolicyError::ContentTooLarge { .. }
            | PolicyError::RegoSyntaxError { .. }
            | PolicyError::ParamInvalid { .. } => 400,
            PolicyError::BeingReferenced { .. } => 409,
            PolicyError::NotFound => 404,
            PolicyError::VersionConflict { .. } => 409,
        }
    }

    pub fn external_message(&self) -> String {
        self.to_string()
    }
}

impl From<crate::resource::error::ResourceError> for PolicyError {
    fn from(_e: crate::resource::error::ResourceError) -> Self {
        PolicyError::ParamInvalid { field: "resource" }
    }
}
