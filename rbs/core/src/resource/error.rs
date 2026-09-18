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

    #[error("resource count exceeded: max {max}, current {current}")]
    CountExceed { max: usize, current: usize },

    #[error("resource not found")]
    NotFound,

    /// Read-path 404 (get_content / get_info / retrieve). RBS deliberately
    /// returns this identical body for "resource missing" and "authorization
    /// denied" so callers cannot enumerate resource existence (the folding is
    /// public — the API docs document it); which case occurred lives in
    /// server-side logs only. Management paths (create/update/delete) use
    /// plain `NotFound` because denial there is a distinct 403.
    #[error("resource not found or access denied")]
    NotFoundOrDenied,

    #[error("version conflict: resource was modified by another request")]
    VersionConflict,

    #[error("backend not found for resource")]
    BackendNotFound,

    #[error("backend error: {detail}")]
    BackendError { detail: String },

    #[error("backend unsupported: {provider}")]
    BackendUnsupported { provider: String },

    /// The resource-bound Rego policy could not be evaluated (e.g. broken
    /// syntax, safe-mode rejected builtin). A server-side fault, not an
    /// authorization decision — the detail is logged, not exposed.
    #[error("policy evaluation failed")]
    PolicyEvaluationFailed,

    #[error("JWE encryption failed: {reason}")]
    JweEncryptionFailed { reason: String },

    #[error("backend operation unsupported")]
    BackendOperationUnsupported,

    #[error("csr required for this resource provider")]
    CsrRequired,

    #[error("ca request pending")]
    CaRequestPending,

    /// Backend saturated with concurrent requests (e.g. too many in-flight
    /// CA issuances). Mapped to HTTP 429 so callers back off and retry.
    #[error("backend busy: too many concurrent requests, retry later")]
    BackendBusy,
}

impl ResourceError {
    pub fn http_status(&self) -> u16 {
        match self {
            ResourceError::PermissionDenied => 403,
            ResourceError::AlreadyExists { .. } | ResourceError::VersionConflict
            | ResourceError::CountExceed { .. } => 409,
            ResourceError::ParamInvalid { .. }
            | ResourceError::PolicyIdInvalid(_)
            | ResourceError::BackendNotFound
            | ResourceError::BackendUnsupported { .. }
            | ResourceError::JweEncryptionFailed { .. }
            | ResourceError::BackendOperationUnsupported
            | ResourceError::CsrRequired => 400,
            ResourceError::NotFound => 404,
            ResourceError::NotFoundOrDenied => 404,
            ResourceError::BackendError { .. } => 502,
            ResourceError::CaRequestPending => 202,
            ResourceError::BackendBusy => 429,
            ResourceError::PolicyEvaluationFailed => 500,
        }
    }

    pub fn external_message(&self) -> String {
        self.to_string()
    }
}
