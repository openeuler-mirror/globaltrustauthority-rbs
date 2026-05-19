use super::config::PolicyConfig;
use super::error::PolicyError;

/// PolicyValidator - pure validation functions, zero state.
#[derive(Debug, Clone)]
pub struct PolicyValidator {
    config: PolicyConfig,
}

impl PolicyValidator {
    pub fn new(config: PolicyConfig) -> Self {
        Self { config }
    }

    /// Validate policy name: length 1..max_name_len, no blacklisted chars.
    pub fn validate_name(&self, name: &str) -> Result<(), PolicyError> {
        if name.is_empty() || name.len() > self.config.max_name_len {
            return Err(PolicyError::NameInvalid {
                reason: format!("name length must be 1..{}, got {}", self.config.max_name_len, name.len()),
            });
        }
        if let Some(c) = name.chars().find(|c| self.config.name_blacklist.contains(c)) {
            return Err(PolicyError::NameInvalid { reason: format!("name contains forbidden character: '{}'", c) });
        }
        Ok(())
    }

    /// Check that user has not reached policy count limit.
    pub fn check_user_policy_count(&self, current_count: usize) -> Result<(), PolicyError> {
        if current_count >= self.config.max_per_user {
            return Err(PolicyError::CountExceed { max: self.config.max_per_user, current: current_count });
        }
        Ok(())
    }

    /// Decode base64-encoded policy content and check size.
    pub fn decode_and_check_size(&self, content_type: &str, content: &str) -> Result<String, PolicyError> {
        if content_type != "base64" {
            return Err(PolicyError::UnsupportedContentType { content_type: content_type.to_string() });
        }
        if content.is_empty() {
            return Err(PolicyError::ContentDecodeError { reason: "policy content must not be empty".to_string() });
        }

        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(content)
            .map_err(|e| PolicyError::ContentDecodeError { reason: format!("base64 decode failed: {}", e) })?;

        let size_kb = decoded.len() / 1024;
        if size_kb > self.config.max_content_size_kb {
            return Err(PolicyError::ContentTooLarge { size_kb, max_kb: self.config.max_content_size_kb });
        }

        String::from_utf8(decoded).map_err(|e| PolicyError::ContentDecodeError {
            reason: format!("decoded content is not valid UTF-8: {}", e),
        })
    }

}
