/// Resource module configuration.
#[derive(Debug, Clone)]
pub struct ResourceConfig {
    pub max_resource_name_len: usize,
    pub max_repo_name_len: usize,
    pub max_additional_info_len: usize,
    pub allowed_resource_types: Vec<String>,
    pub allowed_content_types: Vec<String>,
    pub allowed_export_modes: Vec<String>,
    pub configured_backends: Vec<String>,
}

impl Default for ResourceConfig {
    fn default() -> Self {
        Self {
            max_resource_name_len: 32,
            max_repo_name_len: 32,
            max_additional_info_len: 512,
            allowed_resource_types: vec!["secret".to_string(), "cert".to_string()],
            allowed_content_types: vec![
                "jwt".to_string(),
                "json".to_string(),
                "text".to_string(),
                "binary".to_string(),
                "jwk".to_string(),
                "jwe".to_string(),
            ],
            allowed_export_modes: vec!["jwe".to_string()],
            configured_backends: vec!["vault".to_string()],
        }
    }
}
