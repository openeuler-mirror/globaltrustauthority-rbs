/// Policy module configuration.
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    /// Maximum number of policies per user.
    pub max_per_user: usize,
    /// Maximum size of decoded policy content in KB.
    pub max_content_size_kb: usize,
    /// Maximum page size for list queries.
    pub max_page_size: usize,
    /// Blacklisted characters in policy names.
    pub name_blacklist: Vec<char>,
    /// Maximum length of policy name.
    pub max_name_len: usize,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            max_per_user: 10,
            max_content_size_kb: 128,
            max_page_size: 100,
            name_blacklist: vec!['<', '>', '"', '\'', '&', '|', '\\', '/', '*', '?', '`'],
            max_name_len: 255,
        }
    }
}
