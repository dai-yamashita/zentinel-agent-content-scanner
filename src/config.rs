//! Configuration types for Content Scanner agent.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Root configuration for Content Scanner agent.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Config {
    /// Global settings.
    #[serde(default)]
    pub settings: Settings,

    /// Body handling configuration.
    #[serde(default)]
    pub body: BodyConfig,

    /// ClamAV daemon configuration.
    #[serde(default)]
    pub clamd: ClamdConfig,

    /// Paths to skip scanning.
    #[serde(default)]
    pub skip_paths: Vec<String>,

    /// HTTP methods to scan (empty = all methods with body).
    #[serde(default)]
    pub scan_methods: Vec<String>,
}

/// Global settings.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Settings {
    /// Master enable/disable switch.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Action when ClamAV is unavailable.
    #[serde(default)]
    pub fail_action: FailAction,

    /// Log malware detections.
    #[serde(default = "default_true")]
    pub log_detections: bool,

    /// Log clean scans.
    #[serde(default)]
    pub log_clean: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            fail_action: FailAction::default(),
            log_detections: true,
            log_clean: false,
        }
    }
}

/// Action to take when ClamAV is unavailable.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FailAction {
    /// Allow request when scan fails (fail-open).
    #[default]
    Allow,
    /// Block request when scan fails (fail-closed).
    Block,
}

/// Body handling configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BodyConfig {
    /// Maximum body size to scan (bytes).
    #[serde(default = "default_max_size")]
    pub max_size: usize,

    /// Content types to scan (empty = all). Types are compared without regard
    /// to ASCII case. A request without a `Content-Type` header, or with one
    /// that names no media type, is always scanned.
    #[serde(default)]
    pub content_types: Vec<String>,
}

impl Default for BodyConfig {
    fn default() -> Self {
        Self {
            max_size: default_max_size(),
            content_types: vec![],
        }
    }
}

fn default_max_size() -> usize {
    52_428_800 // 50MB
}

/// ClamAV daemon configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClamdConfig {
    /// Enable ClamAV scanning.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Path to clamd Unix socket.
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,

    /// Scan timeout in milliseconds.
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,

    /// Chunk size for streaming to clamd.
    #[serde(default = "default_chunk_size")]
    pub chunk_size: usize,
}

impl Default for ClamdConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            socket_path: default_socket_path(),
            timeout_ms: default_timeout(),
            chunk_size: default_chunk_size(),
        }
    }
}

fn default_socket_path() -> PathBuf {
    PathBuf::from("/var/run/clamav/clamd.ctl")
}

fn default_timeout() -> u64 {
    30000 // 30 seconds
}

fn default_chunk_size() -> usize {
    65536 // 64KB
}

fn default_true() -> bool {
    true
}

impl Config {
    /// Load configuration from a YAML file.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let expanded = expand_env_vars(&content);
        let config: Config = serde_yaml::from_str(&expanded)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration.
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate max body size
        if self.body.max_size == 0 {
            anyhow::bail!("body.max_size must be greater than 0");
        }

        // Validate timeout
        if self.clamd.timeout_ms == 0 {
            anyhow::bail!("clamd.timeout_ms must be greater than 0");
        }

        // Validate chunk size
        if self.clamd.chunk_size == 0 {
            anyhow::bail!("clamd.chunk_size must be greater than 0");
        }

        Ok(())
    }

    /// Check if a path should be skipped.
    pub fn should_skip_path(&self, path: &str) -> bool {
        self.skip_paths
            .iter()
            .any(|skip| path == skip || path.starts_with(&format!("{}/", skip)))
    }

    /// Check if a method should be scanned.
    pub fn should_scan_method(&self, method: &str) -> bool {
        if self.scan_methods.is_empty() {
            // If no methods specified, scan all methods that typically have bodies
            matches!(method.to_uppercase().as_str(), "POST" | "PUT" | "PATCH")
        } else {
            self.scan_methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(method))
        }
    }

    /// Check if a content type should be scanned.
    ///
    /// A request without a `Content-Type` (`None`), or with one that names no
    /// media type (empty, blank, or only parameters such as
    /// `; charset=utf-8`), is always scanned: a type the client does not
    /// declare cannot be matched against `body.content_types`. A declared type
    /// is scanned when the list is empty or one of its patterns matches.
    pub fn should_scan_content_type(&self, content_type: Option<&str>) -> bool {
        let content_type = match content_type {
            Some(ct) if !media_type(ct).is_empty() => ct,
            _ => return true,
        };

        // If no content types specified, scan all
        if self.body.content_types.is_empty() {
            return true;
        }

        self.body
            .content_types
            .iter()
            .any(|pattern| matches_content_type(pattern, content_type))
    }

    /// Generate example configuration YAML.
    pub fn example() -> String {
        r#"# Content Scanner Agent Configuration

settings:
  enabled: true
  fail_action: allow           # allow or block when ClamAV unavailable
  log_detections: true
  log_clean: false

# Body handling
body:
  max_size: 52428800           # 50MB max body to scan
  # Only scan these content types (empty = all). A request without a
  # Content-Type header, or with one that names no media type, is always
  # scanned.
  content_types:
    - "application/octet-stream"
    - "application/zip"
    - "application/x-zip-compressed"
    - "application/gzip"
    - "application/x-gzip"
    - "application/x-tar"
    - "application/pdf"
    - "application/msword"
    - "application/vnd.openxmlformats-officedocument.*"
    - "multipart/form-data"

# ClamAV daemon configuration
clamd:
  enabled: true
  socket_path: "/var/run/clamav/clamd.ctl"
  timeout_ms: 30000            # 30 second scan timeout
  chunk_size: 65536            # 64KB chunks to clamd

# Paths to skip scanning
skip_paths:
  - "/health"
  - "/ready"
  - "/metrics"

# Methods to scan (empty = POST, PUT, PATCH)
scan_methods:
  - "POST"
  - "PUT"
  - "PATCH"
"#
        .to_string()
    }
}

/// Check if a content type matches a pattern.
///
/// Supports:
/// - Exact match: "application/json"
/// - Wildcard subtype: "application/*"
/// - Glob suffix: "application/vnd.*"
///
/// The comparison ignores ASCII case on both sides, since the type and
/// subtype of a media type are case-insensitive (RFC 9110, section 8.3.1):
/// the pattern "application/pdf" matches "Application/PDF". Only ASCII letters
/// are folded.
pub fn matches_content_type(pattern: &str, content_type: &str) -> bool {
    let media_type = media_type(content_type);

    if let Some(prefix) = pattern.strip_suffix("/*") {
        // Wildcard subtype: "application/*" matches "application/json"
        starts_with_ignore_ascii_case(media_type, prefix)
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        // Glob suffix: "application/vnd.*" matches "application/vnd.ms-excel"
        starts_with_ignore_ascii_case(media_type, prefix)
    } else {
        // Exact match
        media_type.eq_ignore_ascii_case(pattern)
    }
}

/// Check whether `value` starts with `prefix`, ignoring ASCII case.
///
/// Compares bytes, so it never cuts `value` inside a multi-byte character.
fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

/// Extract just the media type (before any parameters like charset).
fn media_type(content_type: &str) -> &str {
    content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
}

/// Expand environment variables in the format ${VAR_NAME}.
fn expand_env_vars(content: &str) -> String {
    let mut result = content.to_string();
    let re = regex::Regex::new(r"\$\{([^}]+)\}").unwrap();

    for cap in re.captures_iter(content) {
        let var_name = &cap[1];
        let var_value = std::env::var(var_name).unwrap_or_default();
        result = result.replace(&cap[0], &var_value);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let settings = Settings::default();
        assert!(settings.enabled);
        assert_eq!(settings.fail_action, FailAction::Allow);
        assert!(settings.log_detections);
        assert!(!settings.log_clean);
    }

    #[test]
    fn test_default_body_config() {
        let body = BodyConfig::default();
        assert_eq!(body.max_size, 52_428_800);
        assert!(body.content_types.is_empty());
    }

    #[test]
    fn test_default_clamd_config() {
        let clamd = ClamdConfig::default();
        assert!(clamd.enabled);
        assert_eq!(
            clamd.socket_path,
            PathBuf::from("/var/run/clamav/clamd.ctl")
        );
        assert_eq!(clamd.timeout_ms, 30000);
        assert_eq!(clamd.chunk_size, 65536);
    }

    #[test]
    fn test_matches_content_type_exact() {
        assert!(matches_content_type("application/json", "application/json"));
        assert!(matches_content_type(
            "application/json",
            "application/json; charset=utf-8"
        ));
        assert!(!matches_content_type("application/json", "application/xml"));
    }

    #[test]
    fn test_matches_content_type_wildcard() {
        assert!(matches_content_type("application/*", "application/json"));
        assert!(matches_content_type(
            "application/*",
            "application/octet-stream"
        ));
        assert!(!matches_content_type("application/*", "text/html"));
    }

    #[test]
    fn test_matches_content_type_glob() {
        assert!(matches_content_type(
            "application/vnd.*",
            "application/vnd.ms-excel"
        ));
        assert!(matches_content_type(
            "application/vnd.*",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        ));
        assert!(!matches_content_type(
            "application/vnd.*",
            "application/json"
        ));
    }

    #[test]
    fn test_matches_content_type_ignores_ascii_case_exact() {
        // Value only, pattern only, and both mixed.
        assert!(matches_content_type("application/pdf", "Application/PDF"));
        assert!(matches_content_type("application/pdf", "APPLICATION/pdf"));
        assert!(matches_content_type("Application/PDF", "application/pdf"));
        assert!(matches_content_type("Application/pdf", "application/PDF"));
        assert!(matches_content_type(
            "application/pdf",
            "Application/PDF; charset=UTF-8"
        ));
        assert!(matches_content_type(
            "application/pdf",
            "  Application/PDF "
        ));
        assert!(!matches_content_type("application/pdf", "Application/PDFX"));
        assert!(!matches_content_type("Application/PDF", "text/plain"));
    }

    #[test]
    fn test_matches_content_type_ignores_ascii_case_wildcard() {
        assert!(matches_content_type("application/*", "APPLICATION/zip"));
        assert!(matches_content_type("Application/*", "application/zip"));
        assert!(matches_content_type("Application/*", "APPLICATION/Zip"));
        assert!(!matches_content_type("application/*", "TEXT/html"));
        assert!(!matches_content_type("Application/*", "text/html"));
    }

    #[test]
    fn test_matches_content_type_ignores_ascii_case_glob() {
        assert!(matches_content_type(
            "application/vnd.*",
            "Application/VND.MS-Excel"
        ));
        assert!(matches_content_type(
            "Application/Vnd.*",
            "application/vnd.ms-excel"
        ));
        assert!(matches_content_type(
            "Application/Vnd.*",
            "APPLICATION/VND.ms-excel"
        ));
        assert!(!matches_content_type(
            "application/vnd.*",
            "Application/JSON"
        ));
    }

    #[test]
    fn test_matches_content_type_non_ascii_does_not_match_or_panic() {
        // Only ASCII letters are folded, and no value is cut inside a
        // multi-byte character.
        assert!(!matches_content_type("application/pdf", "\u{e9}/pdf"));
        assert!(!matches_content_type(
            "application/pdf",
            "application\u{e9}"
        ));
        assert!(!matches_content_type("\u{e9}/pdf", "\u{c9}/pdf"));
        assert!(matches_content_type("\u{e9}/pdf", "\u{e9}/PDF"));
        // The pattern's prefix ends inside the value's multi-byte character.
        assert!(!matches_content_type("application/*", "applicatio\u{e9}"));
        assert!(!matches_content_type(
            "application/vnd.*",
            "application/vnd\u{e9}"
        ));
        assert!(!matches_content_type(
            "application/vnd.*",
            "application\u{e9}"
        ));
        // Values shorter than the pattern.
        assert!(!matches_content_type("application/vnd.*", "application"));
        assert!(!matches_content_type("application/vnd.*", ""));
        assert!(!matches_content_type("application/pdf", "application"));
        assert!(!matches_content_type("application/pdf", ""));
    }

    #[test]
    fn test_should_scan_content_type_ignores_ascii_case() {
        let config = Config {
            settings: Settings::default(),
            body: BodyConfig {
                max_size: default_max_size(),
                content_types: vec!["application/pdf".to_string(), "Image/*".to_string()],
            },
            clamd: ClamdConfig::default(),
            skip_paths: vec![],
            scan_methods: vec![],
        };

        assert!(config.should_scan_content_type(Some("Application/PDF")));
        assert!(config.should_scan_content_type(Some("IMAGE/png; name=A.PNG")));
        assert!(!config.should_scan_content_type(Some("Text/Plain")));
    }

    #[test]
    fn test_should_skip_path() {
        let config = Config {
            settings: Settings::default(),
            body: BodyConfig::default(),
            clamd: ClamdConfig::default(),
            skip_paths: vec!["/health".to_string(), "/ready".to_string()],
            scan_methods: vec![],
        };

        assert!(config.should_skip_path("/health"));
        assert!(config.should_skip_path("/health/live"));
        assert!(config.should_skip_path("/ready"));
        assert!(!config.should_skip_path("/api/upload"));
    }

    #[test]
    fn test_should_scan_method_default() {
        let config = Config {
            settings: Settings::default(),
            body: BodyConfig::default(),
            clamd: ClamdConfig::default(),
            skip_paths: vec![],
            scan_methods: vec![], // Empty = default methods
        };

        assert!(config.should_scan_method("POST"));
        assert!(config.should_scan_method("PUT"));
        assert!(config.should_scan_method("PATCH"));
        assert!(!config.should_scan_method("GET"));
        assert!(!config.should_scan_method("DELETE"));
    }

    #[test]
    fn test_should_scan_method_custom() {
        let config = Config {
            settings: Settings::default(),
            body: BodyConfig::default(),
            clamd: ClamdConfig::default(),
            skip_paths: vec![],
            scan_methods: vec!["POST".to_string()],
        };

        assert!(config.should_scan_method("POST"));
        assert!(config.should_scan_method("post")); // Case insensitive
        assert!(!config.should_scan_method("PUT"));
    }

    #[test]
    fn test_should_scan_content_type_empty() {
        let config = Config {
            settings: Settings::default(),
            body: BodyConfig::default(), // Empty content_types = scan all
            clamd: ClamdConfig::default(),
            skip_paths: vec![],
            scan_methods: vec![],
        };

        assert!(config.should_scan_content_type(Some("application/json")));
        assert!(config.should_scan_content_type(Some("application/octet-stream")));
        // A request that declares no type is scanned too.
        assert!(config.should_scan_content_type(None));
    }

    #[test]
    fn test_should_scan_content_type_filtered() {
        let config = Config {
            settings: Settings::default(),
            body: BodyConfig {
                max_size: default_max_size(),
                content_types: vec![
                    "application/octet-stream".to_string(),
                    "application/zip".to_string(),
                ],
            },
            clamd: ClamdConfig::default(),
            skip_paths: vec![],
            scan_methods: vec![],
        };

        assert!(config.should_scan_content_type(Some("application/octet-stream")));
        assert!(config.should_scan_content_type(Some("application/zip")));
        assert!(!config.should_scan_content_type(Some("application/json")));
    }

    #[test]
    fn test_should_scan_content_type_missing_with_filter() {
        let config = Config {
            settings: Settings::default(),
            body: BodyConfig {
                max_size: default_max_size(),
                content_types: vec!["application/pdf".to_string()],
            },
            clamd: ClamdConfig::default(),
            skip_paths: vec![],
            scan_methods: vec![],
        };

        // No Content-Type cannot be matched against the list, so it is scanned.
        assert!(config.should_scan_content_type(None));
    }

    #[test]
    fn test_should_scan_content_type_declared_mismatch_not_scanned() {
        let config = Config {
            settings: Settings::default(),
            body: BodyConfig {
                max_size: default_max_size(),
                content_types: vec!["application/pdf".to_string()],
            },
            clamd: ClamdConfig::default(),
            skip_paths: vec![],
            scan_methods: vec![],
        };

        assert!(!config.should_scan_content_type(Some("text/plain")));
        assert!(!config.should_scan_content_type(Some("text/plain; charset=utf-8")));
        assert!(config.should_scan_content_type(Some("application/pdf")));
    }

    #[test]
    fn test_should_scan_content_type_without_media_type() {
        for content_types in [vec![], vec!["application/pdf".to_string()]] {
            let config = Config {
                settings: Settings::default(),
                body: BodyConfig {
                    max_size: default_max_size(),
                    content_types,
                },
                clamd: ClamdConfig::default(),
                skip_paths: vec![],
                scan_methods: vec![],
            };

            // A value that names no media type declares no type.
            assert!(config.should_scan_content_type(Some("")));
            assert!(config.should_scan_content_type(Some("   ")));
            assert!(config.should_scan_content_type(Some("; charset=utf-8")));
        }
    }

    #[test]
    fn test_expand_env_vars() {
        std::env::set_var("TEST_SOCKET", "/tmp/test.sock");
        let input = "socket_path: \"${TEST_SOCKET}\"";
        let result = expand_env_vars(input);
        assert_eq!(result, "socket_path: \"/tmp/test.sock\"");
        std::env::remove_var("TEST_SOCKET");
    }

    #[test]
    fn test_parse_config_yaml() {
        let yaml = r#"
settings:
  enabled: true
  fail_action: block

body:
  max_size: 10485760

clamd:
  socket_path: "/tmp/clamd.sock"
  timeout_ms: 10000

skip_paths:
  - "/health"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.settings.enabled);
        assert_eq!(config.settings.fail_action, FailAction::Block);
        assert_eq!(config.body.max_size, 10_485_760);
        assert_eq!(config.clamd.socket_path, PathBuf::from("/tmp/clamd.sock"));
        assert_eq!(config.skip_paths.len(), 1);
    }

    #[test]
    fn test_validate_zero_max_size() {
        let config = Config {
            settings: Settings::default(),
            body: BodyConfig {
                max_size: 0,
                content_types: vec![],
            },
            clamd: ClamdConfig::default(),
            skip_paths: vec![],
            scan_methods: vec![],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_zero_timeout() {
        let config = Config {
            settings: Settings::default(),
            body: BodyConfig::default(),
            clamd: ClamdConfig {
                enabled: true,
                socket_path: default_socket_path(),
                timeout_ms: 0,
                chunk_size: default_chunk_size(),
            },
            skip_paths: vec![],
            scan_methods: vec![],
        };
        assert!(config.validate().is_err());
    }
}
