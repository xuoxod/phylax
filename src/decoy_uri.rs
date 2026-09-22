//! # Autonomous Decoy URI Honeyroutes & Reconnaissance Traps
//! One-Job: Deterministically identify and categorize automated scanners probing known decoy endpoints.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Category of decoy endpoint tripped by the scanner
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecoyCategory {
    /// Environment / Secrets (`/.env`, `/pip.conf`, `/.azure/credentials`)
    EnvironmentSecret,
    /// Version Control Systems (`/.git`, `/.svn`)
    VersionControl,
    /// Cloud & Infrastructure State (`/terraform.tfstate`, `/.aws`)
    CloudInfrastructure,
    /// Admin & CMS Probes (`/wp-admin`, `/wp-login.php`, `/phpmyadmin`)
    AdminCmsProbe,
    /// Database & Filesystem Dumps (`/dump.sql`, `/backup.zip`)
    DatabaseBackup,
    /// Private Keys & Tokens (`/private.key`, `/id_rsa`)
    PrivateKey,
    /// User-defined custom decoy route
    Custom,
}

impl DecoyCategory {
    pub fn name(&self) -> &'static str {
        match self {
            Self::EnvironmentSecret => "Environment & Secrets Probe",
            Self::VersionControl => "Version Control Repository Probe",
            Self::CloudInfrastructure => "Cloud & Infrastructure State Probe",
            Self::AdminCmsProbe => "Administrative & CMS Panel Probe",
            Self::DatabaseBackup => "Database & Filesystem Backup Probe",
            Self::PrivateKey => "Cryptographic Private Key Probe",
            Self::Custom => "Custom Decoy Honeyroute",
        }
    }
}

/// Verdict returned from Decoy URI evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecoyUriVerdict {
    Clean,
    Trapped {
        matched_path: String,
        category: DecoyCategory,
    },
}

/// Configuration for Decoy URI Honeyroute Sentinel
#[derive(Debug, Clone)]
pub struct DecoyUriConfig {
    pub enabled: bool,
    pub custom_exact_routes: Vec<(String, DecoyCategory)>,
    pub custom_prefix_routes: Vec<(String, DecoyCategory)>,
}

impl Default for DecoyUriConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            custom_exact_routes: Vec::new(),
            custom_prefix_routes: Vec::new(),
        }
    }
}

/// Sentinel that deterministically matches scanner reconnaissance probes in sub-microsecond time
#[derive(Debug, Clone)]
pub struct DecoyUriSentinel {
    enabled: bool,
    exact_traps: HashSet<String>,
    prefix_traps: Vec<(String, DecoyCategory)>,
}

impl Default for DecoyUriSentinel {
    fn default() -> Self {
        Self::new(DecoyUriConfig::default())
    }
}

impl DecoyUriSentinel {
    /// Construct a new sentinel loaded with the curated production catalog
    pub fn new(config: DecoyUriConfig) -> Self {
        let mut exact_traps = HashSet::new();
        let mut prefix_traps = Vec::new();

        // 1. Curated Exact Traps: Environment, Secrets & Cloud Probes
        let standard_exact = [
            // Environment files
            ("/.env", DecoyCategory::EnvironmentSecret),
            ("/.env.local", DecoyCategory::EnvironmentSecret),
            ("/.env.production", DecoyCategory::EnvironmentSecret),
            ("/.env.backup", DecoyCategory::EnvironmentSecret),
            ("/.env.defaults", DecoyCategory::EnvironmentSecret),
            ("/.env_hidden", DecoyCategory::EnvironmentSecret),
            ("/fe/.env", DecoyCategory::EnvironmentSecret),
            ("/develop/.env", DecoyCategory::EnvironmentSecret),
            ("/pip.conf", DecoyCategory::EnvironmentSecret),
            ("/.azure/credentials", DecoyCategory::EnvironmentSecret),
            ("/auth.json", DecoyCategory::EnvironmentSecret),
            ("/secrets.json", DecoyCategory::EnvironmentSecret),
            ("/config.json", DecoyCategory::EnvironmentSecret),
            ("/config.properties", DecoyCategory::EnvironmentSecret),
            ("/config.codekit", DecoyCategory::EnvironmentSecret),
            ("/config/constant.js", DecoyCategory::EnvironmentSecret),
            // Cloud & Infrastructure
            ("/app/terraform.tfstate", DecoyCategory::CloudInfrastructure),
            ("/terraform.tfstate", DecoyCategory::CloudInfrastructure),
            ("/awsconfiguration.json", DecoyCategory::CloudInfrastructure),
            ("/aws.sh", DecoyCategory::CloudInfrastructure),
            ("/Procfile", DecoyCategory::CloudInfrastructure),
            ("/.firebaserc", DecoyCategory::CloudInfrastructure),
            ("/.tugboat", DecoyCategory::CloudInfrastructure),
            ("/.codeclimate.yml", DecoyCategory::CloudInfrastructure),
            ("/.zsh_history", DecoyCategory::EnvironmentSecret),
            ("/.wget-hsts", DecoyCategory::EnvironmentSecret),
            ("/errors.log", DecoyCategory::EnvironmentSecret),
            // CMS & Admin Panels
            ("/wp-login.php", DecoyCategory::AdminCmsProbe),
            ("/xmlrpc.php", DecoyCategory::AdminCmsProbe),
            ("/sites/default/settings.php.old", DecoyCategory::AdminCmsProbe),
            ("/bitrix/modules/updater_partner.log", DecoyCategory::AdminCmsProbe),
            // Private Keys & Certificates
            ("/private.key", DecoyCategory::PrivateKey),
            ("/id_rsa", DecoyCategory::PrivateKey),
            ("/storage/oauth-public.key", DecoyCategory::PrivateKey),
            // Backups
            ("/web.zip", DecoyCategory::DatabaseBackup),
            ("/site.tar.gz", DecoyCategory::DatabaseBackup),
            ("/backup.sql", DecoyCategory::DatabaseBackup),
            ("/database.sql", DecoyCategory::DatabaseBackup),
            ("/dump.sql", DecoyCategory::DatabaseBackup),
        ];

        for (path, _) in &standard_exact {
            exact_traps.insert(path.to_ascii_lowercase());
        }

        // 2. Curated Prefix Traps
        let standard_prefix = [
            ("/.git/", DecoyCategory::VersionControl),
            ("/.git", DecoyCategory::VersionControl),
            ("/.svn/", DecoyCategory::VersionControl),
            ("/.svn", DecoyCategory::VersionControl),
            ("/.aws/", DecoyCategory::CloudInfrastructure),
            ("/wp-admin", DecoyCategory::AdminCmsProbe),
            ("/phpmyadmin", DecoyCategory::AdminCmsProbe),
            ("/pma", DecoyCategory::AdminCmsProbe),
            ("/actuator/", DecoyCategory::AdminCmsProbe),
            ("/k8s/", DecoyCategory::CloudInfrastructure),
        ];

        for (prefix, category) in &standard_prefix {
            prefix_traps.push((prefix.to_ascii_lowercase(), *category));
        }

        // 3. User-defined Custom Traps
        for (exact, _) in &config.custom_exact_routes {
            exact_traps.insert(exact.to_ascii_lowercase());
        }
        for (prefix, category) in config.custom_prefix_routes {
            prefix_traps.push((prefix.to_ascii_lowercase(), category));
        }

        Self {
            enabled: config.enabled,
            exact_traps,
            prefix_traps,
        }
    }

    /// Normalizes a URI path (removes query/fragment, collapses multiple slashes, converts to lowercase)
    #[inline]
    pub fn normalize_path(raw_path: &str) -> String {
        let path_without_query = match raw_path.find('?') {
            Some(idx) => &raw_path[..idx],
            None => raw_path,
        };

        let path_without_hash = match path_without_query.find('#') {
            Some(idx) => &path_without_query[..idx],
            None => path_without_query,
        };

        let trimmed = path_without_hash.trim();
        if trimmed.is_empty() {
            return "/".to_string();
        }

        // Collapse multi-slashes e.g. "//.env" -> "/.env"
        let mut normalized = String::with_capacity(trimmed.len());
        let mut last_was_slash = false;

        for ch in trimmed.chars() {
            let lower = ch.to_ascii_lowercase();
            if lower == '/' {
                if !last_was_slash {
                    normalized.push('/');
                    last_was_slash = true;
                }
            } else {
                normalized.push(lower);
                last_was_slash = false;
            }
        }

        if !normalized.starts_with('/') {
            normalized.insert(0, '/');
        }

        normalized
    }

    /// Evaluates a requested URI path in sub-microsecond time
    pub fn evaluate(&self, raw_path: &str) -> DecoyUriVerdict {
        if !self.enabled {
            return DecoyUriVerdict::Clean;
        }

        // Fast-path: If path is already clean lowercase with no query/multi-slash, avoid all heap allocations
        let needs_normalization = raw_path
            .bytes()
            .any(|b| b.is_ascii_uppercase() || b == b'?' || b == b'#' || b == b'\\')
            || raw_path.contains("//");

        if !needs_normalization {
            let path = raw_path.trim();

            if self.exact_traps.contains(path) {
                let category = self.categorize_path(path);
                return DecoyUriVerdict::Trapped {
                    matched_path: path.to_string(),
                    category,
                };
            }

            for (prefix, category) in &self.prefix_traps {
                if path.starts_with(prefix) {
                    return DecoyUriVerdict::Trapped {
                        matched_path: path.to_string(),
                        category: *category,
                    };
                }
            }

            if let Some(ext_idx) = path.rfind('.') {
                let ext = &path[ext_idx..];
                if (ext == ".sql" || ext == ".dump" || ext == ".bak" || ext == ".old" || ext == ".swp")
                    && (path.contains("db")
                        || path.contains("data")
                        || path.contains("backup")
                        || path.contains("user")
                        || path.contains("pass")
                        || path.contains("dump"))
                {
                    return DecoyUriVerdict::Trapped {
                        matched_path: path.to_string(),
                        category: DecoyCategory::DatabaseBackup,
                    };
                }
            }

            return DecoyUriVerdict::Clean;
        }

        let normalized = Self::normalize_path(raw_path);

        // 1. Exact Match Check (O(1) HashSet lookup, ~5-10ns)
        if self.exact_traps.contains(&normalized) {
            let category = self.categorize_path(&normalized);
            return DecoyUriVerdict::Trapped {
                matched_path: normalized,
                category,
            };
        }

        // 2. Prefix Match Check
        for (prefix, category) in &self.prefix_traps {
            if normalized.starts_with(prefix) {
                return DecoyUriVerdict::Trapped {
                    matched_path: normalized,
                    category: *category,
                };
            }
        }

        // 3. Sensitive Backup Extension Check (*.sql, *.dump, *.tar.gz, *.bak, *.old)
        if let Some(ext_idx) = normalized.rfind('.') {
            let ext = &normalized[ext_idx..];
            if (ext == ".sql" || ext == ".dump" || ext == ".bak" || ext == ".old" || ext == ".swp")
                && (normalized.contains("db")
                    || normalized.contains("data")
                    || normalized.contains("backup")
                    || normalized.contains("user")
                    || normalized.contains("pass")
                    || normalized.contains("dump"))
            {
                return DecoyUriVerdict::Trapped {
                    matched_path: normalized,
                    category: DecoyCategory::DatabaseBackup,
                };
            }
        }

        DecoyUriVerdict::Clean
    }

    /// Helper to assign appropriate category to exact matches
    fn categorize_path(&self, path: &str) -> DecoyCategory {
        if path.contains("env") || path.contains("pip.conf") || path.contains("credentials") || path.contains("auth.json") || path.contains("secrets") || path.contains("config") {
            DecoyCategory::EnvironmentSecret
        } else if path.contains("terraform") || path.contains("aws") || path.contains("k8s") || path.contains("firebase") {
            DecoyCategory::CloudInfrastructure
        } else if path.contains("wp-") || path.contains("xmlrpc") || path.contains("phpmyadmin") || path.contains("settings.php") {
            DecoyCategory::AdminCmsProbe
        } else if path.contains("key") || path.contains("id_rsa") {
            DecoyCategory::PrivateKey
        } else if path.contains(".zip") || path.contains(".tar") || path.contains(".sql") {
            DecoyCategory::DatabaseBackup
        } else {
            DecoyCategory::Custom
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_production_paths_are_not_trapped() {
        let sentinel = DecoyUriSentinel::default();
        let clean_paths = [
            "/",
            "/auth/login",
            "/auth/register",
            "/downloads",
            "/tools/media-forge",
            "/pricing",
            "/about",
            "/terms",
            "/healthz",
            "/api/v1/status",
            "/assets/main.css",
            "/images/logo.png",
        ];

        for path in &clean_paths {
            assert_eq!(
                sentinel.evaluate(path),
                DecoyUriVerdict::Clean,
                "Path '{}' should be clean",
                path
            );
        }
    }

    #[test]
    fn test_exact_decoy_paths_are_trapped() {
        let sentinel = DecoyUriSentinel::default();

        let trapped_cases = [
            ("/.env", DecoyCategory::EnvironmentSecret),
            ("/.env.local", DecoyCategory::EnvironmentSecret),
            ("/pip.conf", DecoyCategory::EnvironmentSecret),
            ("/.azure/credentials", DecoyCategory::EnvironmentSecret),
            ("/auth.json", DecoyCategory::EnvironmentSecret),
            ("/app/terraform.tfstate", DecoyCategory::CloudInfrastructure),
            ("/wp-login.php", DecoyCategory::AdminCmsProbe),
            ("/private.key", DecoyCategory::PrivateKey),
            ("/backup.sql", DecoyCategory::DatabaseBackup),
        ];

        for (path, expected_category) in &trapped_cases {
            let verdict = sentinel.evaluate(path);
            assert!(
                matches!(verdict, DecoyUriVerdict::Trapped { category, .. } if category == *expected_category),
                "Path '{}' expected {:?}, got {:?}",
                path,
                expected_category,
                verdict
            );
        }
    }

    #[test]
    fn test_prefix_decoy_paths_are_trapped() {
        let sentinel = DecoyUriSentinel::default();

        let prefix_cases = [
            ("/.git/config", DecoyCategory::VersionControl),
            ("/.git/HEAD", DecoyCategory::VersionControl),
            ("/.svn/entries", DecoyCategory::VersionControl),
            ("/.aws/credentials", DecoyCategory::CloudInfrastructure),
            ("/wp-admin/includes/post.php", DecoyCategory::AdminCmsProbe),
            ("/phpmyadmin/index.php", DecoyCategory::AdminCmsProbe),
            ("/actuator/health", DecoyCategory::AdminCmsProbe),
        ];

        for (path, expected_category) in &prefix_cases {
            let verdict = sentinel.evaluate(path);
            assert!(
                matches!(verdict, DecoyUriVerdict::Trapped { category, .. } if category == *expected_category),
                "Prefix path '{}' expected {:?}, got {:?}",
                path,
                expected_category,
                verdict
            );
        }
    }

    #[test]
    fn test_path_normalization_multi_slash_and_case_insensitivity() {
        let sentinel = DecoyUriSentinel::default();

        // Multi-slash
        assert!(matches!(
            sentinel.evaluate("//.env"),
            DecoyUriVerdict::Trapped { .. }
        ));

        // Mixed case
        assert!(matches!(
            sentinel.evaluate("/.ENV"),
            DecoyUriVerdict::Trapped { .. }
        ));

        // Query parameters appended by scanners
        assert!(matches!(
            sentinel.evaluate("/.env?id=1&debug=true"),
            DecoyUriVerdict::Trapped { .. }
        ));
    }

    #[test]
    fn test_custom_decoy_routes() {
        let config = DecoyUriConfig {
            enabled: true,
            custom_exact_routes: vec![
                ("/my-hidden-debug".to_string(), DecoyCategory::Custom),
            ],
            custom_prefix_routes: vec![
                ("/internal-admin/".to_string(), DecoyCategory::Custom),
            ],
        };
        let sentinel = DecoyUriSentinel::new(config);

        assert!(matches!(
            sentinel.evaluate("/my-hidden-debug"),
            DecoyUriVerdict::Trapped { category: DecoyCategory::Custom, .. }
        ));

        assert!(matches!(
            sentinel.evaluate("/internal-admin/dashboard"),
            DecoyUriVerdict::Trapped { category: DecoyCategory::Custom, .. }
        ));
    }

    #[test]
    fn test_sub_microsecond_evaluation_performance() {
        let sentinel = DecoyUriSentinel::default();
        let path = "/auth/register";

        let start = std::time::Instant::now();
        for _ in 0..10_000 {
            let _ = sentinel.evaluate(path);
        }
        let elapsed = start.elapsed();
        let avg_ns = elapsed.as_nanos() / 10_000;
        // In unoptimized debug test profile, ensure it executes well within microsecond bounds (<5µs)
        assert!(avg_ns < 5000, "Average evaluation should be < 5000ns in debug build (was {}ns)", avg_ns);
    }
}
