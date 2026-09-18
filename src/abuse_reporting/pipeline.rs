//! # Informant Orchestration Pipeline & Opt-in Engine
//! One-Job: Coordinate opt-in gates, dry-run simulations, cooldown verification, and dispatch.

use crate::abuse_reporting::abuseipdb::AbuseIpDbReportPayload;
use crate::abuse_reporting::cooldown::{CooldownConfig, ReportCooldownGovernor};
use crate::abuse_reporting::dossier::{DossierFormatter, ForensicDossier};
use crate::abuse_reporting::transport::{AbuseReporterTransport, HttpAbuseReporterTransport};
use std::sync::Arc;

/// Operational configuration for the abuse informant engine
#[derive(Debug, Clone)]
pub struct InformantConfig {
    /// Master opt-in switch (defaults to false for safety)
    pub enabled: bool,
    /// Dry-run simulation mode (formats dossiers without outbound transmission)
    pub dry_run: bool,
    /// AbuseIPDB API key (if live dispatch enabled)
    pub api_key: Option<String>,
    /// Cooldown & rate limiting configuration
    pub cooldown: CooldownConfig,
}

impl Default for InformantConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dry_run: true,
            api_key: None,
            cooldown: CooldownConfig::default(),
        }
    }
}

impl InformantConfig {
    /// Discovers configuration from environment variables or standard reference paths:
    /// - Checks `ABUSEIPDB_API_KEY` environment variable
    /// - Checks `~/Documents/reference/abuse_ip_db/api-key.txt` reference file
    /// If an API key is discovered, live automated reporting is enabled.
    pub fn from_env_or_default() -> Self {
        let key = std::env::var("ABUSEIPDB_API_KEY")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                let home = std::env::var("HOME").ok()?;
                let path = format!("{}/Documents/reference/abuse_ip_db/api-key.txt", home);
                std::fs::read_to_string(path)
                    .ok()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
            });

        let dry_run = std::env::var("RMT_ABUSE_REPORTING_DRY_RUN")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let enabled = key.is_some()
            && std::env::var("RMT_ABUSE_REPORTING_ENABLED")
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true);

        Self {
            enabled,
            dry_run,
            api_key: key,
            cooldown: CooldownConfig::default(),
        }
    }
}

/// Result of evaluating an abusive incident
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InformantVerdict {
    /// Incident successfully reported to upstream threat intelligence
    Reported { ip: String, confidence_score: u32 },
    /// Incident verified and formatted in dry-run mode
    DryRunReported {
        ip: String,
        categories: String,
        comment: String,
    },
    /// Report suppressed due to per-IP cooldown window or daily quota limit
    SuppressedCooldown,
    /// Engine is disabled in configuration
    Disabled,
    /// Report failed due to network or authorization error
    Error(String),
}

/// Sovereign Informant Engine orchestrating threat reporting
#[derive(Clone)]
pub struct InformantEngine {
    config: InformantConfig,
    cooldown_governor: ReportCooldownGovernor,
    transport: Arc<dyn AbuseReporterTransport>,
}

impl std::fmt::Debug for InformantEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InformantEngine")
            .field("config", &self.config)
            .field(
                "daily_reports_count",
                &self.cooldown_governor.daily_reports_count(),
            )
            .finish()
    }
}

impl InformantEngine {
    pub fn new(config: InformantConfig, transport: Arc<dyn AbuseReporterTransport>) -> Self {
        let cooldown_governor = ReportCooldownGovernor::new(config.cooldown.clone());
        Self {
            config,
            cooldown_governor,
            transport,
        }
    }

    /// Construct an InformantEngine backed by the production HTTP transport
    pub fn with_http_transport(config: InformantConfig) -> Self {
        let transport = Arc::new(HttpAbuseReporterTransport::new(None));
        Self::new(config, transport)
    }

    /// Evaluates a forensic dossier and dispatches to configured sinks
    pub async fn process_incident(&self, dossier: &ForensicDossier) -> InformantVerdict {
        // 1. Check master opt-in switch
        if !self.config.enabled {
            return InformantVerdict::Disabled;
        }

        // 2. Check deduplication & daily quota cooldown
        if !self
            .cooldown_governor
            .should_report(&dossier.client_ip, dossier.timestamp_ms)
        {
            tracing::debug!(
                "🛑 [INFORMANT] Incident report suppressed by cooldown for IP '{}'",
                dossier.client_ip
            );
            return InformantVerdict::SuppressedCooldown;
        }

        let comment = DossierFormatter::render_incident_comment(dossier);
        let categories = dossier.category.to_categories_param();

        // 3. Dry-Run Mode: Record and format without external API calls
        if self.config.dry_run {
            tracing::info!(
                "🧪 [INFORMANT DRY-RUN] Formatted abuse report for IP '{}' (categories: {}): \n{}",
                dossier.client_ip,
                categories,
                comment
            );
            self.cooldown_governor
                .record_reported(&dossier.client_ip, dossier.timestamp_ms);
            return InformantVerdict::DryRunReported {
                ip: dossier.client_ip.clone(),
                categories,
                comment,
            };
        }

        // 4. Validate API Key for live dispatch
        let api_key = match self.config.api_key.as_deref() {
            Some(key) if !key.trim().is_empty() => key,
            _ => {
                let err_msg =
                    "Abuse reporting is enabled but no valid AbuseIPDB API key was provided"
                        .to_string();
                tracing::warn!("⚠️ [INFORMANT] {}", err_msg);
                return InformantVerdict::Error(err_msg);
            }
        };

        let payload = AbuseIpDbReportPayload {
            ip: dossier.client_ip.clone(),
            categories,
            comment,
        };

        // 5. Dispatch via configured transport
        match self.transport.submit_report(&payload, api_key).await {
            Ok(resp) => {
                tracing::info!(
                    "📡 [INFORMANT] Successfully reported abusive IP '{}' (Confidence Score: {})",
                    resp.ip_address,
                    resp.abuse_confidence_score
                );
                self.cooldown_governor
                    .record_reported(&dossier.client_ip, dossier.timestamp_ms);
                InformantVerdict::Reported {
                    ip: resp.ip_address,
                    confidence_score: resp.abuse_confidence_score,
                }
            }
            Err(e) => {
                tracing::error!(
                    "❌ [INFORMANT] Failed to submit report for IP '{}': {}",
                    dossier.client_ip,
                    e
                );
                InformantVerdict::Error(e.to_string())
            }
        }
    }

    pub fn cooldown_governor(&self) -> &ReportCooldownGovernor {
        &self.cooldown_governor
    }

    pub fn config(&self) -> &InformantConfig {
        &self.config
    }

    /// Query AbuseIPDB reputation metadata for a given IP address
    pub async fn check_ip(
        &self,
        ip: &str,
    ) -> Result<
        crate::abuse_reporting::abuseipdb::AbuseIpDbCheckResponse,
        crate::abuse_reporting::error::AbuseReportError,
    > {
        let api_key = match self.config.api_key.as_deref() {
            Some(key) if !key.trim().is_empty() => key,
            _ => return Err(crate::abuse_reporting::error::AbuseReportError::MissingApiKey),
        };
        self.transport.check_ip(ip, api_key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abuse_reporting::category::AbuseCategory;
    use crate::abuse_reporting::transport::MockAbuseReporterTransport;

    #[tokio::test]
    async fn test_pipeline_missing_api_key_returns_error() {
        let config = InformantConfig {
            enabled: true,
            dry_run: false,
            api_key: None,
            cooldown: CooldownConfig::default(),
        };
        let mock = Arc::new(MockAbuseReporterTransport::new());
        let engine = InformantEngine::new(config, mock);

        let dossier = ForensicDossier {
            client_ip: "1.2.3.4".to_string(),
            timestamp_ms: 1000,
            target_uri: "/test".to_string(),
            http_method: "POST".to_string(),
            category: AbuseCategory::WebHoneypot,
            trapped_field: None,
            user_agent: None,
            evidence_notes: "notes".to_string(),
        };

        let verdict = engine.process_incident(&dossier).await;
        assert!(matches!(verdict, InformantVerdict::Error(_)));
    }

    #[test]
    fn test_default_informant_config_is_safely_disabled() {
        let def = InformantConfig::default();
        assert!(!def.enabled);
        assert!(def.dry_run);
        assert!(def.api_key.is_none());
    }
}
