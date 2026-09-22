//! # Informant Orchestration Pipeline & Opt-in Engine
//! One-Job: Coordinate opt-in gates, dry-run simulations, cooldown verification, and multi-sink dispatch.

use crate::abuse_reporting::abuseipdb::AbuseIpDbCheckResponse;
use crate::abuse_reporting::cooldown::{CooldownConfig, ReportCooldownGovernor};
use crate::abuse_reporting::dossier::{DossierFormatter, ForensicDossier};
use crate::abuse_reporting::error::AbuseReportError;
use crate::abuse_reporting::sink::{
    AbuseIpDbSink, GenericWebhookSink, IncidentSink, MultiSink,
};
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
    /// Generic Webhook destination URL (for enterprise SIEM, Datadog, Slack, Splunk)
    pub webhook_url: Option<String>,
    /// Optional authorization header value for webhook (e.g. "Bearer token" or "ApiKey secret")
    pub webhook_auth: Option<String>,
    /// Cooldown & rate limiting configuration
    pub cooldown: CooldownConfig,
}

impl Default for InformantConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dry_run: true,
            api_key: None,
            webhook_url: None,
            webhook_auth: None,
            cooldown: CooldownConfig::default(),
        }
    }
}

impl InformantConfig {
    /// Discovers configuration from environment variables or standard reference paths:
    /// - Checks `ABUSEIPDB_API_KEY` environment variable or `~/Documents/reference/abuse_ip_db/api-key.txt`
    /// - Checks `PHYLAX_WEBHOOK_URL` / `RMT_WEBHOOK_URL` for generic enterprise sinks
    ///
    /// If an API key or webhook endpoint is discovered, automated reporting is armed by default.
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

        let webhook_url = std::env::var("PHYLAX_WEBHOOK_URL")
            .or_else(|_| std::env::var("RMT_WEBHOOK_URL"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let webhook_auth = std::env::var("PHYLAX_WEBHOOK_AUTH")
            .or_else(|_| std::env::var("RMT_WEBHOOK_AUTH"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let dry_run = std::env::var("RMT_ABUSE_REPORTING_DRY_RUN")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let enabled = (key.is_some() || webhook_url.is_some())
            && std::env::var("RMT_ABUSE_REPORTING_ENABLED")
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true);

        Self {
            enabled,
            dry_run,
            api_key: key,
            webhook_url,
            webhook_auth,
            cooldown: CooldownConfig::default(),
        }
    }
}

/// Result of evaluating an abusive incident
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InformantVerdict {
    /// Incident successfully reported to upstream threat intelligence or enterprise sink
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

/// Sovereign Informant Engine orchestrating threat reporting across one or multiple sinks
#[derive(Clone)]
pub struct InformantEngine {
    config: InformantConfig,
    cooldown_governor: ReportCooldownGovernor,
    sink: Arc<dyn IncidentSink>,
    transport: Option<Arc<dyn AbuseReporterTransport>>,
}

impl std::fmt::Debug for InformantEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InformantEngine")
            .field("config", &self.config)
            .field("sink_name", &self.sink.name())
            .field(
                "daily_reports_count",
                &self.cooldown_governor.daily_reports_count(),
            )
            .finish()
    }
}

impl InformantEngine {
    /// Helper to construct the appropriate IncidentSink from InformantConfig
    fn build_sink_from_config(
        config: &InformantConfig,
        transport: Arc<dyn AbuseReporterTransport>,
    ) -> Arc<dyn IncidentSink> {
        let mut sinks: Vec<Arc<dyn IncidentSink>> = Vec::new();

        if let Some(ref key) = config.api_key {
            if !key.trim().is_empty() {
                sinks.push(Arc::new(AbuseIpDbSink::new(key.clone(), transport.clone())));
            }
        }

        if let Some(ref url) = config.webhook_url {
            if !url.trim().is_empty() {
                let mut headers = Vec::new();
                if let Some(ref auth) = config.webhook_auth {
                    if !auth.trim().is_empty() {
                        headers.push(("Authorization".to_string(), auth.clone()));
                    }
                }
                sinks.push(Arc::new(GenericWebhookSink::new(url.clone(), headers)));
            }
        }

        if sinks.is_empty() {
            // Default to AbuseIpDbSink (will yield clean error if key missing upon live dispatch)
            Arc::new(AbuseIpDbSink::new(String::new(), transport))
        } else if sinks.len() == 1 {
            sinks.remove(0)
        } else {
            Arc::new(MultiSink::new(sinks))
        }
    }

    /// Primary constructor supporting transport abstraction (e.g. for AbuseIPDB & testing)
    pub fn new(config: InformantConfig, transport: Arc<dyn AbuseReporterTransport>) -> Self {
        let sink = Self::build_sink_from_config(&config, transport.clone());
        let cooldown_governor = ReportCooldownGovernor::new(config.cooldown.clone());
        Self {
            config,
            cooldown_governor,
            sink,
            transport: Some(transport),
        }
    }

    /// Enterprise constructor allowing injection of arbitrary IncidentSink (e.g. Webhook, Syslog, MultiSink)
    pub fn with_sink(config: InformantConfig, sink: Arc<dyn IncidentSink>) -> Self {
        let cooldown_governor = ReportCooldownGovernor::new(config.cooldown.clone());
        Self {
            config,
            cooldown_governor,
            sink,
            transport: None,
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

        // 4. Dispatch via configured sink
        match self.sink.dispatch(dossier).await {
            Ok(receipt) => {
                tracing::info!(
                    "📡 [INFORMANT] Successfully dispatched incident for IP '{}' via {} ({})",
                    dossier.client_ip,
                    receipt.sink_name,
                    receipt.detail
                );
                self.cooldown_governor
                    .record_reported(&dossier.client_ip, dossier.timestamp_ms);
                InformantVerdict::Reported {
                    ip: dossier.client_ip.clone(),
                    confidence_score: 0,
                }
            }
            Err(e) => {
                tracing::error!(
                    "❌ [INFORMANT] Failed to dispatch report for IP '{}': {}",
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

    pub fn sink(&self) -> &Arc<dyn IncidentSink> {
        &self.sink
    }

    /// Query AbuseIPDB reputation metadata for a given IP address
    pub async fn check_ip(&self, ip: &str) -> Result<AbuseIpDbCheckResponse, AbuseReportError> {
        let transport = self.transport.as_ref().ok_or_else(|| {
            AbuseReportError::Config("No AbuseIPDB transport available for check_ip".to_string())
        })?;
        let api_key = match self.config.api_key.as_deref() {
            Some(key) if !key.trim().is_empty() => key,
            _ => return Err(AbuseReportError::MissingApiKey),
        };
        transport.check_ip(ip, api_key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abuse_reporting::category::AbuseCategory;
    use crate::abuse_reporting::sink::MockIncidentSink;
    use crate::abuse_reporting::transport::MockAbuseReporterTransport;

    #[tokio::test]
    async fn test_pipeline_missing_api_key_returns_error() {
        let config = InformantConfig {
            enabled: true,
            dry_run: false,
            api_key: None,
            webhook_url: None,
            webhook_auth: None,
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

    #[tokio::test]
    async fn test_pipeline_with_generic_mock_sink_works_seamlessly() {
        let config = InformantConfig {
            enabled: true,
            dry_run: false,
            api_key: None,
            webhook_url: None,
            webhook_auth: None,
            cooldown: CooldownConfig::default(),
        };
        let mock_sink = Arc::new(MockIncidentSink::new());
        let engine = InformantEngine::with_sink(config, mock_sink.clone());

        let dossier = ForensicDossier {
            client_ip: "192.0.2.45".to_string(),
            timestamp_ms: 2000,
            target_uri: "/api/login".to_string(),
            http_method: "POST".to_string(),
            category: AbuseCategory::CredentialStuffing,
            trapped_field: Some("password_decoy".to_string()),
            user_agent: Some("CustomBot/1.0".to_string()),
            evidence_notes: "Automated credential burst".to_string(),
        };

        let verdict = engine.process_incident(&dossier).await;
        assert!(matches!(verdict, InformantVerdict::Reported { .. }));
        assert_eq!(mock_sink.recorded_dossiers().len(), 1);
        assert_eq!(mock_sink.recorded_dossiers()[0].client_ip, "192.0.2.45");
    }

    #[test]
    fn test_default_informant_config_is_safely_disabled() {
        let def = InformantConfig::default();
        assert!(!def.enabled);
        assert!(def.dry_run);
        assert!(def.api_key.is_none());
        assert!(def.webhook_url.is_none());
    }
}
