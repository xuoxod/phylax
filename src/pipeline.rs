//! # Radical OJP: Composable Fail-Fast Shield Pipeline
//! Single Job: Chain all isolated defense layers into a unified, zero-overhead pipeline.

use crate::adaptive_pow::{AdaptivePowConfig, AdaptivePowEngine, InfractionSeverity};
use crate::autonomous_quarantine::{AutonomousQuarantine, QuarantineConfig};
use crate::decoy_uri::{DecoyUriConfig, DecoyUriSentinel, DecoyUriVerdict};
use crate::email_guard::{EmailPatternGuard, EmailVerdict};
use crate::honeypot::{HoneypotValidator, HoneypotVerdict};
use crate::pow::{PowEngine, PowVerdict};
use crate::subnet_guard::{SubnetGuard, SubnetVerdict};
use crate::tarpit::{TarpitConfig, TarpitGovernor};
use crate::timing::{TimingGuard, TimingVerdict};
use serde::{Deserialize, Serialize};
#[cfg(feature = "abuse-reporting")]
use std::sync::Arc;

/// Request context submitted for Shield verification
#[derive(Debug, Clone, Default)]
pub struct ShieldRequest<'a> {
    pub client_ip: &'a str,
    pub submitted_fields: &'a [(String, String)],
    pub timing_token: Option<&'a str>,
    pub pow_challenge_token: Option<&'a str>,
    pub pow_nonce: Option<u64>,
    pub email: Option<&'a str>,
    pub target_uri: Option<&'a str>,
    pub http_method: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub now_ms: u64,
}

/// Client context issued to HTML/JS frontends for rendering decoy fields, timing token, and PoW puzzle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldClientContext {
    pub timing_token: String,
    pub pow_challenge: String,
    pub pow_seed: String,
    pub pow_difficulty: u8,
    pub decoy_fields: Vec<String>,
}

/// Reason for Shield denial
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenialReason {
    HoneypotTrapped { field: String },
    DecoyUriTrapped { path: String, category: String },
    SubnetBlocked { ip: String, cidr: String },
    EmailPatternSuspicious { reason: String },
    SubmissionTooFast { elapsed_ms: u64, min_ms: u64 },
    SubmissionTimingExpired,
    TimingSignatureInvalid,
    MissingTimingToken,
    PowInvalidSolution,
    PowExpired,
    PowReplayed,
    MissingPowChallenge,
}

impl DenialReason {
    pub fn public_message(&self) -> &'static str {
        match self {
            DenialReason::HoneypotTrapped { .. } => "Automated submission detected (trap tripped).",
            DenialReason::DecoyUriTrapped { .. } => {
                "Access restricted: Automated reconnaissance probe detected."
            }
            DenialReason::SubnetBlocked { .. } => {
                "Perimeter access restricted: Tor exit node or hosting datacenter."
            }
            DenialReason::EmailPatternSuspicious { .. } => "Invalid or suspicious email pattern.",
            DenialReason::SubmissionTooFast { .. } => {
                "Form submitted suspiciously fast. Please take your time."
            }
            DenialReason::SubmissionTimingExpired => {
                "Form session expired. Please refresh the page."
            }
            DenialReason::TimingSignatureInvalid => "Form verification signature mismatch.",
            DenialReason::MissingTimingToken => "Missing security timing token.",
            DenialReason::PowInvalidSolution => "Proof of work puzzle verification failed.",
            DenialReason::PowExpired => "Proof of work puzzle expired. Please reload the page.",
            DenialReason::PowReplayed => {
                "Security token has already been consumed. Please refresh."
            }
            DenialReason::MissingPowChallenge => "Missing proof of work security challenge.",
        }
    }
}

/// Verdict from Shield evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShieldVerdict {
    /// All layers passed. Genuine operator.
    Allow {
        canonical_email: Option<String>,
        elapsed_timing_ms: Option<u64>,
    },
    /// One of the defense layers failed.
    Deny(DenialReason),
}

impl ShieldVerdict {
    #[inline]
    pub fn is_allowed(&self) -> bool {
        matches!(self, ShieldVerdict::Allow { .. })
    }

    #[inline]
    pub fn is_denied(&self) -> bool {
        !self.is_allowed()
    }
}

/// Composable Sovereign Shield Pipeline
#[derive(Debug, Clone)]
pub struct ShieldPipeline {
    honeypot: HoneypotValidator,
    timing: TimingGuard,
    pow: PowEngine,
    email_guard: EmailPatternGuard,
    subnet_guard: SubnetGuard,
    tarpit: TarpitGovernor,
    adaptive_pow: AdaptivePowEngine,
    quarantine: AutonomousQuarantine,
    decoy_uri: DecoyUriSentinel,
    threat_harvester: crate::threat_harvester::ThreatHarvesterEngine,
    enable_pow: bool,
    enable_timing: bool,
    enable_subnet: bool,
    #[cfg(feature = "abuse-reporting")]
    informant: Option<Arc<crate::abuse_reporting::InformantEngine>>,
}

impl ShieldPipeline {
    /// Create a new pipeline builder
    pub fn builder() -> ShieldPipelineBuilder {
        ShieldPipelineBuilder::default()
    }

    /// Access the Decoy URI Sentinel
    pub fn decoy_uri(&self) -> &DecoyUriSentinel {
        &self.decoy_uri
    }

    /// Access the Threat Harvester Engine (Layer 13)
    pub fn threat_harvester(&self) -> &crate::threat_harvester::ThreatHarvesterEngine {
        &self.threat_harvester
    }

    /// Record an anomalous or unmapped URI probe into the multi-subnet threat harvester.
    /// Autonomously promotes confirmed zero-day threats into the DecoyUriSentinel.
    pub fn record_anomalous_uri(
        &self,
        raw_path: &str,
        client_ip: std::net::IpAddr,
        now_ms: u64,
    ) -> Option<crate::threat_harvester::PromotionVerdict> {
        self.threat_harvester.ingest_anomalous_uri(raw_path, client_ip, now_ms)
    }

    /// Convenience wrapper to record anomalous URI using string IP representation
    pub fn record_anomalous_uri_str(
        &self,
        raw_path: &str,
        client_ip_str: &str,
        now_ms: u64,
    ) -> Option<crate::threat_harvester::PromotionVerdict> {
        self.threat_harvester.ingest_anomalous_uri_str(raw_path, client_ip_str, now_ms)
    }

    /// Access the Tarpit Governor
    pub fn tarpit(&self) -> &TarpitGovernor {
        &self.tarpit
    }

    /// Access the Adaptive PoW Engine
    pub fn adaptive_pow(&self) -> &AdaptivePowEngine {
        &self.adaptive_pow
    }

    /// Access the Autonomous Quarantine Engine
    pub fn quarantine(&self) -> &AutonomousQuarantine {
        &self.quarantine
    }

    /// Create a MaintenanceManager bound to this pipeline's live defensive state
    pub fn maintenance_manager(&self) -> crate::maintenance::MaintenanceManager {
        crate::maintenance::MaintenanceManager::new(
            self.quarantine.clone(),
            self.adaptive_pow.clone(),
        )
        .with_threat_harvester(self.threat_harvester.clone())
    }

    /// Execute a maintenance pass directly across this pipeline's defense engines
    pub fn run_maintenance(&self, now_ms: u64) -> crate::maintenance::MaintenanceReport {
        self.maintenance_manager().run_maintenance(now_ms)
    }

    /// Spawn a persistent non-blocking background task running periodic maintenance for this pipeline
    pub fn spawn_background_maintenance(
        &self,
        interval: std::time::Duration,
    ) -> tokio::task::JoinHandle<()> {
        self.maintenance_manager().spawn_background_worker(interval)
    }

    #[cfg(feature = "abuse-reporting")]
    /// Access the abuse informant engine if configured
    pub fn informant(&self) -> Option<&Arc<crate::abuse_reporting::InformantEngine>> {
        self.informant.as_ref()
    }

    /// Issue a client context (timing token + PoW challenge + decoy field list)
    pub fn issue_client_context(&self, now_ms: u64, seed_nonce: u64) -> ShieldClientContext {
        self.issue_client_context_for_ip("", now_ms, seed_nonce)
    }

    /// Issue an adaptive client context with dynamic PoW difficulty scaled by client IP threat score
    pub fn issue_client_context_for_ip(
        &self,
        ip: &str,
        now_ms: u64,
        seed_nonce: u64,
    ) -> ShieldClientContext {
        let timing_token = self.timing.generate_token(now_ms);
        let difficulty = if ip.is_empty() {
            self.pow.difficulty_bits()
        } else {
            self.adaptive_pow.get_difficulty(ip, now_ms) as u8
        };
        let (pow_seed, pow_challenge) = self
            .pow
            .issue_challenge_with_difficulty(now_ms, seed_nonce, difficulty);

        ShieldClientContext {
            timing_token,
            pow_challenge,
            pow_seed,
            pow_difficulty: difficulty,
            decoy_fields: self.honeypot.decoy_fields().to_vec(),
        }
    }

    /// Evaluate an incoming request through all enabled chained defense layers (Fail-Fast)
    pub fn evaluate(&self, req: &ShieldRequest) -> ShieldVerdict {
        self.evaluate_flexible(req, self.enable_timing, self.enable_pow)
    }

    /// Evaluate only perimeter layers (honeypot, subnet, email) without timing or PoW constraints
    pub fn evaluate_perimeter(&self, req: &ShieldRequest) -> ShieldVerdict {
        self.evaluate_flexible(req, false, false)
    }

    /// Flexible evaluation allowing runtime toggling of timing and PoW requirements
    pub fn evaluate_flexible(
        &self,
        req: &ShieldRequest,
        require_timing: bool,
        require_pow: bool,
    ) -> ShieldVerdict {
        // 0. Layer 0: Autonomous Quarantine Check (~10ns)
        if !req.client_ip.is_empty() && self.quarantine.is_quarantined(req.client_ip, req.now_ms) {
            return ShieldVerdict::Deny(DenialReason::SubnetBlocked {
                ip: req.client_ip.to_string(),
                cidr: "autonomous_quarantine".to_string(),
            });
        }

        // 0.5 Layer 0.5: Decoy URI Reconnaissance Check (~5-10ns)
        if let Some(target_uri) = req.target_uri {
            let uri_verdict = self.decoy_uri.evaluate(target_uri);
            if let DecoyUriVerdict::Trapped { matched_path, category } = uri_verdict {
                if !req.client_ip.is_empty() {
                    self.quarantine.record_and_check(req.client_ip, req.now_ms);
                    self.adaptive_pow.record_infraction(
                        req.client_ip,
                        InfractionSeverity::Hostile,
                        req.now_ms,
                    );

                    #[cfg(feature = "abuse-reporting")]
                    if let Some(ref informant) = self.informant {
                        let dossier = crate::abuse_reporting::ForensicDossier {
                            client_ip: req.client_ip.to_string(),
                            timestamp_ms: req.now_ms,
                            target_uri: target_uri.to_string(),
                            http_method: req.http_method.unwrap_or("GET").to_string(),
                            category: crate::abuse_reporting::AbuseCategory::ExploitProbe,
                            trapped_field: None,
                            user_agent: req.user_agent.map(|s| s.to_string()),
                            evidence_notes: format!(
                                "Phylax autonomous decoy URI probe trapped on path '{}' ({})",
                                matched_path,
                                category.name()
                            ),
                        };
                        let informant_cloned = informant.clone();
                        tokio::spawn(async move {
                            informant_cloned.process_incident(&dossier).await;
                        });
                    }
                }
                return ShieldVerdict::Deny(DenialReason::DecoyUriTrapped {
                    path: matched_path,
                    category: category.name().to_string(),
                });
            }
        }

        // 1. Layer 1: Honeypot Check (~5ns)
        let hp_verdict = self.honeypot.validate(req.submitted_fields);
        if let HoneypotVerdict::Trapped { field_name, .. } = hp_verdict {
            if !req.client_ip.is_empty() {
                self.quarantine.record_and_check(req.client_ip, req.now_ms);
                self.adaptive_pow.record_infraction(
                    req.client_ip,
                    InfractionSeverity::Severe,
                    req.now_ms,
                );

                #[cfg(feature = "abuse-reporting")]
                if let Some(ref informant) = self.informant {
                    let dossier = crate::abuse_reporting::ForensicDossier {
                        client_ip: req.client_ip.to_string(),
                        timestamp_ms: req.now_ms,
                        target_uri: req.target_uri.unwrap_or("/").to_string(),
                        http_method: req.http_method.unwrap_or("POST").to_string(),
                        category: crate::abuse_reporting::AbuseCategory::WebHoneypot,
                        trapped_field: Some(field_name.clone()),
                        user_agent: req.user_agent.map(|s| s.to_string()),
                        evidence_notes: format!(
                            "Phylax autonomous honeypot trap tripped on hidden decoy field '{}'",
                            field_name
                        ),
                    };
                    let informant_cloned = informant.clone();
                    tokio::spawn(async move {
                        informant_cloned.process_incident(&dossier).await;
                    });
                }
            }
            return ShieldVerdict::Deny(DenialReason::HoneypotTrapped { field: field_name });
        }

        // 2. Layer 2: Subnet Check (~15ns)
        if self.enable_subnet && !req.client_ip.is_empty() {
            let subnet_verdict = self.subnet_guard.check_ip(req.client_ip);
            if let SubnetVerdict::Blocked { ip, matched_cidr } = subnet_verdict {
                self.adaptive_pow.record_infraction(
                    req.client_ip,
                    InfractionSeverity::Hostile,
                    req.now_ms,
                );
                return ShieldVerdict::Deny(DenialReason::SubnetBlocked {
                    ip,
                    cidr: matched_cidr,
                });
            }
        }

        // 3. Layer 3: Email Pattern Check (~30ns)
        let mut canonical_email = None;
        if let Some(raw_email) = req.email {
            match self.email_guard.inspect(raw_email) {
                EmailVerdict::Clean { canonical } => {
                    canonical_email = Some(canonical);
                }
                EmailVerdict::DisposableDomain { domain } => {
                    return ShieldVerdict::Deny(DenialReason::EmailPatternSuspicious {
                        reason: format!("Disposable throwaway domain '{}' is prohibited", domain),
                    });
                }
                EmailVerdict::ExcessiveDotScattering { raw_local } => {
                    return ShieldVerdict::Deny(DenialReason::EmailPatternSuspicious {
                        reason: format!("Suspicious bot dot-scattering pattern in '{}'", raw_local),
                    });
                }
                EmailVerdict::Malformed => {
                    return ShieldVerdict::Deny(DenialReason::EmailPatternSuspicious {
                        reason: "Malformed email address syntax".to_string(),
                    });
                }
            }
        }

        // 4. Layer 4: Form Submission Timing Check (~200ns)
        let mut elapsed_timing_ms = None;
        if require_timing {
            let Some(token) = req.timing_token else {
                return ShieldVerdict::Deny(DenialReason::MissingTimingToken);
            };

            match self.timing.verify_token(token, req.now_ms) {
                TimingVerdict::Valid { elapsed_ms } => {
                    elapsed_timing_ms = Some(elapsed_ms);
                }
                TimingVerdict::TooFast { elapsed_ms, min_ms } => {
                    return ShieldVerdict::Deny(DenialReason::SubmissionTooFast {
                        elapsed_ms,
                        min_ms,
                    });
                }
                TimingVerdict::Expired { .. } => {
                    return ShieldVerdict::Deny(DenialReason::SubmissionTimingExpired);
                }
                TimingVerdict::SignatureMismatch | TimingVerdict::Malformed => {
                    return ShieldVerdict::Deny(DenialReason::TimingSignatureInvalid);
                }
            }
        }

        // 5. Layer 5: Proof-of-Work Challenge (~500ns)
        if require_pow {
            let Some(token) = req.pow_challenge_token else {
                return ShieldVerdict::Deny(DenialReason::MissingPowChallenge);
            };
            let Some(nonce) = req.pow_nonce else {
                return ShieldVerdict::Deny(DenialReason::PowInvalidSolution);
            };

            match self.pow.verify_solution(token, nonce, req.now_ms) {
                PowVerdict::Verified { .. } => {}
                PowVerdict::InvalidSolution { .. } => {
                    return ShieldVerdict::Deny(DenialReason::PowInvalidSolution);
                }
                PowVerdict::Expired { .. } => {
                    return ShieldVerdict::Deny(DenialReason::PowExpired);
                }
                PowVerdict::Replayed => {
                    return ShieldVerdict::Deny(DenialReason::PowReplayed);
                }
                PowVerdict::SignatureMismatch | PowVerdict::Malformed => {
                    return ShieldVerdict::Deny(DenialReason::PowInvalidSolution);
                }
            }
        }

        ShieldVerdict::Allow {
            canonical_email,
            elapsed_timing_ms,
        }
    }
}

impl Default for ShieldPipeline {
    fn default() -> Self {
        Self::builder().build()
    }
}

/// Builder for sovereign Shield pipeline
pub struct ShieldPipelineBuilder {
    secret_key: Vec<u8>,
    decoy_fields: Option<Vec<String>>,
    timing_min_ms: u64,
    timing_max_ms: u64,
    pow_difficulty: u8,
    pow_expiration_ms: u64,
    max_email_dots: usize,
    enable_pow: bool,
    enable_timing: bool,
    enable_subnet: bool,
    tarpit_config: TarpitConfig,
    adaptive_pow_config: AdaptivePowConfig,
    quarantine_config: QuarantineConfig,
    decoy_uri_config: DecoyUriConfig,
    threat_harvester_config: crate::threat_harvester::ThreatHarvesterConfig,
    #[cfg(feature = "abuse-reporting")]
    informant: Option<Arc<crate::abuse_reporting::InformantEngine>>,
}

impl Default for ShieldPipelineBuilder {
    fn default() -> Self {
        Self {
            secret_key: b"rmt_default_shield_secret_key_2026".to_vec(),
            decoy_fields: None,
            timing_min_ms: 2000,
            timing_max_ms: 86_400_000,
            pow_difficulty: 16,
            pow_expiration_ms: 300_000,
            max_email_dots: 3,
            enable_pow: true,
            enable_timing: true,
            enable_subnet: true,
            tarpit_config: TarpitConfig::default(),
            adaptive_pow_config: AdaptivePowConfig::default(),
            quarantine_config: QuarantineConfig::default(),
            decoy_uri_config: DecoyUriConfig::default(),
            threat_harvester_config: crate::threat_harvester::ThreatHarvesterConfig::default(),
            #[cfg(feature = "abuse-reporting")]
            informant: None,
        }
    }
}

impl ShieldPipelineBuilder {
    pub fn secret_key<K: Into<Vec<u8>>>(mut self, key: K) -> Self {
        self.secret_key = key.into();
        self
    }

    pub fn with_honeypot_fields<I, S>(mut self, fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.decoy_fields = Some(fields.into_iter().map(Into::into).collect());
        self
    }

    pub fn with_timing(mut self, min_ms: u64, max_ms: u64) -> Self {
        self.timing_min_ms = min_ms;
        self.timing_max_ms = max_ms;
        self.enable_timing = true;
        self
    }

    pub fn with_pow(mut self, difficulty_bits: u8, expiration_ms: u64) -> Self {
        self.pow_difficulty = difficulty_bits;
        self.pow_expiration_ms = expiration_ms;
        self.enable_pow = true;
        self
    }

    pub fn with_tarpit(mut self, config: TarpitConfig) -> Self {
        self.tarpit_config = config;
        self
    }

    pub fn with_adaptive_pow(mut self, config: AdaptivePowConfig) -> Self {
        self.adaptive_pow_config = config;
        self
    }

    pub fn with_quarantine(mut self, config: QuarantineConfig) -> Self {
        self.quarantine_config = config;
        self
    }

    /// Configure the Decoy URI Reconnaissance Sentinel
    pub fn with_decoy_uris(mut self, config: DecoyUriConfig) -> Self {
        self.decoy_uri_config = config;
        self
    }

    pub fn enable_pow(mut self, enabled: bool) -> Self {
        self.enable_pow = enabled;
        self
    }

    pub fn enable_timing(mut self, enabled: bool) -> Self {
        self.enable_timing = enabled;
        self
    }

    pub fn enable_subnet_guard(mut self, enabled: bool) -> Self {
        self.enable_subnet = enabled;
        self
    }

    #[cfg(feature = "abuse-reporting")]
    /// Configure autonomous abuse reporting with the provided InformantConfig
    pub fn with_abuse_reporting(mut self, config: crate::abuse_reporting::InformantConfig) -> Self {
        self.informant = Some(Arc::new(
            crate::abuse_reporting::InformantEngine::with_http_transport(config),
        ));
        self
    }

    #[cfg(feature = "abuse-reporting")]
    /// Automatically discovers AbuseIPDB credentials and activates live automated reporting
    pub fn with_default_abuse_reporting(mut self) -> Self {
        let conf = crate::abuse_reporting::InformantConfig::from_env_or_default();
        if conf.enabled {
            self.informant = Some(Arc::new(
                crate::abuse_reporting::InformantEngine::with_http_transport(conf),
            ));
        }
        self
    }

    #[cfg(feature = "abuse-reporting")]
    /// Attach an existing InformantEngine instance
    pub fn with_informant_engine(
        mut self,
        informant: Arc<crate::abuse_reporting::InformantEngine>,
    ) -> Self {
        self.informant = Some(informant);
        self
    }

    pub fn with_threat_harvester(
        mut self,
        config: crate::threat_harvester::ThreatHarvesterConfig,
    ) -> Self {
        self.threat_harvester_config = config;
        self
    }

    pub fn build(self) -> ShieldPipeline {
        let honeypot = match self.decoy_fields {
            Some(fields) => HoneypotValidator::new(fields),
            None => HoneypotValidator::default(),
        };

        let timing = TimingGuard::new(&*self.secret_key, self.timing_min_ms, self.timing_max_ms);
        let pow = PowEngine::new(
            &*self.secret_key,
            self.pow_difficulty,
            self.pow_expiration_ms,
        );
        let email_guard = EmailPatternGuard::new(self.max_email_dots);
        let subnet_guard = SubnetGuard::default();
        let tarpit = TarpitGovernor::new(self.tarpit_config);
        let adaptive_pow = AdaptivePowEngine::new(self.adaptive_pow_config);
        let quarantine = AutonomousQuarantine::new(self.quarantine_config);
        let decoy_uri = DecoyUriSentinel::new(self.decoy_uri_config);
        let threat_harvester = crate::threat_harvester::ThreatHarvesterEngine::new(
            self.threat_harvester_config,
            decoy_uri.clone(),
        );

        ShieldPipeline {
            honeypot,
            timing,
            pow,
            email_guard,
            subnet_guard,
            tarpit,
            adaptive_pow,
            quarantine,
            decoy_uri,
            threat_harvester,
            enable_pow: self.enable_pow,
            enable_timing: self.enable_timing,
            enable_subnet: self.enable_subnet,
            #[cfg(feature = "abuse-reporting")]
            informant: self.informant,
        }
    }
}

pub type PhylaxPipeline = ShieldPipeline;
pub type PhylaxPipelineBuilder = ShieldPipelineBuilder;
pub type PhylaxRequest<'a> = ShieldRequest<'a>;
pub type PhylaxVerdict = ShieldVerdict;
pub type PhylaxClientContext = ShieldClientContext;
