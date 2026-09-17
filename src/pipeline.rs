//! # Radical OJP: Composable Fail-Fast Shield Pipeline
//! Single Job: Chain all isolated defense layers into a unified, zero-overhead pipeline.

use crate::adaptive_pow::{AdaptivePowConfig, AdaptivePowEngine, InfractionSeverity};
use crate::autonomous_quarantine::{AutonomousQuarantine, QuarantineConfig};
use crate::email_guard::{EmailPatternGuard, EmailVerdict};
use crate::honeypot::{HoneypotValidator, HoneypotVerdict};
use crate::pow::{PowEngine, PowVerdict};
use crate::subnet_guard::{SubnetGuard, SubnetVerdict};
use crate::tarpit::{TarpitConfig, TarpitGovernor};
use crate::timing::{TimingGuard, TimingVerdict};
use serde::{Deserialize, Serialize};

/// Request context submitted for Shield verification
#[derive(Debug, Clone, Default)]
pub struct ShieldRequest<'a> {
    pub client_ip: &'a str,
    pub submitted_fields: &'a [(String, String)],
    pub timing_token: Option<&'a str>,
    pub pow_challenge_token: Option<&'a str>,
    pub pow_nonce: Option<u64>,
    pub email: Option<&'a str>,
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
    enable_pow: bool,
    enable_timing: bool,
    enable_subnet: bool,
}

impl ShieldPipeline {
    /// Create a new pipeline builder
    pub fn builder() -> ShieldPipelineBuilder {
        ShieldPipelineBuilder::default()
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

        ShieldPipeline {
            honeypot,
            timing,
            pow,
            email_guard,
            subnet_guard,
            tarpit,
            adaptive_pow,
            quarantine,
            enable_pow: self.enable_pow,
            enable_timing: self.enable_timing,
            enable_subnet: self.enable_subnet,
        }
    }
}

pub type PhylaxPipeline = ShieldPipeline;
pub type PhylaxPipelineBuilder = ShieldPipelineBuilder;
pub type PhylaxRequest<'a> = ShieldRequest<'a>;
pub type PhylaxVerdict = ShieldVerdict;
pub type PhylaxClientContext = ShieldClientContext;
