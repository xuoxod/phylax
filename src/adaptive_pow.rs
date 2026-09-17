//! # Adaptive Proof-of-Work Difficulty Ratcheting Engine
//!
//! Forces attackers to pay quadratic CPU costs for automated scanning and stuffing swarms.
//! Escalates SHA-256 micro-puzzle difficulty from baseline (12 bits, ~5ms) up to
//! severe (22 bits, ~5-10 seconds of 100% CPU lockup per attempt) based on client threat behavior.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// Severity of an observed threat infraction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfractionSeverity {
    /// Failed login, 404 scanning (minor)
    Suspicious,
    /// Rapid requests, invalid HMAC tokens, fast-forwarding (moderate)
    Hostile,
    /// Honeypot tripped, known Tor exit brute force, leaked credential spray (severe)
    Severe,
}

/// Configuration for adaptive PoW difficulty
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptivePowConfig {
    pub baseline_difficulty: u32,
    pub suspicious_difficulty: u32,
    pub hostile_difficulty: u32,
    pub severe_difficulty: u32,
    pub infraction_decay_ms: u64,
}

impl Default for AdaptivePowConfig {
    fn default() -> Self {
        Self {
            baseline_difficulty: 12,
            suspicious_difficulty: 15,
            hostile_difficulty: 18,
            severe_difficulty: 22,
            infraction_decay_ms: 15 * 60 * 1000, // 15 minutes
        }
    }
}

#[derive(Debug, Clone)]
struct IpInfractionRecord {
    score: u32,
    last_infraction_ms: u64,
}

/// Adaptive Proof-of-Work Engine
#[derive(Debug, Clone)]
pub struct AdaptivePowEngine {
    config: AdaptivePowConfig,
    records: Arc<RwLock<HashMap<String, IpInfractionRecord>>>,
}

impl AdaptivePowEngine {
    pub fn new(config: AdaptivePowConfig) -> Self {
        Self {
            config,
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Compute current difficulty for an IP taking decay into account
    pub fn get_difficulty(&self, ip: &str, now_ms: u64) -> u32 {
        let records = self.records.read();
        let record = match records.get(ip) {
            Some(r) => r,
            None => return self.config.baseline_difficulty,
        };

        let elapsed = now_ms.saturating_sub(record.last_infraction_ms);
        let decay_steps = (elapsed / self.config.infraction_decay_ms) as u32;

        let effective_score = record.score.saturating_sub(decay_steps);
        match effective_score {
            0 => self.config.baseline_difficulty,
            1 => self.config.suspicious_difficulty,
            2 => self.config.hostile_difficulty,
            _ => self.config.severe_difficulty,
        }
    }

    /// Record a threat infraction and ratchet difficulty accordingly
    pub fn record_infraction(&self, ip: &str, severity: InfractionSeverity, now_ms: u64) {
        let mut records = self.records.write();
        let record = records.entry(ip.to_string()).or_insert(IpInfractionRecord {
            score: 0,
            last_infraction_ms: now_ms,
        });

        // First apply decay from previous interval
        let elapsed = now_ms.saturating_sub(record.last_infraction_ms);
        let decay_steps = (elapsed / self.config.infraction_decay_ms) as u32;
        let decayed_score = record.score.saturating_sub(decay_steps);

        let target_score = match severity {
            InfractionSeverity::Suspicious => 1,
            InfractionSeverity::Hostile => 2,
            InfractionSeverity::Severe => 3,
        };

        record.score = decayed_score.max(target_score).min(3);
        record.last_infraction_ms = now_ms;
    }

    /// Reset an IP upon successful human verification
    pub fn clear_infractions(&self, ip: &str) {
        self.records.write().remove(ip);
    }
}
