//! # Autonomous CIDR Quarantine Engine
//!
//! Automatically expands repeat offender IPs into their surrounding `/24` (IPv4)
//! or `/48` (IPv6) subnet boundaries, imposing an autonomous quarantine with configurable TTL.

use ipnet::IpNet;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

/// Configuration for autonomous quarantine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuarantineConfig {
    /// Number of severe infractions required to trigger autonomous CIDR quarantine
    pub infraction_threshold: u32,
    /// Duration of quarantine in milliseconds (e.g. 24 hours)
    pub quarantine_duration_ms: u64,
    /// Maximum number of active quarantined subnets to track
    pub max_tracked_subnets: usize,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            infraction_threshold: 3,
            quarantine_duration_ms: 24 * 60 * 60 * 1000, // 24 hours
            max_tracked_subnets: 5000,
        }
    }
}

/// Autonomous Quarantine Manager
#[derive(Debug, Clone)]
pub struct AutonomousQuarantine {
    config: QuarantineConfig,
    active_bans: Arc<RwLock<HashMap<IpNet, u64>>>,
    ip_infractions: Arc<RwLock<HashMap<String, (u32, u64)>>>,
}

impl AutonomousQuarantine {
    pub fn new(config: QuarantineConfig) -> Self {
        Self {
            config,
            active_bans: Arc::new(RwLock::new(HashMap::new())),
            ip_infractions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Derive the /24 (IPv4) or /48 (IPv6) subnet string for a given IP
    pub fn derive_quarantine_cidr(ip_str: &str) -> Option<String> {
        let addr = IpAddr::from_str(ip_str).ok()?;
        match addr {
            IpAddr::V4(v4) => {
                let net = ipnet::Ipv4Net::new(v4, 24).ok()?.trunc();
                Some(format!("{}/24", net.network()))
            }
            IpAddr::V6(v6) => {
                let net = ipnet::Ipv6Net::new(v6, 48).ok()?.trunc();
                Some(format!("{}/48", net.network()))
            }
        }
    }

    /// Record an infraction from an IP. If threshold is met, auto-quarantine its subnet.
    /// Returns true if autonomous quarantine was activated.
    pub fn record_and_check(&self, ip: &str, now_ms: u64) -> bool {
        let mut infractions = self.ip_infractions.write();
        let entry = infractions.entry(ip.to_string()).or_insert((0, now_ms));
        entry.0 += 1;
        entry.1 = now_ms;

        if entry.0 >= self.config.infraction_threshold {
            if let Some(cidr_str) = Self::derive_quarantine_cidr(ip) {
                if let Ok(net) = IpNet::from_str(&cidr_str) {
                    let mut bans = self.active_bans.write();
                    bans.insert(net, now_ms + self.config.quarantine_duration_ms);
                    return true;
                }
            }
        }

        false
    }

    /// Check if an IP falls within any currently active quarantined CIDR block
    pub fn is_quarantined(&self, ip: &str, now_ms: u64) -> bool {
        let addr = match IpAddr::from_str(ip) {
            Ok(a) => a,
            Err(_) => return false,
        };

        let bans = self.active_bans.read();
        for (net, expires_at) in bans.iter() {
            if *expires_at > now_ms && net.contains(&addr) {
                return true;
            }
        }

        false
    }

    /// Remove expired bans to keep memory lean
    pub fn purge_expired(&self, now_ms: u64) {
        let mut bans = self.active_bans.write();
        bans.retain(|_, expires_at| *expires_at > now_ms);
    }
}
