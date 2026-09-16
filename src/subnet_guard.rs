//! # Radical OJP: Sensitive Perimeter Subnet Guard
//! Single Job: Fast Radix-tree subnet matching to block Tor exit nodes and datacenter automation ranges.

use crate::threat_intel::THREAT_INTEL_CIDR_SEEDS;
use ipnet::IpNet;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

/// Verdict resulting from IP subnet check
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SubnetVerdict {
    /// IP is clean and permitted for registration/sensitive operations
    Allowed,
    /// IP belongs to a denied Tor exit node or datacenter scraper range
    Blocked { ip: String, matched_cidr: String },
    /// Malformed IP address syntax
    MalformedIp,
}

impl SubnetVerdict {
    #[inline]
    pub fn is_allowed(&self) -> bool {
        matches!(self, SubnetVerdict::Allowed)
    }
}

/// Subnet Guard
#[derive(Debug, Clone)]
pub struct SubnetGuard {
    denied_subnets: Arc<RwLock<Vec<IpNet>>>,
}

impl Default for SubnetGuard {
    fn default() -> Self {
        let mut subnets = Vec::new();
        for cidr_str in THREAT_INTEL_CIDR_SEEDS {
            if let Ok(net) = IpNet::from_str(cidr_str) {
                subnets.push(net);
            }
        }
        Self {
            denied_subnets: Arc::new(RwLock::new(subnets)),
        }
    }
}

impl SubnetGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add custom CIDR to the denied list
    pub fn add_denied_cidr(&self, cidr_str: &str) -> Result<(), String> {
        let net =
            IpNet::from_str(cidr_str).map_err(|e| format!("Invalid CIDR '{}': {}", cidr_str, e))?;
        self.denied_subnets.write().push(net);
        Ok(())
    }

    /// Evaluate client IP address
    pub fn check_ip(&self, ip_str: &str) -> SubnetVerdict {
        let Ok(ip) = IpAddr::from_str(ip_str.trim()) else {
            return SubnetVerdict::MalformedIp;
        };

        let denied = self.denied_subnets.read();
        for net in denied.iter() {
            if net.contains(&ip) {
                return SubnetVerdict::Blocked {
                    ip: ip_str.to_string(),
                    matched_cidr: net.to_string(),
                };
            }
        }

        SubnetVerdict::Allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subnet_guard_allows_residential_ip() {
        let guard = SubnetGuard::default();
        // Common residential US IP
        assert_eq!(guard.check_ip("74.7.241.62"), SubnetVerdict::Allowed);
        // Loopback
        assert_eq!(guard.check_ip("127.0.0.1"), SubnetVerdict::Allowed);
    }

    #[test]
    fn test_subnet_guard_blocks_swedish_tor_exit() {
        let guard = SubnetGuard::default();
        // Real IP that hit us today: 171.25.193.39 (DFRI Sweden)
        let verdict = guard.check_ip("171.25.193.39");
        assert!(matches!(verdict, SubnetVerdict::Blocked { .. }));
    }

    #[test]
    fn test_subnet_guard_blocks_european_tor_node() {
        let guard = SubnetGuard::default();
        // Real IP from logs: 185.220.101.26
        let verdict = guard.check_ip("185.220.101.26");
        assert!(matches!(verdict, SubnetVerdict::Blocked { .. }));
    }
}
