//! # Radical OJP: Sensitive Perimeter Subnet Guard
//! Single Job: Fast Radix-tree subnet matching to block Tor exit nodes and datacenter automation ranges.

use crate::threat_intel::{DATACENTER_AND_SCANNER_CIDR_SEEDS, THREAT_INTEL_CIDR_SEEDS};
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

/// Granular classification of IP origin risk
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpRiskCategory {
    /// Standard clean residential or enterprise IP (standard sliding decay rate limits)
    Residential,
    /// Commercial cloud hosting / datacenter / mass-scanner subnet (Zero tolerance: instant quarantine on anomaly)
    Datacenter { matched_cidr: String },
    /// Anonymizing Tor exit node or bulletproof proxy
    TorExit { matched_cidr: String },
    /// Malformed IP address string
    Malformed,
}

impl IpRiskCategory {
    #[inline]
    pub fn is_high_risk(&self) -> bool {
        matches!(
            self,
            IpRiskCategory::Datacenter { .. } | IpRiskCategory::TorExit { .. }
        )
    }
}

/// Subnet Guard
#[derive(Debug, Clone)]
pub struct SubnetGuard {
    denied_subnets: Arc<RwLock<Vec<IpNet>>>,
    datacenter_subnets: Arc<RwLock<Vec<IpNet>>>,
}

impl Default for SubnetGuard {
    fn default() -> Self {
        let mut denied = Vec::new();
        for cidr_str in THREAT_INTEL_CIDR_SEEDS {
            if let Ok(net) = IpNet::from_str(cidr_str) {
                denied.push(net);
            }
        }

        let mut datacenter = Vec::new();
        for cidr_str in DATACENTER_AND_SCANNER_CIDR_SEEDS {
            if let Ok(net) = IpNet::from_str(cidr_str) {
                datacenter.push(net);
            }
        }

        Self {
            denied_subnets: Arc::new(RwLock::new(denied)),
            datacenter_subnets: Arc::new(RwLock::new(datacenter)),
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

    /// Add custom CIDR to the datacenter/scanner list
    pub fn add_datacenter_cidr(&self, cidr_str: &str) -> Result<(), String> {
        let net =
            IpNet::from_str(cidr_str).map_err(|e| format!("Invalid CIDR '{}': {}", cidr_str, e))?;
        self.datacenter_subnets.write().push(net);
        Ok(())
    }

    /// Evaluate client IP address for perimeter admission
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

    /// Granular risk classification for defense weighting
    pub fn evaluate_risk(&self, ip_str: &str) -> IpRiskCategory {
        let Ok(ip) = IpAddr::from_str(ip_str.trim()) else {
            return IpRiskCategory::Malformed;
        };

        // 1. Check Tor exit / bulletproof proxy subnets
        for net in self.denied_subnets.read().iter() {
            if net.contains(&ip) {
                return IpRiskCategory::TorExit {
                    matched_cidr: net.to_string(),
                };
            }
        }

        // 2. Check commercial cloud / datacenter / mass-scanner subnets
        for net in self.datacenter_subnets.read().iter() {
            if net.contains(&ip) {
                return IpRiskCategory::Datacenter {
                    matched_cidr: net.to_string(),
                };
            }
        }

        IpRiskCategory::Residential
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subnet_guard_allows_residential_ip() {
        let guard = SubnetGuard::default();
        // Common residential US IP
        assert_eq!(guard.check_ip("198.51.100.62"), SubnetVerdict::Allowed);
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

    #[test]
    fn test_subnet_guard_evaluates_datacenter_and_residential_risk() {
        let guard = SubnetGuard::default();

        // Residential US IP
        let res_risk = guard.evaluate_risk("198.51.100.42");
        assert_eq!(res_risk, IpRiskCategory::Residential);
        assert!(!res_risk.is_high_risk());

        // Censys scanner IP (162.142.125.4)
        let censys_risk = guard.evaluate_risk("162.142.125.4");
        assert!(matches!(censys_risk, IpRiskCategory::Datacenter { .. }));
        assert!(censys_risk.is_high_risk());

        // Tencent Cloud bot IP (43.130.102.7 - hit our canary trap overnight)
        let tencent_risk = guard.evaluate_risk("43.130.102.7");
        assert!(matches!(tencent_risk, IpRiskCategory::Datacenter { .. }));
        assert!(tencent_risk.is_high_risk());

        // Tor exit node (171.25.193.39)
        let tor_risk = guard.evaluate_risk("171.25.193.39");
        assert!(matches!(tor_risk, IpRiskCategory::TorExit { .. }));
        assert!(tor_risk.is_high_risk());
    }
}
