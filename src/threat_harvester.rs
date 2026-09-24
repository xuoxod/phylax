//! # Autonomous Zero-Day & Emerging Threat Harvester (Layer 13)
//!
//! One-Job: Autonomously correlate anomalous, unmapped 404 reconnaissance probes across
//! distinct network subnets, detecting coordinated zero-day vulnerability campaigns in real-time
//! and elevating confirmed threat paths into the active `DecoyUriSentinel` trap catalog without human intervention.
//!
//! ### Sybil & Cache-Pollution Defense Invariant:
//! Single-IP attackers or scanners attempting to flood the engine with millions of randomized URIs
//! cannot elevate paths or exhaust memory:
//! 1. Multi-Subnet Correlation: A candidate path requires confirmation from at least `promotion_subnet_threshold`
//!    distinct `/24` IPv4 or `/48` IPv6 subnets within `window_duration_ms`.
//! 2. Subnet Quota Caps: A single subnet cannot contribute more than `max_paths_per_subnet` candidate paths
//!    in a given window, thwarting crawler dictionary-fuzzing cache-pollution attacks.
//! 3. Bounded Memory Eviction: Candidate paths are strictly bounded by `max_tracked_candidates` with deterministic
//!    LRU and time-window pruning.

use crate::decoy_uri::{DecoyCategory, DecoyUriSentinel};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

/// Canonical network subnet key used for mathematical multi-subnet correlation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SubnetKey {
    /// IPv4 /24 subnet prefix ([oct1, oct2, oct3])
    V4([u8; 3]),
    /// IPv6 /48 subnet prefix ([seg1, seg2, seg3])
    V6([u16; 3]),
}

impl SubnetKey {
    /// Extracts canonical subnet key from an `IpAddr`
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                SubnetKey::V4([o[0], o[1], o[2]])
            }
            IpAddr::V6(v6) => {
                // If it's an IPv4-mapped IPv6 address (::ffff:192.0.2.1), extract IPv4 /24
                if let Some(v4) = v6.to_ipv4_mapped() {
                    let o = v4.octets();
                    SubnetKey::V4([o[0], o[1], o[2]])
                } else {
                    let s = v6.segments();
                    SubnetKey::V6([s[0], s[1], s[2]])
                }
            }
        }
    }

    /// Parses string IP and extracts canonical subnet key
    pub fn from_ip_str(ip_str: &str) -> Option<Self> {
        let trimmed = ip_str.trim();
        // Remove port if present (e.g., "192.168.1.1:8080" or "[2001:db8::1]:8080")
        let host = if trimmed.starts_with('[') {
            if let Some(end) = trimmed.find(']') {
                &trimmed[1..end]
            } else {
                trimmed
            }
        } else if let Some(colon) = trimmed.find(':') {
            if trimmed.matches(':').count() == 1 {
                &trimmed[..colon]
            } else {
                trimmed
            }
        } else {
            trimmed
        };

        host.parse::<IpAddr>().ok().map(Self::from_ip)
    }

    /// Formats as CIDR notation
    pub fn to_cidr_string(&self) -> String {
        match self {
            SubnetKey::V4(oct) => format!("{}.{}.{}.0/24", oct[0], oct[1], oct[2]),
            SubnetKey::V6(seg) => format!("{:x}:{:x}:{:x}::/48", seg[0], seg[1], seg[2]),
        }
    }
}

/// Configuration for Autonomous Zero-Day Threat Harvester
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatHarvesterConfig {
    /// Whether autonomous threat harvesting is active (default: true)
    pub enabled: bool,
    /// Number of distinct /24 or /48 subnets required to promote an anomalous path (default: 3)
    pub promotion_subnet_threshold: usize,
    /// Sliding time window in milliseconds during which subnets must be observed (default: 3,600,000 ms = 1 hr)
    pub window_duration_ms: u64,
    /// Maximum distinct anomalous paths tracked simultaneously to prevent memory exhaustion (default: 10,000)
    pub max_tracked_candidates: usize,
    /// Maximum distinct candidate paths a single subnet may introduce in a window (anti-fuzzing quota, default: 25)
    pub max_paths_per_subnet: usize,
}

impl Default for ThreatHarvesterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            promotion_subnet_threshold: 3,
            window_duration_ms: 3_600_000, // 1 hour
            max_tracked_candidates: 10_000,
            max_paths_per_subnet: 25,
        }
    }
}

/// In-memory forensic record for an anomalous candidate path under observation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatePathRecord {
    pub path: String,
    pub category: DecoyCategory,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub hit_count: u64,
    pub participating_subnets: HashSet<SubnetKey>,
    pub promoted: bool,
}

/// Verdict returned when an anomalous path reaches threshold and is elevated to active decoy traps
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionVerdict {
    pub path: String,
    pub category: DecoyCategory,
    pub distinct_subnets: usize,
    pub total_hits: u64,
    pub first_seen_ms: u64,
    pub promoted_at_ms: u64,
}

/// Autonomous Threat Harvester Engine
#[derive(Debug, Clone)]
pub struct ThreatHarvesterEngine {
    config: ThreatHarvesterConfig,
    sentinel: DecoyUriSentinel,
    candidates: Arc<RwLock<HashMap<String, CandidatePathRecord>>>,
    subnet_path_counts: Arc<RwLock<HashMap<SubnetKey, usize>>>,
}

impl ThreatHarvesterEngine {
    /// Construct a new threat harvester bound to an existing `DecoyUriSentinel`
    pub fn new(config: ThreatHarvesterConfig, sentinel: DecoyUriSentinel) -> Self {
        Self {
            config,
            sentinel,
            candidates: Arc::new(RwLock::new(HashMap::new())),
            subnet_path_counts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Construct a new threat harvester with a default `DecoyUriSentinel`
    pub fn with_default_sentinel(config: ThreatHarvesterConfig) -> Self {
        Self::new(config, DecoyUriSentinel::default())
    }

    /// Reference to the underlying DecoyUriSentinel
    pub fn sentinel(&self) -> &DecoyUriSentinel {
        &self.sentinel
    }

    /// Reference to configuration
    pub fn config(&self) -> &ThreatHarvesterConfig {
        &self.config
    }

    /// Number of actively tracked candidate paths
    pub fn candidate_count(&self) -> usize {
        self.candidates.read().len()
    }

    /// Check if a path is currently being tracked as a candidate
    pub fn is_candidate(&self, raw_path: &str) -> bool {
        let normalized = DecoyUriSentinel::normalize_path(raw_path);
        self.candidates.read().contains_key(&normalized)
    }

    /// Retrieve forensic record for a tracked candidate path
    pub fn get_candidate(&self, raw_path: &str) -> Option<CandidatePathRecord> {
        let normalized = DecoyUriSentinel::normalize_path(raw_path);
        self.candidates.read().get(&normalized).cloned()
    }

    /// Ingest an unmapped or anomalous URI probe from an incoming request
    ///
    /// If the path has reached the multi-subnet correlation threshold within the sliding window,
    /// it is autonomously promoted into `DecoyUriSentinel` and `Some(PromotionVerdict)` is returned.
    pub fn ingest_anomalous_uri(
        &self,
        raw_path: &str,
        client_ip: IpAddr,
        now_ms: u64,
    ) -> Option<PromotionVerdict> {
        if !self.config.enabled {
            return None;
        }

        let normalized = DecoyUriSentinel::normalize_path(raw_path);

        // Ignore root or empty paths
        if normalized == "/" || normalized.is_empty() {
            return None;
        }

        // If path is already a registered trap in DecoyUriSentinel, skip candidate tracking
        if self.sentinel.contains_trap(&normalized) {
            return None;
        }

        let subnet = SubnetKey::from_ip(client_ip);
        let mut candidates = self.candidates.write();
        let mut subnet_counts = self.subnet_path_counts.write();

        if let Some(record) = candidates.get_mut(&normalized) {
            // Check if sliding window expired for this candidate
            if now_ms.saturating_sub(record.first_seen_ms) > self.config.window_duration_ms {
                // Reset window and subnets for this candidate
                record.first_seen_ms = now_ms;
                record.last_seen_ms = now_ms;
                record.hit_count = 1;
                record.participating_subnets.clear();
                record.participating_subnets.insert(subnet);
                return None;
            }

            record.hit_count = record.hit_count.saturating_add(1);
            record.last_seen_ms = now_ms;
            record.participating_subnets.insert(subnet);

            // Check for promotion eligibility
            if !record.promoted
                && record.participating_subnets.len() >= self.config.promotion_subnet_threshold
            {
                record.promoted = true;
                let category = record.category;
                let distinct_subnets = record.participating_subnets.len();
                let total_hits = record.hit_count;
                let first_seen_ms = record.first_seen_ms;

                // Elevate into active decoy traps in sub-microsecond time
                self.sentinel.add_exact_trap_with_category(&normalized, category);

                return Some(PromotionVerdict {
                    path: normalized,
                    category,
                    distinct_subnets,
                    total_hits,
                    first_seen_ms,
                    promoted_at_ms: now_ms,
                });
            }

            None
        } else {
            // New candidate path: verify subnet quota (anti-fuzzing / anti-cache-pollution)
            let current_subnet_paths = subnet_counts.get(&subnet).copied().unwrap_or(0);
            if current_subnet_paths >= self.config.max_paths_per_subnet {
                // Subnet quota exceeded; reject candidate creation to preserve memory
                return None;
            }

            // Verify capacity limits; prune expired entries if at limit
            if candidates.len() >= self.config.max_tracked_candidates {
                Self::prune_internal(
                    &mut candidates,
                    &mut subnet_counts,
                    now_ms,
                    self.config.window_duration_ms,
                );

                // If still at capacity, evict the candidate with the fewest subnets and oldest last_seen_ms
                if candidates.len() >= self.config.max_tracked_candidates {
                    if let Some(evict_key) = candidates
                        .iter()
                        .min_by_key(|(_, rec)| (rec.participating_subnets.len(), rec.last_seen_ms))
                        .map(|(k, _)| k.clone())
                    {
                        candidates.remove(&evict_key);
                    }
                }
            }

            let entry = subnet_counts.entry(subnet).or_insert(0);
            *entry = entry.saturating_add(1);

            let category = Self::categorize_candidate_heuristic(&normalized);
            let mut subnets = HashSet::new();
            subnets.insert(subnet);

            let qualifies_immediately = self.config.promotion_subnet_threshold <= 1;

            let record = CandidatePathRecord {
                path: normalized.clone(),
                category,
                first_seen_ms: now_ms,
                last_seen_ms: now_ms,
                hit_count: 1,
                participating_subnets: subnets,
                promoted: qualifies_immediately,
            };

            candidates.insert(normalized.clone(), record);

            if qualifies_immediately {
                self.sentinel.add_exact_trap_with_category(&normalized, category);
                Some(PromotionVerdict {
                    path: normalized,
                    category,
                    distinct_subnets: 1,
                    total_hits: 1,
                    first_seen_ms: now_ms,
                    promoted_at_ms: now_ms,
                })
            } else {
                None
            }
        }
    }

    /// Convenience wrapper accepting an IP string
    pub fn ingest_anomalous_uri_str(
        &self,
        raw_path: &str,
        client_ip_str: &str,
        now_ms: u64,
    ) -> Option<PromotionVerdict> {
        let ip = client_ip_str.trim().parse::<IpAddr>().ok()?;
        self.ingest_anomalous_uri(raw_path, ip, now_ms)
    }

    pub fn ingest_cve_entry(&self, cve_id: &str, paths: &[&str], category: DecoyCategory) -> usize {
        let mut count = 0;
        for path in paths {
            let normalized = DecoyUriSentinel::normalize_path(path);
            if !normalized.is_empty() && normalized != "/" {
                self.sentinel.add_exact_trap_with_category(&normalized, category);
                count += 1;
            }
        }
        let _ = (cve_id, category); // Reserved for forensic audit logging
        count
    }

    /// Bulk loader for CISA Known Exploited Vulnerabilities (KEV) or MITRE CVE catalogs
    pub fn ingest_bulk_cve_catalog(&self, catalog: &[(&str, DecoyCategory)]) -> usize {
        let mut activated = 0;
        for (path, category) in catalog {
            let normalized = DecoyUriSentinel::normalize_path(path);
            if !normalized.is_empty() && normalized != "/" {
                self.sentinel.add_exact_trap_with_category(&normalized, *category);
                activated += 1;
            }
        }
        activated
    }

    /// Synchronously prune expired candidate records and reset decayed subnet quotas
    pub fn prune_expired(&self, now_ms: u64) -> usize {
        let mut candidates = self.candidates.write();
        let mut subnet_counts = self.subnet_path_counts.write();
        Self::prune_internal(&mut candidates, &mut subnet_counts, now_ms, self.config.window_duration_ms)
    }

    fn prune_internal(
        candidates: &mut HashMap<String, CandidatePathRecord>,
        subnet_counts: &mut HashMap<SubnetKey, usize>,
        now_ms: u64,
        window_duration_ms: u64,
    ) -> usize {
        let initial_len = candidates.len();
        candidates.retain(|_, rec| {
            // Keep if within active window and not already promoted
            !rec.promoted && now_ms.saturating_sub(rec.last_seen_ms) <= window_duration_ms
        });
        let pruned = initial_len.saturating_sub(candidates.len());

        // Recompute active subnet quotas
        subnet_counts.clear();
        for rec in candidates.values() {
            for subnet in &rec.participating_subnets {
                let entry = subnet_counts.entry(*subnet).or_insert(0);
                *entry = entry.saturating_add(1);
            }
        }

        pruned
    }

    /// Heuristic classifier determining threat category for newly observed probe paths
    pub fn categorize_candidate_heuristic(path: &str) -> DecoyCategory {
        let lower = path.to_ascii_lowercase();

        if lower.contains("env")
            || lower.contains("secret")
            || lower.contains("credential")
            || lower.contains("token")
            || lower.contains("vault")
            || lower.contains("key")
            || lower.contains("config")
        {
            DecoyCategory::EnvironmentSecret
        } else if lower.contains("admin")
            || lower.contains("login")
            || lower.contains("wp-")
            || lower.contains("cms")
            || lower.contains("actuator")
            || lower.contains("console")
            || lower.contains("php")
        {
            DecoyCategory::AdminCmsProbe
        } else if lower.contains("git")
            || lower.contains("svn")
            || lower.contains("hg")
            || lower.contains("repo")
        {
            DecoyCategory::VersionControl
        } else if lower.contains("k8s")
            || lower.contains("kube")
            || lower.contains("docker")
            || lower.contains("aws")
            || lower.contains("azure")
            || lower.contains("terraform")
        {
            DecoyCategory::CloudInfrastructure
        } else if lower.contains("db")
            || lower.contains("sql")
            || lower.contains("data")
            || lower.contains("backup")
            || lower.contains("dump")
            || lower.contains("tar")
            || lower.contains("zip")
        {
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
    fn test_subnet_key_extraction_ipv4_and_ipv6() {
        let ip1: IpAddr = "192.168.1.55".parse().unwrap();
        let ip2: IpAddr = "192.168.1.99".parse().unwrap();
        let ip3: IpAddr = "192.168.2.10".parse().unwrap();

        let s1 = SubnetKey::from_ip(ip1);
        let s2 = SubnetKey::from_ip(ip2);
        let s3 = SubnetKey::from_ip(ip3);

        assert_eq!(s1, s2, "Same /24 must yield identical SubnetKey");
        assert_ne!(s1, s3, "Different /24 must yield different SubnetKey");
        assert_eq!(s1.to_cidr_string(), "192.168.1.0/24");

        let v6_1: IpAddr = "2001:db8:abcd:0012::1".parse().unwrap();
        let v6_2: IpAddr = "2001:db8:abcd:ffff::99".parse().unwrap();
        let v6_3: IpAddr = "2001:db8:eeee:0001::1".parse().unwrap();

        let sv6_1 = SubnetKey::from_ip(v6_1);
        let sv6_2 = SubnetKey::from_ip(v6_2);
        let sv6_3 = SubnetKey::from_ip(v6_3);

        assert_eq!(sv6_1, sv6_2, "Same /48 must yield identical SubnetKey");
        assert_ne!(sv6_1, sv6_3, "Different /48 must yield different SubnetKey");
        assert_eq!(sv6_1.to_cidr_string(), "2001:db8:abcd::/48");
    }

    #[test]
    fn test_ipv4_mapped_ipv6_canonicalization() {
        let v6_mapped: IpAddr = "::ffff:198.51.100.42".parse().unwrap();
        let subnet = SubnetKey::from_ip(v6_mapped);
        assert_eq!(subnet, SubnetKey::V4([198, 51, 100]));
        assert_eq!(subnet.to_cidr_string(), "198.51.100.0/24");
    }

    #[test]
    fn test_single_ip_fuzzing_cannot_promote_path() {
        let sentinel = DecoyUriSentinel::default();
        let config = ThreatHarvesterConfig {
            promotion_subnet_threshold: 3,
            ..Default::default()
        };
        let harvester = ThreatHarvesterEngine::new(config, sentinel.clone());
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let now = 100_000;

        // Attacker sends 100 requests to a zero-day probe path from the same IP
        for _ in 0..100 {
            let verdict = harvester.ingest_anomalous_uri("/vulnerable/exploit.php", ip, now);
            assert!(verdict.is_none(), "Single IP must NEVER promote a path");
        }

        assert!(harvester.is_candidate("/vulnerable/exploit.php"));
        assert!(!sentinel.contains_trap("/vulnerable/exploit.php"));
        let record = harvester.get_candidate("/vulnerable/exploit.php").unwrap();
        assert_eq!(record.hit_count, 100);
        assert_eq!(record.participating_subnets.len(), 1);
    }

    #[test]
    fn test_multi_subnet_promotion_elevates_path_to_active_sentinel_trap() {
        let sentinel = DecoyUriSentinel::default();
        let config = ThreatHarvesterConfig {
            promotion_subnet_threshold: 3,
            ..Default::default()
        };
        let harvester = ThreatHarvesterEngine::new(config, sentinel.clone());
        let now = 200_000;

        let ip_subnet_1: IpAddr = "198.51.100.1".parse().unwrap();
        let ip_subnet_2: IpAddr = "192.0.2.77".parse().unwrap();
        let ip_subnet_3: IpAddr = "203.0.113.88".parse().unwrap();

        let zero_day_path = "/api/v1/zero_day_endpoint";
        assert!(!sentinel.contains_trap(zero_day_path));

        // Request 1 from Subnet 1
        assert!(harvester.ingest_anomalous_uri(zero_day_path, ip_subnet_1, now).is_none());
        assert!(!sentinel.contains_trap(zero_day_path));

        // Request 2 from Subnet 2
        assert!(harvester.ingest_anomalous_uri(zero_day_path, ip_subnet_2, now + 10).is_none());
        assert!(!sentinel.contains_trap(zero_day_path));

        // Request 3 from Subnet 3 -> Correlated across 3 distinct subnets!
        let verdict = harvester
            .ingest_anomalous_uri(zero_day_path, ip_subnet_3, now + 20)
            .expect("Path must be promoted when 3 distinct subnets hit it");

        assert_eq!(verdict.path, zero_day_path);
        assert_eq!(verdict.distinct_subnets, 3);
        assert_eq!(verdict.total_hits, 3);

        // Verification: Path is now an active trap in DecoyUriSentinel!
        assert!(sentinel.contains_trap(zero_day_path));

        // A new request hitting this path is now trapped in sub-microsecond time!
        let eval = sentinel.evaluate(zero_day_path);
        match eval {
            crate::decoy_uri::DecoyUriVerdict::Trapped { matched_path, .. } => {
                assert_eq!(matched_path, zero_day_path);
            }
            _ => panic!("Elevated trap must immediately catch subsequent probes"),
        }
    }

    #[test]
    fn test_bulk_cve_catalog_ingestion() {
        let sentinel = DecoyUriSentinel::default();
        let harvester = ThreatHarvesterEngine::new(ThreatHarvesterConfig::default(), sentinel.clone());

        let cve_catalog = [
            ("/ssl-vpn/hipreport.esp", DecoyCategory::Custom), // CVE-2024-3400
            ("/api/v1/totp/user-backup-code", DecoyCategory::AdminCmsProbe), // CVE-2023-46805
        ];

        let count = harvester.ingest_bulk_cve_catalog(&cve_catalog);
        assert_eq!(count, 2);

        assert!(sentinel.contains_trap("/ssl-vpn/hipreport.esp"));
        assert!(sentinel.contains_trap("/api/v1/totp/user-backup-code"));
    }

    #[test]
    fn test_subnet_quota_anti_fuzzing_defense() {
        let sentinel = DecoyUriSentinel::default();
        let config = ThreatHarvesterConfig {
            max_paths_per_subnet: 3,
            ..Default::default()
        };
        let harvester = ThreatHarvesterEngine::new(config, sentinel);
        let ip: IpAddr = "198.51.100.9".parse().unwrap();
        let now = 300_000;

        // Subnet introduces 3 candidate paths (at quota)
        assert!(harvester.ingest_anomalous_uri("/path1", ip, now).is_none());
        assert!(harvester.ingest_anomalous_uri("/path2", ip, now).is_none());
        assert!(harvester.ingest_anomalous_uri("/path3", ip, now).is_none());
        assert_eq!(harvester.candidate_count(), 3);

        // 4th distinct path from the SAME subnet is quota-capped and rejected
        assert!(harvester.ingest_anomalous_uri("/path4_overflow", ip, now).is_none());
        assert_eq!(harvester.candidate_count(), 3, "Subnet quota must block memory pollution");
        assert!(!harvester.is_candidate("/path4_overflow"));
    }
}
