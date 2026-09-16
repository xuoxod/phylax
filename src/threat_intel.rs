//! # Threat Intelligence Seed Data & Signatures
//! Real-world captured signatures from Tor exit nodes, datacenter scrapers, and bot heuristics.

use std::collections::HashSet;

/// Default Honeypot Decoy Field Names
pub const DEFAULT_HONEYPOT_FIELDS: &[&str] = &[
    "website_url",
    "company_fax",
    "secondary_email",
    "hp_auth_token",
];

/// Known Tor Exit Node and Datacenter Scraper CIDRs captured in the wild
pub const THREAT_INTEL_CIDR_SEEDS: &[&str] = &[
    // Swedish DFRI Tor Exit Nodes (Captured from live attack 2026-09-15)
    "171.25.193.0/24",
    // European Tor Exit Relays (Captured 2026-09-15)
    "185.220.101.0/24",
    "185.220.100.0/24",
    "185.129.61.0/24",
    "192.42.116.0/24",
    // Julian Achter Bulletproof Scraper Range (Captured 2026-09-15)
    "185.132.53.0/24",
    // OVH Datacenter Automation Scanners (Captured 2026-09-15)
    "149.56.44.0/24",
    // Known Anonymous Proxy & Crawler Ranges (Captured 2026-09-15)
    "45.84.107.0/24",
    "176.65.149.0/24",
    // KeFF Networks Ltd Bulletproof Scraper Subnet (Captured live attack 2026-09-16)
    "193.189.100.0/24",
    // Gigahost AS Norwegian Tor Exit Node Subnet (Captured live attack 2026-09-16)
    "194.32.107.0/24",
];

/// Known Disposable / Throwaway Email Domains
pub const DISPOSABLE_EMAIL_DOMAINS: &[&str] = &[
    "mailinator.com",
    "10minutemail.com",
    "tempmail.com",
    "guerrillamail.com",
    "trashmail.com",
    "throwawaymail.com",
    "yopmail.com",
    "sharklasers.com",
    "dispostable.com",
    "getairmail.com",
    "temp-mail.org",
    "fakeinbox.com",
    "crazymailing.com",
    "mytemp.email",
];

/// Checks whether a given domain is a known disposable throwaway email provider
pub fn is_disposable_email_domain(domain: &str) -> bool {
    let lower = domain.trim().to_lowercase();
    DISPOSABLE_EMAIL_DOMAINS.contains(&lower.as_str())
}

/// Returns a seed set of known threat CIDRs
pub fn default_threat_cidrs() -> HashSet<String> {
    THREAT_INTEL_CIDR_SEEDS
        .iter()
        .map(|s| s.to_string())
        .collect()
}
