//! # Abuse Category Definition & Standards Mapping
//! One-Job: Map internal threat infraction types to standardized AbuseIPDB category IDs.

use serde::{Deserialize, Serialize};

/// Standardized categories conforming to AbuseIPDB taxonomy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AbuseCategory {
    /// Trip invisible decoy form field / honeypot -> Category 10 (Web Spam), Category 21 (Web App Attack)
    WebHoneypot,
    /// Automated brute-force or dictionary credentials -> Category 18 (Brute-Force), Category 21 (Web App Attack)
    CredentialStuffing,
    /// Unauthorized headless crawler / scraper -> Category 19 (Bad Web Bot), Category 21 (Web App Attack)
    ScraperHarvesting,
    /// Vulnerability scanning / SQLi / fuzzing -> Category 15 (Hacking), Category 21 (Web App Attack)
    ExploitProbe,
    /// High-rate connection or request flood -> Category 4 (DDoS Attack)
    DdosVolumetric,
}

impl AbuseCategory {
    /// Returns the AbuseIPDB numeric category identifiers
    pub fn category_ids(&self) -> Vec<u8> {
        match self {
            Self::WebHoneypot => vec![10, 21],
            Self::CredentialStuffing => vec![18, 21],
            Self::ScraperHarvesting => vec![19, 21],
            Self::ExploitProbe => vec![15, 21],
            Self::DdosVolumetric => vec![4],
        }
    }

    /// Formats categories as a comma-separated string suitable for API parameters
    pub fn to_categories_param(&self) -> String {
        self.category_ids()
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Human-readable descriptor for incident dossiers
    pub fn name(&self) -> &'static str {
        match self {
            Self::WebHoneypot => "Web Honeypot Trap",
            Self::CredentialStuffing => "Credential Stuffing / Brute-Force",
            Self::ScraperHarvesting => "Automated Headless Scraper",
            Self::ExploitProbe => "Web Exploit & Vulnerability Probe",
            Self::DdosVolumetric => "Volumetric L7 Denial of Service",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_serialization_roundtrip() {
        let cat = AbuseCategory::WebHoneypot;
        let json = serde_json::to_string(&cat).unwrap();
        assert_eq!(json, "\"WebHoneypot\"");
        let deserialized: AbuseCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, cat);
    }

    #[test]
    fn test_all_categories_have_valid_ids_and_names() {
        let all = [
            AbuseCategory::WebHoneypot,
            AbuseCategory::CredentialStuffing,
            AbuseCategory::ScraperHarvesting,
            AbuseCategory::ExploitProbe,
            AbuseCategory::DdosVolumetric,
        ];
        for c in all {
            assert!(!c.category_ids().is_empty());
            assert!(!c.to_categories_param().is_empty());
            assert!(!c.name().is_empty());
        }
    }
}
