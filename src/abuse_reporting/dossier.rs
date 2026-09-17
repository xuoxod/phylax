//! # Forensic Incident Dossier & X-ARF Formatter
//! One-Job: Immutable incident data structure and RFC/AbuseIPDB compliant evidence serialization.

use crate::abuse_reporting::category::AbuseCategory;
use serde::{Deserialize, Serialize};

/// Immutable container holding forensic evidence for an abusive incident
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicDossier {
    pub client_ip: String,
    pub timestamp_ms: u64,
    pub target_uri: String,
    pub http_method: String,
    pub category: AbuseCategory,
    pub trapped_field: Option<String>,
    pub user_agent: Option<String>,
    pub evidence_notes: String,
}

/// Stateless formatter generating standardized comments and X-ARF structures
pub struct DossierFormatter;

impl DossierFormatter {
    /// Renders an evidence comment strictly capped at 1024 characters (AbuseIPDB requirement)
    pub fn render_incident_comment(dossier: &ForensicDossier) -> String {
        let mut comment = format!(
            "[Phylax Security Report] Type: {}\nSource IP: {}\nEndpoint: {} {}\nTimestamp: {} ms\nNotes: {}\n",
            dossier.category.name(),
            dossier.client_ip,
            dossier.http_method,
            dossier.target_uri,
            dossier.timestamp_ms,
            dossier.evidence_notes
        );

        if let Some(ref field) = dossier.trapped_field {
            comment.push_str(&format!("Honeypot Decoy Field Tripped: '{}'\n", field));
        }

        if let Some(ref ua) = dossier.user_agent {
            comment.push_str(&format!("User-Agent: {}\n", ua));
        }

        comment.push_str("Forensic validation: Automated probe detected by deterministic application defense.");

        // Guard against AbuseIPDB 1024 character hard ceiling
        if comment.len() > 1024 {
            comment.truncate(1021);
            comment.push_str("...");
        }

        comment
    }

    /// Renders standard JSON format (compatible with X-ARF / Network Abuse Reporting 2.0)
    pub fn render_xarf_json(dossier: &ForensicDossier) -> serde_json::Value {
        serde_json::json!({
            "version": "2.0.0",
            "report_type": "web_abuse",
            "source_ip": dossier.client_ip,
            "timestamp_ms": dossier.timestamp_ms,
            "target_uri": dossier.target_uri,
            "http_method": dossier.http_method,
            "category": dossier.category.name(),
            "category_ids": dossier.category.category_ids(),
            "trapped_field": dossier.trapped_field,
            "user_agent": dossier.user_agent,
            "evidence": dossier.evidence_notes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dossier_truncates_oversized_evidence_notes_to_1024_chars() {
        let massive_notes = "A".repeat(2000);
        let dossier = ForensicDossier {
            client_ip: "10.0.0.1".to_string(),
            timestamp_ms: 123456789,
            target_uri: "/api/test".to_string(),
            http_method: "GET".to_string(),
            category: AbuseCategory::ExploitProbe,
            trapped_field: None,
            user_agent: None,
            evidence_notes: massive_notes,
        };

        let comment = DossierFormatter::render_incident_comment(&dossier);
        assert!(comment.len() <= 1024);
        assert!(comment.ends_with("..."));
    }

    #[test]
    fn test_xarf_json_contains_proper_schema() {
        let dossier = ForensicDossier {
            client_ip: "10.0.0.1".to_string(),
            timestamp_ms: 123456789,
            target_uri: "/api/test".to_string(),
            http_method: "POST".to_string(),
            category: AbuseCategory::WebHoneypot,
            trapped_field: Some("hp_field".to_string()),
            user_agent: Some("TestAgent/1.0".to_string()),
            evidence_notes: "trip".to_string(),
        };

        let xarf = DossierFormatter::render_xarf_json(&dossier);
        assert_eq!(xarf["version"], "2.0.0");
        assert_eq!(xarf["report_type"], "web_abuse");
        assert_eq!(xarf["category_ids"][0], 10);
        assert_eq!(xarf["category_ids"][1], 21);
    }
}
