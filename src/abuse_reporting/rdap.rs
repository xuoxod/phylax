//! # RDAP ISP & Upstream Abuse Contact Resolver
//! One-Job: Parse ICANN / RIR RDAP payloads to identify upstream network provider and abuse email.

use serde::{Deserialize, Serialize};

/// Contact metadata extracted from an RDAP query
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RdapContact {
    pub org_name: Option<String>,
    pub country: Option<String>,
    pub abuse_email: Option<String>,
}

pub struct RdapParser;

impl RdapParser {
    /// Pure function extracting organization name, country, and abuse contact email from RDAP JSON
    pub fn parse_rdap_json(json: &serde_json::Value) -> RdapContact {
        let mut contact = RdapContact::default();

        if let Some(name) = json.get("name").and_then(|v| v.as_str()) {
            contact.org_name = Some(name.to_string());
        }

        if let Some(country) = json.get("country").and_then(|v| v.as_str()) {
            contact.country = Some(country.to_string());
        }

        // Search entities array for abuse role
        if let Some(entities) = json.get("entities").and_then(|v| v.as_array()) {
            contact.abuse_email = Self::find_abuse_email_in_entities(entities);
        }

        contact
    }

    fn find_abuse_email_in_entities(entities: &[serde_json::Value]) -> Option<String> {
        for entity in entities {
            let is_abuse_role = entity
                .get("roles")
                .and_then(|v| v.as_array())
                .map(|roles| roles.iter().any(|r| r.as_str() == Some("abuse")))
                .unwrap_or(false);

            if is_abuse_role {
                if let Some(email) = Self::extract_email_from_vcard(entity) {
                    return Some(email);
                }
            }

            // Check nested entities (e.g., technical or parent entity enclosing abuse department)
            if let Some(nested) = entity.get("entities").and_then(|v| v.as_array()) {
                if let Some(email) = Self::find_abuse_email_in_entities(nested) {
                    return Some(email);
                }
            }
        }

        // Fallback: If no entity explicitly had role "abuse", check if any entity has an email containing "abuse"
        for entity in entities {
            if let Some(email) = Self::extract_email_from_vcard(entity) {
                if email.to_lowercase().contains("abuse") {
                    return Some(email);
                }
            }
        }

        None
    }

    fn extract_email_from_vcard(entity: &serde_json::Value) -> Option<String> {
        let vcard_array = entity.get("vcardArray").and_then(|v| v.as_array())?;
        if vcard_array.len() < 2 {
            return None;
        }

        let properties = vcard_array.get(1).and_then(|v| v.as_array())?;
        for prop in properties {
            let prop_array = prop.as_array()?;
            if prop_array.first().and_then(|v| v.as_str()) == Some("email") {
                // vcard 4.0 format: ["email", { ... }, "text", "abuse@domain.com"]
                if let Some(email) = prop_array.get(3).and_then(|v| v.as_str()) {
                    return Some(email.to_string());
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rdap_empty_payload_returns_none() {
        let empty = serde_json::json!({});
        let contact = RdapParser::parse_rdap_json(&empty);
        assert!(contact.org_name.is_none());
        assert!(contact.abuse_email.is_none());
    }

    #[test]
    fn test_rdap_fallback_email_matching_when_role_missing() {
        let payload = serde_json::json!({
            "name": "SOME-ISP",
            "entities": [
                {
                    "vcardArray": [
                        "vcard",
                        [
                            ["email", {}, "text", "abuse-reports@some-isp.net"]
                        ]
                    ]
                }
            ]
        });

        let contact = RdapParser::parse_rdap_json(&payload);
        assert_eq!(contact.org_name.as_deref(), Some("SOME-ISP"));
        assert_eq!(
            contact.abuse_email.as_deref(),
            Some("abuse-reports@some-isp.net")
        );
    }
}
