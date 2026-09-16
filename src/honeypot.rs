//! # Radical OJP: Honeypot Decoy Trap Validator
//! Single Job: Detect if hidden decoy fields have been populated by automated DOM parsers.

use crate::threat_intel::DEFAULT_HONEYPOT_FIELDS;
use serde::{Deserialize, Serialize};

/// Verdict from evaluating honeypot trap inputs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HoneypotVerdict {
    /// No honeypot fields were triggered. Request is clean.
    Clean,
    /// An automated bot populated a decoy field.
    Trapped {
        field_name: String,
        trapped_value: String,
    },
}

impl HoneypotVerdict {
    #[inline]
    pub fn is_clean(&self) -> bool {
        matches!(self, HoneypotVerdict::Clean)
    }

    #[inline]
    pub fn is_trapped(&self) -> bool {
        !self.is_clean()
    }
}

/// Honeypot Decoy Validator
#[derive(Debug, Clone)]
pub struct HoneypotValidator {
    decoy_fields: Vec<String>,
}

impl Default for HoneypotValidator {
    fn default() -> Self {
        Self {
            decoy_fields: DEFAULT_HONEYPOT_FIELDS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

impl HoneypotValidator {
    /// Instantiate validator with customized decoy field names
    pub fn new<I, S>(fields: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            decoy_fields: fields.into_iter().map(Into::into).collect(),
        }
    }

    /// Retrieve the configured decoy field names (for DOM rendering)
    pub fn decoy_fields(&self) -> &[String] {
        &self.decoy_fields
    }

    /// Validate a key-value slice of submitted form fields
    pub fn validate<K, V>(&self, submitted_fields: &[(K, V)]) -> HoneypotVerdict
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        for (key, val) in submitted_fields {
            let key_str = key.as_ref();
            let val_str = val.as_ref().trim();

            if self
                .decoy_fields
                .iter()
                .any(|df| df.eq_ignore_ascii_case(key_str))
                && !val_str.is_empty()
            {
                return HoneypotVerdict::Trapped {
                    field_name: key_str.to_string(),
                    trapped_value: val_str.to_string(),
                };
            }
        }
        HoneypotVerdict::Clean
    }

    /// Validate a JSON object payload (e.g. from an API POST body)
    pub fn validate_json(&self, json_body: &serde_json::Value) -> HoneypotVerdict {
        if let Some(obj) = json_body.as_object() {
            for (key, val) in obj {
                if self
                    .decoy_fields
                    .iter()
                    .any(|df| df.eq_ignore_ascii_case(key))
                {
                    let str_val = match val {
                        serde_json::Value::String(s) => s.trim().to_string(),
                        serde_json::Value::Null => String::new(),
                        other => other.to_string(),
                    };
                    if !str_val.is_empty() {
                        return HoneypotVerdict::Trapped {
                            field_name: key.clone(),
                            trapped_value: str_val,
                        };
                    }
                }
            }
        }
        HoneypotVerdict::Clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_honeypot_clean_when_decoy_fields_absent() {
        let hp = HoneypotValidator::default();
        let payload = vec![
            ("email", "operator@rmediatech.com"),
            ("username", "rick"),
            ("password", "Secure_Pass_2026!"),
        ];
        assert_eq!(hp.validate(&payload), HoneypotVerdict::Clean);
    }

    #[test]
    fn test_honeypot_clean_when_decoy_fields_empty() {
        let hp = HoneypotValidator::default();
        let payload = vec![
            ("email", "operator@rmediatech.com"),
            ("website_url", "   "),
            ("company_fax", ""),
        ];
        assert_eq!(hp.validate(&payload), HoneypotVerdict::Clean);
    }

    #[test]
    fn test_honeypot_trapped_when_bot_populates_field() {
        let hp = HoneypotValidator::default();
        let payload = vec![
            ("email", "bot@spam.com"),
            ("website_url", "http://spam-link.ru"),
        ];
        let verdict = hp.validate(&payload);
        match verdict {
            HoneypotVerdict::Trapped {
                field_name,
                trapped_value,
            } => {
                assert_eq!(field_name, "website_url");
                assert_eq!(trapped_value, "http://spam-link.ru");
            }
            _ => panic!("Expected HoneypotVerdict::Trapped"),
        }
    }

    #[test]
    fn test_honeypot_json_validation() {
        let hp = HoneypotValidator::default();
        let clean_json = serde_json::json!({
            "email": "dev@rmediatech.com",
            "password": "Password123!",
            "website_url": null
        });
        assert_eq!(hp.validate_json(&clean_json), HoneypotVerdict::Clean);

        let dirty_json = serde_json::json!({
            "email": "bot@spam.com",
            "website_url": "https://malicious.example.com"
        });
        assert!(hp.validate_json(&dirty_json).is_trapped());
    }
}
