//! # Radical OJP: Email Pattern & Bot Evasion Guard
//! Single Job: Detect dot-scattering, plus-aliasing, and disposable throwaway email domains.

use crate::threat_intel::is_disposable_email_domain;
use serde::{Deserialize, Serialize};

/// Verdict from inspecting an email address
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmailVerdict {
    /// Clean, canonicalized email address
    Clean { canonical: String },
    /// Email belongs to a known disposable throwaway provider
    DisposableDomain { domain: String },
    /// Suspicious dot-scatter pattern detected (> 3 dots in local part)
    ExcessiveDotScattering { raw_local: String },
    /// Malformed email syntax
    Malformed,
}

impl EmailVerdict {
    #[inline]
    pub fn is_clean(&self) -> bool {
        matches!(self, EmailVerdict::Clean { .. })
    }
}

/// Email Pattern Guard
#[derive(Debug, Clone, Default)]
pub struct EmailPatternGuard {
    max_local_dots: usize,
}

impl EmailPatternGuard {
    pub fn new(max_local_dots: usize) -> Self {
        Self { max_local_dots }
    }

    /// Inspect and canonicalize an email address
    pub fn inspect(&self, raw_email: &str) -> EmailVerdict {
        let trimmed = raw_email.trim().to_lowercase();
        let mut parts = trimmed.split('@');

        let Some(local_part) = parts.next() else {
            return EmailVerdict::Malformed;
        };
        let Some(domain_part) = parts.next() else {
            return EmailVerdict::Malformed;
        };
        if parts.next().is_some() || local_part.is_empty() || domain_part.is_empty() {
            return EmailVerdict::Malformed;
        }

        // 1. Check for disposable throwaway domain
        if is_disposable_email_domain(domain_part) {
            return EmailVerdict::DisposableDomain {
                domain: domain_part.to_string(),
            };
        }

        // 2. Check for bot dot-scattering trick (e.g., "d.a.n.j.b.a.r.t...")
        let dot_count = local_part.chars().filter(|&c| c == '.').count();
        let threshold = if self.max_local_dots == 0 {
            3
        } else {
            self.max_local_dots
        };
        if dot_count > threshold {
            return EmailVerdict::ExcessiveDotScattering {
                raw_local: local_part.to_string(),
            };
        }

        // 3. Canonicalize Google / Gmail addresses by removing dots and plus tags
        let canonical_local = if domain_part == "gmail.com" || domain_part == "googlemail.com" {
            let base_local = local_part.split('+').next().unwrap_or(local_part);
            base_local.chars().filter(|&c| c != '.').collect::<String>()
        } else {
            local_part.to_string()
        };

        EmailVerdict::Clean {
            canonical: format!("{}@{}", canonical_local, domain_part),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_guard_clean_address() {
        let guard = EmailPatternGuard::default();
        let verdict = guard.inspect("developer@rmediatech.com");
        assert_eq!(
            verdict,
            EmailVerdict::Clean {
                canonical: "developer@rmediatech.com".to_string()
            }
        );
    }

    #[test]
    fn test_email_guard_canonicalizes_gmail_dots() {
        let guard = EmailPatternGuard::new(5);
        let verdict = guard.inspect("john.doe@gmail.com");
        assert_eq!(
            verdict,
            EmailVerdict::Clean {
                canonical: "johndoe@gmail.com".to_string()
            }
        );
    }

    #[test]
    fn test_email_guard_rejects_bot_dot_scattering() {
        let guard = EmailPatternGuard::new(3);
        // Captured from real bot: "da.nj.ba.r.t.h.ol.omew@gmail.com" has 6 dots!
        let verdict = guard.inspect("da.nj.ba.r.t.h.ol.omew@gmail.com");
        assert!(matches!(
            verdict,
            EmailVerdict::ExcessiveDotScattering { .. }
        ));
    }

    #[test]
    fn test_email_guard_rejects_disposable_domains() {
        let guard = EmailPatternGuard::default();
        let verdict = guard.inspect("attacker@tempmail.com");
        assert_eq!(
            verdict,
            EmailVerdict::DisposableDomain {
                domain: "tempmail.com".to_string()
            }
        );
    }
}
