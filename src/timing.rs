//! # Radical OJP: Cryptographic Form Submission Timing Defense
//! Single Job: Measure and verify the elapsed time between form render and form submission.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Default minimum human interaction duration: 2.0 seconds (2,000 ms)
pub const DEFAULT_MIN_SUBMISSION_MS: u64 = 2_000;
/// Default maximum token validity: 24 hours (86,400,000 ms)
pub const DEFAULT_MAX_SUBMISSION_MS: u64 = 86_400_000;

/// Verdict resulting from submission timing verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimingVerdict {
    /// Form submission timing is within legitimate human cadence
    Valid { elapsed_ms: u64 },
    /// Form submitted too fast (automated bot script behavior)
    TooFast { elapsed_ms: u64, min_ms: u64 },
    /// Form token has expired (exceeded maximum validity window)
    Expired { elapsed_ms: u64, max_ms: u64 },
    /// Token format is invalid or malformed
    Malformed,
    /// HMAC signature verification failed (tampering detected)
    SignatureMismatch,
}

impl TimingVerdict {
    #[inline]
    pub fn is_valid(&self) -> bool {
        matches!(self, TimingVerdict::Valid { .. })
    }
}

/// Timing Defense Guard
#[derive(Debug, Clone)]
pub struct TimingGuard {
    secret_key: Vec<u8>,
    min_duration_ms: u64,
    max_duration_ms: u64,
}

impl TimingGuard {
    /// Instantiate a timing guard with specific parameters
    pub fn new<K: Into<Vec<u8>>>(secret_key: K, min_ms: u64, max_ms: u64) -> Self {
        Self {
            secret_key: secret_key.into(),
            min_duration_ms: min_ms,
            max_duration_ms: max_ms,
        }
    }

    /// Instantiate a timing guard with sensible defaults (2s min, 24h max)
    pub fn with_defaults<K: Into<Vec<u8>>>(secret_key: K) -> Self {
        Self::new(
            secret_key,
            DEFAULT_MIN_SUBMISSION_MS,
            DEFAULT_MAX_SUBMISSION_MS,
        )
    }

    /// Generate an authenticated, tamper-proof timestamp token
    pub fn generate_token(&self, now_ms: u64) -> String {
        let timestamp_bytes = now_ms.to_string();
        let sig = self.compute_hmac(timestamp_bytes.as_bytes());
        let combined = format!("{}.{}", timestamp_bytes, sig);
        B64.encode(combined.as_bytes())
    }

    /// Verify a submitted timing token against the current timestamp
    pub fn verify_token(&self, token_str: &str, now_ms: u64) -> TimingVerdict {
        let Ok(decoded_bytes) = B64.decode(token_str.trim().as_bytes()) else {
            return TimingVerdict::Malformed;
        };

        let Ok(decoded_str) = std::str::from_utf8(&decoded_bytes) else {
            return TimingVerdict::Malformed;
        };

        let mut parts = decoded_str.split('.');
        let Some(ts_str) = parts.next() else {
            return TimingVerdict::Malformed;
        };
        let Some(sig_hex) = parts.next() else {
            return TimingVerdict::Malformed;
        };

        let Ok(token_ts) = ts_str.parse::<u64>() else {
            return TimingVerdict::Malformed;
        };

        // 1. Verify HMAC signature in constant time
        let expected_sig = self.compute_hmac(ts_str.as_bytes());
        if expected_sig
            .as_bytes()
            .ct_eq(sig_hex.as_bytes())
            .unwrap_u8()
            != 1
        {
            return TimingVerdict::SignatureMismatch;
        }

        // 2. Check for time travel / clock skew
        if now_ms < token_ts {
            return TimingVerdict::Malformed;
        }

        let elapsed = now_ms - token_ts;

        // 3. Check for sub-human submission speed
        if elapsed < self.min_duration_ms {
            return TimingVerdict::TooFast {
                elapsed_ms: elapsed,
                min_ms: self.min_duration_ms,
            };
        }

        // 4. Check for token expiration
        if elapsed > self.max_duration_ms {
            return TimingVerdict::Expired {
                elapsed_ms: elapsed,
                max_ms: self.max_duration_ms,
            };
        }

        TimingVerdict::Valid {
            elapsed_ms: elapsed,
        }
    }

    fn compute_hmac(&self, data: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.secret_key)
            .expect("HMAC keys of arbitrary length are always accepted");
        mac.update(b"RMT_SHIELD_TIMING_V1:");
        mac.update(data);
        let result = mac.finalize();
        hex::encode(result.into_bytes())
    }
}

// Minimal internal hex encoder to keep crate lean
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
        let bytes = data.as_ref();
        let mut v = Vec::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            v.push(HEX_CHARS[(byte >> 4) as usize]);
            v.push(HEX_CHARS[(byte & 0x0f) as usize]);
        }
        unsafe { String::from_utf8_unchecked(v) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_guard_valid_cadence() {
        let guard = TimingGuard::with_defaults(b"sovereign_secret_key_2026");
        let start_ms = 1_000_000;
        let token = guard.generate_token(start_ms);

        // Human submitted after 3.5 seconds
        let submit_ms = start_ms + 3_500;
        let verdict = guard.verify_token(&token, submit_ms);
        assert_eq!(verdict, TimingVerdict::Valid { elapsed_ms: 3_500 });
    }

    #[test]
    fn test_timing_guard_rejects_sub_millisecond_bot() {
        let guard = TimingGuard::with_defaults(b"sovereign_secret_key_2026");
        let start_ms = 1_000_000;
        let token = guard.generate_token(start_ms);

        // Automated bot submitted after 120ms
        let submit_ms = start_ms + 120;
        let verdict = guard.verify_token(&token, submit_ms);
        assert_eq!(
            verdict,
            TimingVerdict::TooFast {
                elapsed_ms: 120,
                min_ms: DEFAULT_MIN_SUBMISSION_MS
            }
        );
    }

    #[test]
    fn test_timing_guard_rejects_tampered_token() {
        let guard = TimingGuard::with_defaults(b"sovereign_secret_key_2026");
        let start_ms = 1_000_000;
        let token = guard.generate_token(start_ms);

        // Attacker modifies a character in the token
        let mut tampered = token.into_bytes();
        tampered[5] = if tampered[5] == b'A' { b'B' } else { b'A' };
        let tampered_str = String::from_utf8(tampered).unwrap();

        let verdict = guard.verify_token(&tampered_str, start_ms + 4000);
        assert!(matches!(
            verdict,
            TimingVerdict::SignatureMismatch | TimingVerdict::Malformed
        ));
    }

    #[test]
    fn test_timing_guard_rejects_expired_token() {
        let guard = TimingGuard::new(b"sovereign_secret_key_2026", 1000, 5000);
        let start_ms = 1_000_000;
        let token = guard.generate_token(start_ms);

        // Submitted after 6 seconds (exceeding 5s max)
        let verdict = guard.verify_token(&token, start_ms + 6000);
        assert_eq!(
            verdict,
            TimingVerdict::Expired {
                elapsed_ms: 6000,
                max_ms: 5000
            }
        );
    }
}
