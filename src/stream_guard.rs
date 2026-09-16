//! # Radical OJP: L7 Stream & Slowloris Protection Guard
//! Single Job: Enforce route-specific payload quotas and neutralize slow trickle stream exhaustion attacks.

use serde::{Deserialize, Serialize};

/// Endpoint route categories with tailored payload quotas
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteCategory {
    /// Authentication and form submissions (default 16 KB)
    Auth,
    /// Standard JSON API requests (default 1 MB)
    ApiJson,
    /// Media and binary uploads (default 50 MB)
    MediaUpload,
    /// Explicit custom limit
    Custom(usize),
}

impl RouteCategory {
    pub fn default_max_bytes(&self) -> usize {
        match self {
            RouteCategory::Auth => 16 * 1024,               // 16 KB
            RouteCategory::ApiJson => 1024 * 1024,          // 1 MB
            RouteCategory::MediaUpload => 50 * 1024 * 1024, // 50 MB
            RouteCategory::Custom(max) => *max,
        }
    }
}

/// Verdict resulting from L7 stream inspection
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StreamVerdict {
    /// Request size and transfer velocity are within acceptable boundaries
    Permitted,
    /// Declared or received payload exceeds route capacity
    PayloadTooLarge { length: usize, max_allowed: usize },
    /// Transfer speed is suspiciously slow, indicating Slowloris or R-U-Dead-Yet thread starvation
    SlowlorisTrickleDetected {
        bytes_received: usize,
        elapsed_ms: u64,
        rate_bps: f64,
        min_required_bps: f64,
    },
    /// Malformed Content-Length header
    MalformedLengthHeader,
}

impl StreamVerdict {
    #[inline]
    pub fn is_permitted(&self) -> bool {
        matches!(self, StreamVerdict::Permitted)
    }

    pub fn public_message(&self) -> &'static str {
        match self {
            StreamVerdict::Permitted => "Stream permitted.",
            StreamVerdict::PayloadTooLarge { .. } => {
                "Payload exceeds maximum permitted size for this endpoint."
            }
            StreamVerdict::SlowlorisTrickleDetected { .. } => {
                "Request transfer rate is below minimum throughput requirements."
            }
            StreamVerdict::MalformedLengthHeader => "Malformed Content-Length header.",
        }
    }
}

/// Configuration for Stream Guard
#[derive(Debug, Clone)]
pub struct StreamGuardConfig {
    /// Minimum transfer speed in bytes/second required after grace period
    pub min_transfer_rate_bps: f64,
    /// Grace period in milliseconds before throughput checks are enforced (e.g. 3000 ms)
    pub grace_period_ms: u64,
    /// Maximum absolute duration in milliseconds an HTTP body upload may take
    pub max_stream_duration_ms: u64,
}

impl Default for StreamGuardConfig {
    fn default() -> Self {
        Self {
            min_transfer_rate_bps: 512.0,   // Minimum 512 bytes per second
            grace_period_ms: 3000,          // 3 seconds initial grace
            max_stream_duration_ms: 60_000, // 60 seconds hard ceiling
        }
    }
}

/// Sovereign L7 Stream Guard
#[derive(Debug, Clone)]
pub struct StreamGuard {
    config: StreamGuardConfig,
}

impl Default for StreamGuard {
    fn default() -> Self {
        Self::new(StreamGuardConfig::default())
    }
}

impl StreamGuard {
    pub fn new(config: StreamGuardConfig) -> Self {
        Self { config }
    }

    /// Check Content-Length header prior to reading body stream into memory
    pub fn inspect_content_length(
        &self,
        content_length_header: Option<&str>,
        category: RouteCategory,
    ) -> StreamVerdict {
        let max_allowed = category.default_max_bytes();

        let Some(header) = content_length_header else {
            return StreamVerdict::Permitted;
        };

        match header.trim().parse::<usize>() {
            Ok(length) => {
                if length > max_allowed {
                    StreamVerdict::PayloadTooLarge {
                        length,
                        max_allowed,
                    }
                } else {
                    StreamVerdict::Permitted
                }
            }
            Err(_) => StreamVerdict::MalformedLengthHeader,
        }
    }

    /// Check throughput velocity during chunked or streaming body ingestion
    pub fn inspect_stream_progress(
        &self,
        bytes_received: usize,
        elapsed_ms: u64,
        category: RouteCategory,
    ) -> StreamVerdict {
        let max_allowed = category.default_max_bytes();

        // Check if stream has exceeded maximum buffer capacity
        if bytes_received > max_allowed {
            return StreamVerdict::PayloadTooLarge {
                length: bytes_received,
                max_allowed,
            };
        }

        // Hard duration ceiling
        if elapsed_ms > self.config.max_stream_duration_ms {
            return StreamVerdict::SlowlorisTrickleDetected {
                bytes_received,
                elapsed_ms,
                rate_bps: (bytes_received as f64) / (elapsed_ms as f64 / 1000.0),
                min_required_bps: self.config.min_transfer_rate_bps,
            };
        }

        // Evaluate throughput only after grace period has passed
        if elapsed_ms >= self.config.grace_period_ms {
            let elapsed_sec = elapsed_ms as f64 / 1000.0;
            let current_bps = (bytes_received as f64) / elapsed_sec;

            if current_bps < self.config.min_transfer_rate_bps {
                return StreamVerdict::SlowlorisTrickleDetected {
                    bytes_received,
                    elapsed_ms,
                    rate_bps: (current_bps * 100.0).round() / 100.0,
                    min_required_bps: self.config.min_transfer_rate_bps,
                };
            }
        }

        StreamVerdict::Permitted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_guard_rejects_oversized_payloads() {
        let guard = StreamGuard::default();

        // 100 KB auth submission (limit is 16 KB)
        let res = guard.inspect_content_length(Some("102400"), RouteCategory::Auth);
        assert!(matches!(res, StreamVerdict::PayloadTooLarge { .. }));

        // 500 KB API JSON submission (limit is 1 MB) -> OK
        let res_api = guard.inspect_content_length(Some("512000"), RouteCategory::ApiJson);
        assert_eq!(res_api, StreamVerdict::Permitted);
    }

    #[test]
    fn test_stream_guard_detects_slowloris_trickle() {
        let guard = StreamGuard::default();

        // During grace period (2000ms), 10 bytes transferred -> Permitted
        assert_eq!(
            guard.inspect_stream_progress(10, 2000, RouteCategory::Auth),
            StreamVerdict::Permitted
        );

        // After grace period (5000ms), only 50 bytes transferred (10 B/s < 512 B/s) -> Slowloris detected!
        let res = guard.inspect_stream_progress(50, 5000, RouteCategory::Auth);
        assert!(matches!(
            res,
            StreamVerdict::SlowlorisTrickleDetected { .. }
        ));

        // Healthy transfer: 50,000 bytes in 5000ms (10,000 B/s) -> Permitted
        assert_eq!(
            guard.inspect_stream_progress(50_000, 5000, RouteCategory::ApiJson),
            StreamVerdict::Permitted
        );
    }
}
