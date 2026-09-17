//! # Sovereign Asymmetric Tarpit Engine
//!
//! Reverses Slowloris attacks: when a malicious bot or credential-stuffing crawler
//! trips a honeypot or perimeter violation, the tarpit engine trickles response
//! chunks byte-by-byte at a throttled cadence.
//!
//! This holds the bot's execution thread and socket hostage, burning their worker pool
//! while consuming virtually zero memory or CPU on our server via async epoll.

use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// Configuration for the Asymmetric Tarpit Governor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TarpitConfig {
    /// Delay in milliseconds between trickled chunks (e.g. 3000ms = 3s)
    pub trickle_interval_ms: u64,
    /// Maximum duration in seconds to keep the bot connection stalled
    pub max_duration_s: u64,
    /// Number of bytes to send per trickle tick
    pub chunk_size: usize,
    /// Maximum concurrent tarpit connections allowed before fail-safe drop
    pub max_concurrent_tarpits: usize,
}

impl Default for TarpitConfig {
    fn default() -> Self {
        Self {
            trickle_interval_ms: 3000,
            max_duration_s: 45,
            chunk_size: 2,
            max_concurrent_tarpits: 256,
        }
    }
}

/// RAII Slot Guard that releases the tarpit slot when the connection terminates
#[derive(Debug)]
pub struct TarpitSlotGuard {
    active_count: Arc<AtomicUsize>,
    total_wasted_ms: Arc<AtomicU64>,
    start_ms: u64,
}

impl Drop for TarpitSlotGuard {
    fn drop(&mut self) {
        self.active_count.fetch_sub(1, Ordering::SeqCst);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(self.start_ms);
        let elapsed = now.saturating_sub(self.start_ms);
        self.total_wasted_ms.fetch_add(elapsed, Ordering::Relaxed);
    }
}

/// Tarpit allocation verdict
#[derive(Debug)]
pub enum TarpitVerdict {
    /// Tarpit engaged: worker held in slow trickle stream
    Engage { slot_guard: TarpitSlotGuard },
    /// Concurrency ceiling reached: fail-safe drop connection to conserve server FDs
    CeilingExceededDrop,
}

impl PartialEq for TarpitVerdict {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (TarpitVerdict::Engage { .. }, TarpitVerdict::Engage { .. })
                | (
                    TarpitVerdict::CeilingExceededDrop,
                    TarpitVerdict::CeilingExceededDrop
                )
        )
    }
}

/// The Tarpit Governor orchestrating connection slots and decoy payload trickling
#[derive(Debug, Clone)]
pub struct TarpitGovernor {
    config: TarpitConfig,
    active_count: Arc<AtomicUsize>,
    total_tarpitted: Arc<AtomicUsize>,
    total_wasted_ms: Arc<AtomicU64>,
    _lock: Arc<Mutex<()>>,
}

impl TarpitGovernor {
    pub fn new(config: TarpitConfig) -> Self {
        Self {
            config,
            active_count: Arc::new(AtomicUsize::new(0)),
            total_tarpitted: Arc::new(AtomicUsize::new(0)),
            total_wasted_ms: Arc::new(AtomicU64::new(0)),
            _lock: Arc::new(Mutex::new(())),
        }
    }

    /// Try to acquire a tarpit slot for an offending client IP
    pub fn acquire_slot(&self, _client_ip: &str) -> TarpitVerdict {
        let current = self.active_count.load(Ordering::SeqCst);
        if current >= self.config.max_concurrent_tarpits {
            return TarpitVerdict::CeilingExceededDrop;
        }

        self.active_count.fetch_add(1, Ordering::SeqCst);
        self.total_tarpitted.fetch_add(1, Ordering::Relaxed);

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        TarpitVerdict::Engage {
            slot_guard: TarpitSlotGuard {
                active_count: Arc::clone(&self.active_count),
                total_wasted_ms: Arc::clone(&self.total_wasted_ms),
                start_ms: now_ms,
            },
        }
    }

    /// Generate an endless, syntactically valid decoy chunk (HTML or JSON stream)
    pub fn generate_decoy_chunk(&self, chunk_index: usize) -> Vec<u8> {
        if chunk_index == 0 {
            b"<!DOCTYPE html><html><head><title>Authentication Verification In Progress</title></head><body><!-- init -->\n".to_vec()
        } else {
            format!(
                "<!-- chunk_{:04x}: verifying security telemetry parameters... -->\n",
                chunk_index
            )
            .into_bytes()
        }
    }

    pub fn active_tarpits_count(&self) -> usize {
        self.active_count.load(Ordering::SeqCst)
    }

    pub fn total_tarpitted_count(&self) -> usize {
        self.total_tarpitted.load(Ordering::Relaxed)
    }

    pub fn total_wasted_duration_ms(&self) -> u64 {
        self.total_wasted_ms.load(Ordering::Relaxed)
    }

    pub fn config(&self) -> &TarpitConfig {
        &self.config
    }
}
