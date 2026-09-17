//! # Report Cooldown & Quota Governor
//! One-Job: Sliding-window deduplication per IP and global daily quota governance.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// Configuration parameters for report rate-limiting and quota safety
#[derive(Debug, Clone)]
pub struct CooldownConfig {
    /// Minimum milliseconds required between reports for the same IP (e.g. 15 minutes = 900,000ms)
    pub cooldown_window_ms: u64,
    /// Hard ceiling on total reports dispatched across all IPs within any 24-hour window
    pub max_reports_per_day: usize,
}

impl Default for CooldownConfig {
    fn default() -> Self {
        Self {
            cooldown_window_ms: 900_000, // 15 minutes
            max_reports_per_day: 100,
        }
    }
}

#[derive(Debug)]
struct CooldownState {
    last_reported: HashMap<String, u64>,
    daily_timestamps: Vec<u64>,
}

/// Thread-safe deduplication governor
#[derive(Clone, Debug)]
pub struct ReportCooldownGovernor {
    config: CooldownConfig,
    state: Arc<RwLock<CooldownState>>,
}

impl ReportCooldownGovernor {
    pub fn new(config: CooldownConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CooldownState {
                last_reported: HashMap::new(),
                daily_timestamps: Vec::new(),
            })),
        }
    }

    /// Evaluates if an incident for this IP is eligible for dispatch
    pub fn should_report(&self, ip: &str, now_ms: u64) -> bool {
        let mut state = self.state.write();

        // 1. Prune timestamps older than 24 hours (86,400,000 ms)
        let cutoff_24h = now_ms.saturating_sub(86_400_000);
        state.daily_timestamps.retain(|&ts| ts > cutoff_24h);

        // 2. Check global daily quota
        if state.daily_timestamps.len() >= self.config.max_reports_per_day {
            return false;
        }

        // 3. Check per-IP cooldown window
        if let Some(&last_ts) = state.last_reported.get(ip) {
            if now_ms < last_ts.saturating_add(self.config.cooldown_window_ms) {
                return false;
            }
        }

        true
    }

    /// Records that a report was dispatched for the IP
    pub fn record_reported(&self, ip: &str, now_ms: u64) {
        let mut state = self.state.write();

        state.last_reported.insert(ip.to_string(), now_ms);
        state.daily_timestamps.push(now_ms);

        // Bounded memory cleanup: remove entries older than 24 hours
        let cutoff_24h = now_ms.saturating_sub(86_400_000);
        state.last_reported.retain(|_, &mut ts| ts > cutoff_24h);
    }

    /// Returns count of reports sent within the current 24-hour sliding window
    pub fn daily_reports_count(&self) -> usize {
        let state = self.state.read();
        state.daily_timestamps.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cooldown_24h_eviction_resets_quota() {
        let config = CooldownConfig {
            cooldown_window_ms: 1000,
            max_reports_per_day: 2,
        };
        let governor = ReportCooldownGovernor::new(config);
        let t0 = 100_000_000;

        // Record 2 reports to hit limit
        governor.record_reported("1.1.1.1", t0);
        governor.record_reported("2.2.2.2", t0 + 100);
        assert_eq!(governor.daily_reports_count(), 2);
        assert!(!governor.should_report("3.3.3.3", t0 + 200));

        // Advance time by 25 hours (90,000,000 ms)
        let t1 = t0 + 90_000_000;
        assert!(governor.should_report("3.3.3.3", t1));
        governor.record_reported("3.3.3.3", t1);
        assert_eq!(governor.daily_reports_count(), 1);
    }

    #[test]
    fn test_default_cooldown_config() {
        let def = CooldownConfig::default();
        assert_eq!(def.cooldown_window_ms, 900_000);
        assert_eq!(def.max_reports_per_day, 100);
    }
}
