//! # Radical OJP: Zero-Lock In-Memory Cache Shield
//! Single Job: Serve high-concurrency public HTTP requests from memory with ETag matching and zero SQLite/disk I/O.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

/// Cached item in the memory shield
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub content_type: String,
    pub body: Arc<Vec<u8>>,
    pub etag: String,
    pub expires_at_s: u64,
}

/// Verdict resulting from CacheShield evaluation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheVerdict {
    /// Fresh content found in memory shield
    Hit {
        body: Arc<Vec<u8>>,
        content_type: String,
        etag: String,
    },
    /// Client's If-None-Match ETag matches current cached state (HTTP 304)
    NotModified { etag: String },
    /// Resource is not in cache (requires handler execution)
    Miss,
    /// Resource was in cache but has passed its TTL
    Expired,
}

impl CacheVerdict {
    #[inline]
    pub fn is_hit_or_304(&self) -> bool {
        matches!(
            self,
            CacheVerdict::Hit { .. } | CacheVerdict::NotModified { .. }
        )
    }
}

/// Configuration for Cache Shield
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheShieldConfig {
    pub max_entries: usize,
    pub default_ttl_s: u64,
}

impl Default for CacheShieldConfig {
    fn default() -> Self {
        Self {
            max_entries: 1_000,
            default_ttl_s: 300, // 5 minutes
        }
    }
}

/// Sovereign In-Memory HTTP Cache Shield
#[derive(Debug, Clone)]
pub struct CacheShield {
    config: CacheShieldConfig,
    store: Arc<RwLock<HashMap<String, CachedResponse>>>,
}

impl Default for CacheShield {
    fn default() -> Self {
        Self::new(CacheShieldConfig::default())
    }
}

impl CacheShield {
    pub fn new(config: CacheShieldConfig) -> Self {
        Self {
            config,
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate strong ETag from body content
    pub fn compute_etag(body: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(body);
        let hash = hasher.finalize();
        let hex_prefix: String = hash[..8].iter().map(|b| format!("{:02x}", b)).collect();
        format!("\"{}\"", hex_prefix)
    }

    /// Query cache for an endpoint key with client-provided If-None-Match header
    pub fn get(&self, key: &str, if_none_match: Option<&str>, now_s: u64) -> CacheVerdict {
        let store = self.store.read();
        let Some(entry) = store.get(key) else {
            return CacheVerdict::Miss;
        };

        if now_s >= entry.expires_at_s {
            return CacheVerdict::Expired;
        }

        // Check ETag 304 conditional match
        if let Some(client_etag) = if_none_match {
            let clean_client = client_etag.trim();
            if clean_client == entry.etag || clean_client == "*" {
                return CacheVerdict::NotModified {
                    etag: entry.etag.clone(),
                };
            }
        }

        CacheVerdict::Hit {
            body: Arc::clone(&entry.body),
            content_type: entry.content_type.clone(),
            etag: entry.etag.clone(),
        }
    }

    /// Insert or update an entry in the cache
    pub fn insert(
        &self,
        key: &str,
        body: Vec<u8>,
        content_type: &str,
        ttl_s: Option<u64>,
        now_s: u64,
    ) -> String {
        let etag = Self::compute_etag(&body);
        let ttl = ttl_s.unwrap_or(self.config.default_ttl_s);
        let expires_at_s = now_s + ttl;

        let mut store = self.store.write();
        // Prune if limit reached
        if store.len() >= self.config.max_entries {
            store.retain(|_, v| v.expires_at_s > now_s);
        }

        store.insert(
            key.to_string(),
            CachedResponse {
                content_type: content_type.to_string(),
                body: Arc::new(body),
                etag: etag.clone(),
                expires_at_s,
            },
        );

        etag
    }

    /// Invalidate a specific cached route
    pub fn invalidate(&self, key: &str) {
        let mut store = self.store.write();
        store.remove(key);
    }

    /// Clear all cached responses
    pub fn clear(&self) {
        let mut store = self.store.write();
        store.clear();
    }

    /// Number of active items in cache
    pub fn len(&self) -> usize {
        let store = self.store.read();
        store.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_shield_hit_and_etag_304() {
        let cache = CacheShield::default();
        let now = 1_000_000;
        let route = "/api/v1/public/announcements";
        let body = b"{\"status\":\"operational\"}".to_vec();

        let etag = cache.insert(route, body, "application/json", Some(60), now);

        // First request without If-None-Match -> Hit
        match cache.get(route, None, now + 10) {
            CacheVerdict::Hit {
                body,
                etag: hit_etag,
                ..
            } => {
                assert_eq!(hit_etag, etag);
                assert_eq!(&*body, b"{\"status\":\"operational\"}");
            }
            other => panic!("Expected CacheVerdict::Hit, got {:?}", other),
        }

        // Subsequent request with matching If-None-Match -> NotModified (HTTP 304)
        match cache.get(route, Some(&etag), now + 15) {
            CacheVerdict::NotModified { etag: not_mod_etag } => {
                assert_eq!(not_mod_etag, etag);
            }
            other => panic!("Expected NotModified, got {:?}", other),
        }

        // After TTL expires -> Expired
        assert_eq!(cache.get(route, None, now + 65), CacheVerdict::Expired);
    }
}
