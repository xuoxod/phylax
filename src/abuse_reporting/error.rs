//! # Informant Domain Error Taxonomy
//! One-Job: Type-safe, actionable error definitions.

use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum AbuseReportError {
    #[error("Missing or unconfigured AbuseIPDB API key")]
    MissingApiKey,

    #[error("API authentication failed: invalid API key (HTTP 401)")]
    Unauthorized,

    #[error("Rate limit exceeded on reporting endpoint (retry after {retry_after_s:?}s)")]
    RateLimited { retry_after_s: Option<u64> },

    #[error("Upstream HTTP transmission failure: {0}")]
    Network(String),

    #[error("API returned error response (HTTP {status}): {body}")]
    ApiError { status: u16, body: String },

    #[error("Serialization / JSON error: {0}")]
    Serialization(String),
}

#[derive(Error, Debug, Clone)]
pub enum RdapError {
    #[error("Upstream RDAP query network failure: {0}")]
    Network(String),

    #[error("Invalid RDAP JSON payload: {0}")]
    InvalidPayload(String),

    #[error("No abuse contact entity located in RDAP response")]
    NotFound,
}
