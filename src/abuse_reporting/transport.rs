//! # Abuse Reporter Transport Abstraction & Implementations
//! One-Job: Execute HTTP transmission of report payloads with mockability for deterministic testing.

use crate::abuse_reporting::abuseipdb::{
    AbuseIpDbCheckRawResponse, AbuseIpDbCheckResponse, AbuseIpDbRawResponse,
    AbuseIpDbReportPayload, AbuseIpDbResponse,
};
use crate::abuse_reporting::error::AbuseReportError;
use parking_lot::Mutex;
use std::sync::Arc;

/// Trait defining transport capability for dispatching abuse reports and reputation lookups
#[async_trait::async_trait]
pub trait AbuseReporterTransport: Send + Sync {
    async fn submit_report(
        &self,
        payload: &AbuseIpDbReportPayload,
        api_key: &str,
    ) -> Result<AbuseIpDbResponse, AbuseReportError>;

    async fn check_ip(
        &self,
        ip: &str,
        api_key: &str,
    ) -> Result<AbuseIpDbCheckResponse, AbuseReportError>;
}

/// Production HTTP transport using reqwest and rustls
pub struct HttpAbuseReporterTransport {
    client: reqwest::Client,
    endpoint: String,
}

impl HttpAbuseReporterTransport {
    pub fn new(endpoint: Option<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            endpoint: endpoint
                .unwrap_or_else(|| "https://api.abuseipdb.com/api/v2/report".to_string()),
        }
    }
}

impl Default for HttpAbuseReporterTransport {
    fn default() -> Self {
        Self::new(None)
    }
}

#[async_trait::async_trait]
impl AbuseReporterTransport for HttpAbuseReporterTransport {
    async fn submit_report(
        &self,
        payload: &AbuseIpDbReportPayload,
        api_key: &str,
    ) -> Result<AbuseIpDbResponse, AbuseReportError> {
        if api_key.trim().is_empty() {
            return Err(AbuseReportError::MissingApiKey);
        }

        let resp = self
            .client
            .post(&self.endpoint)
            .header("Key", api_key)
            .header("Accept", "application/json")
            .form(&[
                ("ip", payload.ip.as_str()),
                ("categories", payload.categories.as_str()),
                ("comment", payload.comment.as_str()),
            ])
            .send()
            .await
            .map_err(|e| AbuseReportError::Network(e.to_string()))?;

        let status = resp.status();
        if status == reqwest::StatusCode::OK {
            let raw: AbuseIpDbRawResponse = resp
                .json()
                .await
                .map_err(|e| AbuseReportError::Serialization(e.to_string()))?;
            Ok(AbuseIpDbResponse {
                ip_address: raw.data.ip_address,
                abuse_confidence_score: raw.data.abuse_confidence_score,
            })
        } else if status == reqwest::StatusCode::UNAUTHORIZED {
            Err(AbuseReportError::Unauthorized)
        } else if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry_after = resp
                .headers()
                .get("Retry-After")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            Err(AbuseReportError::RateLimited {
                retry_after_s: retry_after,
            })
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(AbuseReportError::ApiError {
                status: status.as_u16(),
                body,
            })
        }
    }

    async fn check_ip(
        &self,
        ip: &str,
        api_key: &str,
    ) -> Result<AbuseIpDbCheckResponse, AbuseReportError> {
        if api_key.trim().is_empty() {
            return Err(AbuseReportError::MissingApiKey);
        }

        let check_url = if self.endpoint.ends_with("/report") {
            self.endpoint.replace("/report", "/check")
        } else {
            "https://api.abuseipdb.com/api/v2/check".to_string()
        };

        let resp = self
            .client
            .get(&check_url)
            .header("Key", api_key)
            .header("Accept", "application/json")
            .query(&[("ipAddress", ip)])
            .send()
            .await
            .map_err(|e| AbuseReportError::Network(e.to_string()))?;

        let status = resp.status();
        if status == reqwest::StatusCode::OK {
            let raw: AbuseIpDbCheckRawResponse = resp
                .json()
                .await
                .map_err(|e| AbuseReportError::Serialization(e.to_string()))?;
            Ok(AbuseIpDbCheckResponse {
                ip_address: raw.data.ip_address,
                is_whitelisted: raw.data.is_whitelisted,
                abuse_confidence_score: raw.data.abuse_confidence_score,
                country_code: raw.data.country_code,
                usage_type: raw.data.usage_type,
                isp: raw.data.isp,
                domain: raw.data.domain,
                is_tor: raw.data.is_tor,
                total_reports: raw.data.total_reports,
            })
        } else if status == reqwest::StatusCode::UNAUTHORIZED {
            Err(AbuseReportError::Unauthorized)
        } else if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry_after = resp
                .headers()
                .get("Retry-After")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            Err(AbuseReportError::RateLimited {
                retry_after_s: retry_after,
            })
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(AbuseReportError::ApiError {
                status: status.as_u16(),
                body,
            })
        }
    }
}

/// In-memory mock transport for deterministic testing
#[derive(Clone, Default)]
pub struct MockAbuseReporterTransport {
    recorded: Arc<Mutex<Vec<AbuseIpDbReportPayload>>>,
    simulated_error: Arc<Mutex<Option<AbuseReportError>>>,
}

impl MockAbuseReporterTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_simulated_error(&self, error: Option<AbuseReportError>) {
        *self.simulated_error.lock() = error;
    }

    pub fn get_recorded_reports(&self) -> Vec<AbuseIpDbReportPayload> {
        self.recorded.lock().clone()
    }
}

#[async_trait::async_trait]
impl AbuseReporterTransport for MockAbuseReporterTransport {
    async fn submit_report(
        &self,
        payload: &AbuseIpDbReportPayload,
        api_key: &str,
    ) -> Result<AbuseIpDbResponse, AbuseReportError> {
        if api_key.trim().is_empty() {
            return Err(AbuseReportError::MissingApiKey);
        }

        if let Some(ref err) = *self.simulated_error.lock() {
            return Err(err.clone());
        }

        self.recorded.lock().push(payload.clone());

        Ok(AbuseIpDbResponse {
            ip_address: payload.ip.clone(),
            abuse_confidence_score: 100,
        })
    }

    async fn check_ip(
        &self,
        ip: &str,
        api_key: &str,
    ) -> Result<AbuseIpDbCheckResponse, AbuseReportError> {
        if api_key.trim().is_empty() {
            return Err(AbuseReportError::MissingApiKey);
        }

        if let Some(ref err) = *self.simulated_error.lock() {
            return Err(err.clone());
        }

        Ok(AbuseIpDbCheckResponse {
            ip_address: ip.to_string(),
            is_whitelisted: false,
            abuse_confidence_score: 100,
            country_code: Some("US".to_string()),
            usage_type: Some("Data Center/Web Hosting/Transit".to_string()),
            isp: Some("Mock ISP".to_string()),
            domain: Some("mockisp.net".to_string()),
            is_tor: false,
            total_reports: 42,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_empty_api_key_rejected_immediately() {
        let mock = MockAbuseReporterTransport::new();
        let payload = AbuseIpDbReportPayload {
            ip: "1.1.1.1".to_string(),
            categories: "10".to_string(),
            comment: "test".to_string(),
        };
        let err = mock.submit_report(&payload, "   ").await.unwrap_err();
        assert!(matches!(err, AbuseReportError::MissingApiKey));
    }
}
