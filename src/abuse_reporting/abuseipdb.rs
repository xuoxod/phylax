//! # AbuseIPDB V2 API Payload & Transport Specification
//! One-Job: Construct and serialize AbuseIPDB v2 report requests and parse responses.

use serde::{Deserialize, Serialize};

/// Payload sent to AbuseIPDB /api/v2/report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseIpDbReportPayload {
    pub ip: String,
    pub categories: String,
    pub comment: String,
}

/// Parsed response from AbuseIPDB API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseIpDbResponse {
    pub ip_address: String,
    pub abuse_confidence_score: u32,
}

/// Internal wrapper matching AbuseIPDB JSON response schema
#[derive(Debug, Deserialize)]
pub struct AbuseIpDbRawResponse {
    pub data: AbuseIpDbData,
}

#[derive(Debug, Deserialize)]
pub struct AbuseIpDbData {
    #[serde(rename = "ipAddress")]
    pub ip_address: String,
    #[serde(rename = "abuseConfidenceScore")]
    pub abuse_confidence_score: u32,
}

/// Parsed reputation data from AbuseIPDB /api/v2/check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseIpDbCheckResponse {
    pub ip_address: String,
    pub is_whitelisted: bool,
    pub abuse_confidence_score: u32,
    pub country_code: Option<String>,
    pub usage_type: Option<String>,
    pub isp: Option<String>,
    pub domain: Option<String>,
    pub is_tor: bool,
    pub total_reports: u32,
}

#[derive(Debug, Deserialize)]
pub struct AbuseIpDbCheckRawResponse {
    pub data: AbuseIpDbCheckData,
}

#[derive(Debug, Deserialize)]
pub struct AbuseIpDbCheckData {
    #[serde(rename = "ipAddress")]
    pub ip_address: String,
    #[serde(rename = "isWhitelisted", default)]
    pub is_whitelisted: bool,
    #[serde(rename = "abuseConfidenceScore", default)]
    pub abuse_confidence_score: u32,
    #[serde(rename = "countryCode")]
    pub country_code: Option<String>,
    #[serde(rename = "usageType")]
    pub usage_type: Option<String>,
    pub isp: Option<String>,
    pub domain: Option<String>,
    #[serde(rename = "isTor", default)]
    pub is_tor: bool,
    #[serde(rename = "totalReports", default)]
    pub total_reports: u32,
}
