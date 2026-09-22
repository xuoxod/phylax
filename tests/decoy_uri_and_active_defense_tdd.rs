//! # Decoy URI Honeyroutes & Active Reconnaissance Defense TDD Suite
//! Radical OJP & TDD Suite for deterministic scanner interception and automated multi-sink reporting.

use phylax::decoy_uri::{DecoyCategory, DecoyUriConfig, DecoyUriSentinel, DecoyUriVerdict};
use phylax::pipeline::{DenialReason, ShieldPipeline, ShieldRequest, ShieldVerdict};
#[cfg(feature = "abuse-reporting")]
use std::time::Duration;

#[cfg(feature = "abuse-reporting")]
use phylax::abuse_reporting::{
    CooldownConfig, InformantConfig, InformantEngine, MockAbuseReporterTransport,
};
#[cfg(feature = "abuse-reporting")]
use std::sync::Arc;

#[test]
fn test_decoy_uri_sentinel_pure_evaluation() {
    let sentinel = DecoyUriSentinel::default();

    // 1. Clean application routes
    assert_eq!(sentinel.evaluate("/"), DecoyUriVerdict::Clean);
    assert_eq!(sentinel.evaluate("/auth/login"), DecoyUriVerdict::Clean);
    assert_eq!(sentinel.evaluate("/pricing"), DecoyUriVerdict::Clean);
    assert_eq!(sentinel.evaluate("/healthz"), DecoyUriVerdict::Clean);
    assert_eq!(sentinel.evaluate("/assets/app.js"), DecoyUriVerdict::Clean);

    // 2. Trapped common vulnerability scanner targets
    assert!(matches!(
        sentinel.evaluate("/.env"),
        DecoyUriVerdict::Trapped { category: DecoyCategory::EnvironmentSecret, .. }
    ));
    assert!(matches!(
        sentinel.evaluate("/.azure/credentials"),
        DecoyUriVerdict::Trapped { category: DecoyCategory::EnvironmentSecret, .. }
    ));
    assert!(matches!(
        sentinel.evaluate("/app/terraform.tfstate"),
        DecoyUriVerdict::Trapped { category: DecoyCategory::CloudInfrastructure, .. }
    ));
    assert!(matches!(
        sentinel.evaluate("/wp-login.php"),
        DecoyUriVerdict::Trapped { category: DecoyCategory::AdminCmsProbe, .. }
    ));
    assert!(matches!(
        sentinel.evaluate("/.git/config"),
        DecoyUriVerdict::Trapped { category: DecoyCategory::VersionControl, .. }
    ));
    assert!(matches!(
        sentinel.evaluate("/backup.sql"),
        DecoyUriVerdict::Trapped { category: DecoyCategory::DatabaseBackup, .. }
    ));
    assert!(matches!(
        sentinel.evaluate("/private.key"),
        DecoyUriVerdict::Trapped { category: DecoyCategory::PrivateKey, .. }
    ));

    // 3. Generic PHP exploit scans against pure Rust backend
    assert!(matches!(
        sentinel.evaluate("/wp-configs.php"),
        DecoyUriVerdict::Trapped { category: DecoyCategory::AdminCmsProbe, .. }
    ));
    assert!(matches!(
        sentinel.evaluate("/update.php"),
        DecoyUriVerdict::Trapped { category: DecoyCategory::AdminCmsProbe, .. }
    ));
    assert!(matches!(
        sentinel.evaluate("/2.php"),
        DecoyUriVerdict::Trapped { category: DecoyCategory::AdminCmsProbe, .. }
    ));
    assert!(matches!(
        sentinel.evaluate("/shell.phtml"),
        DecoyUriVerdict::Trapped { category: DecoyCategory::AdminCmsProbe, .. }
    ));
}

#[test]
fn test_decoy_uri_reconnaissance_traps_scanners_in_shield_pipeline() {
    let pipeline = ShieldPipeline::builder().build();
    let now_ms = 1_000_000;

    // 1. Clean Request to legitimate endpoint -> Allowed
    let clean_req = ShieldRequest {
        client_ip: "198.51.100.22",
        target_uri: Some("/auth/login"),
        http_method: Some("GET"),
        now_ms,
        ..Default::default()
    };
    let verdict = pipeline.evaluate_perimeter(&clean_req);
    assert!(verdict.is_allowed(), "Clean request should be allowed");

    // 2. Scanner hitting /.env -> Denied as DecoyUriTrapped
    let scanner_req = ShieldRequest {
        client_ip: "34.140.234.80",
        target_uri: Some("/.env"),
        http_method: Some("GET"),
        now_ms,
        ..Default::default()
    };
    let verdict = pipeline.evaluate_perimeter(&scanner_req);
    assert_eq!(
        verdict,
        ShieldVerdict::Deny(DenialReason::DecoyUriTrapped {
            path: "/.env".to_string(),
            category: "Environment & Secrets Probe".to_string(),
        })
    );

    // 3. Scanner hitting /wp-login.php -> Denied as AdminCmsProbe
    let cms_scanner_req = ShieldRequest {
        client_ip: "39.185.68.25",
        target_uri: Some("/wp-login.php"),
        http_method: Some("GET"),
        now_ms,
        ..Default::default()
    };
    let verdict = pipeline.evaluate_perimeter(&cms_scanner_req);
    assert_eq!(
        verdict,
        ShieldVerdict::Deny(DenialReason::DecoyUriTrapped {
            path: "/wp-login.php".to_string(),
            category: "Administrative & CMS Panel Probe".to_string(),
        })
    );

    // 4. Scanner hitting /.git/HEAD with normalization -> Denied as VersionControl
    let git_req = ShieldRequest {
        client_ip: "185.220.101.5",
        target_uri: Some("//.git/HEAD?ref=main"),
        http_method: Some("GET"),
        now_ms,
        ..Default::default()
    };
    let verdict = pipeline.evaluate_perimeter(&git_req);
    assert_eq!(
        verdict,
        ShieldVerdict::Deny(DenialReason::DecoyUriTrapped {
            path: "/.git/head".to_string(),
            category: "Version Control Repository Probe".to_string(),
        })
    );
}

#[test]
fn test_decoy_uri_trap_populates_quarantine_and_adaptive_pow() {
    let pipeline = ShieldPipeline::builder().build();
    let now_ms = 1_000_000;
    let scanner_ip = "193.189.100.200";

    assert_eq!(pipeline.adaptive_pow().tracked_ips_count(), 0);

    let probe = ShieldRequest {
        client_ip: scanner_ip,
        target_uri: Some("/.azure/credentials"),
        http_method: Some("GET"),
        now_ms,
        ..Default::default()
    };

    let verdict = pipeline.evaluate_perimeter(&probe);
    assert!(matches!(verdict, ShieldVerdict::Deny(DenialReason::DecoyUriTrapped { .. })));

    // Verify adaptive PoW difficulty was ratcheted for repeat scanner
    assert_eq!(pipeline.adaptive_pow().tracked_ips_count(), 1);
    assert!(pipeline.adaptive_pow().get_difficulty(scanner_ip, now_ms) > 10);
}

#[cfg(feature = "abuse-reporting")]
#[tokio::test]
async fn test_decoy_uri_trap_triggers_asynchronous_abuse_reporting() {
    let mock_transport = Arc::new(MockAbuseReporterTransport::new());
    let informant_config = InformantConfig {
        enabled: true,
        dry_run: false,
        api_key: Some("test_api_key".to_string()),
        webhook_url: None,
        webhook_auth: None,
        cooldown: CooldownConfig {
            cooldown_window_ms: 60_000,
            max_reports_per_day: 10,
        },
    };

    let informant = Arc::new(InformantEngine::new(
        informant_config,
        mock_transport.clone(),
    ));

    let pipeline = ShieldPipeline::builder()
        .with_informant_engine(informant.clone())
        .build();

    let now_ms = 1_000_000;
    let scanner_ip = "45.84.107.101";

    let probe = ShieldRequest {
        client_ip: scanner_ip,
        target_uri: Some("/.env"),
        http_method: Some("GET"),
        user_agent: Some("Go-http-client/1.1"),
        now_ms,
        ..Default::default()
    };

    let verdict = pipeline.evaluate_perimeter(&probe);
    assert!(matches!(verdict, ShieldVerdict::Deny(DenialReason::DecoyUriTrapped { .. })));

    // Allow async background dispatch task to execute
    tokio::time::sleep(Duration::from_millis(50)).await;

    let reports = mock_transport.get_recorded_reports();
    assert_eq!(reports.len(), 1, "Should have submitted 1 abuse report");
    assert_eq!(reports[0].ip, scanner_ip);
    assert_eq!(reports[0].categories, "15,21"); // Category 15: Hacking, Category 21: Web App Attack
    assert!(reports[0].comment.contains("/.env"));
    assert!(reports[0].comment.contains("decoy URI probe trapped"));

    // Duplicate probe within cooldown must be suppressed
    let _ = pipeline.evaluate_perimeter(&probe);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(mock_transport.get_recorded_reports().len(), 1, "Duplicate report must be suppressed by cooldown");
}

#[test]
fn test_decoy_uri_custom_builder_configuration() {
    let config = DecoyUriConfig {
        enabled: true,
        custom_exact_routes: vec![("/super-secret-admin".to_string(), DecoyCategory::Custom)],
        custom_prefix_routes: vec![("/hidden-api/".to_string(), DecoyCategory::Custom)],
    };

    let pipeline = ShieldPipeline::builder()
        .with_decoy_uris(config)
        .build();

    let custom_probe = ShieldRequest {
        client_ip: "10.0.0.1",
        target_uri: Some("/super-secret-admin"),
        now_ms: 1000,
        ..Default::default()
    };

    let verdict = pipeline.evaluate_perimeter(&custom_probe);
    assert_eq!(
        verdict,
        ShieldVerdict::Deny(DenialReason::DecoyUriTrapped {
            path: "/super-secret-admin".to_string(),
            category: "Custom Decoy Honeyroute".to_string(),
        })
    );
}
