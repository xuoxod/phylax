//! # Phylax Autonomous Maintenance & Abuse Intelligence Integration TDD
//! Radical OJP & TDD Suite for zero-lock memory hygiene and optional AbuseIPDB incident reporting.

use phylax::adaptive_pow::{AdaptivePowConfig, InfractionSeverity};
use phylax::autonomous_quarantine::QuarantineConfig;
use phylax::pipeline::{DenialReason, ShieldPipeline, ShieldRequest, ShieldVerdict};
use std::time::Duration;

#[cfg(feature = "abuse-reporting")]
use phylax::abuse_reporting::{
    CooldownConfig, InformantConfig, InformantEngine, MockAbuseReporterTransport,
};
#[cfg(feature = "abuse-reporting")]
use std::sync::Arc;

#[test]
fn test_pipeline_maintenance_manager_prunes_stores_and_returns_accurate_report() {
    let pipeline = ShieldPipeline::builder()
        .with_quarantine(QuarantineConfig {
            infraction_threshold: 1,
            quarantine_duration_ms: 1000,
            max_tracked_subnets: 100,
        })
        .with_adaptive_pow(AdaptivePowConfig {
            baseline_difficulty: 10,
            suspicious_difficulty: 12,
            hostile_difficulty: 14,
            severe_difficulty: 16,
            infraction_decay_ms: 1000,
        })
        .build();

    let now_ms = 1_000_000;

    // Simulate honeypot trap at t=1,000,000
    let trapped_fields = vec![("website_url".to_string(), "http://bot.com".to_string())];
    let req = ShieldRequest {
        client_ip: "185.34.33.2",
        submitted_fields: &trapped_fields,
        now_ms,
        ..Default::default()
    };

    let verdict = pipeline.evaluate(&req);
    assert_eq!(
        verdict,
        ShieldVerdict::Deny(DenialReason::HoneypotTrapped {
            field: "website_url".to_string()
        })
    );

    // Verify state was populated: 1 quarantined subnet, 1 adaptive PoW record
    assert_eq!(pipeline.quarantine().active_bans_count(), 1);
    assert_eq!(pipeline.adaptive_pow().tracked_ips_count(), 1);

    // Immediate maintenance pass at t+500ms (nothing pruned)
    let early_report = pipeline.run_maintenance(now_ms + 500);
    assert_eq!(early_report.quarantined_subnets_pruned, 0);
    assert_eq!(early_report.decayed_pow_records_pruned, 0);
    assert_eq!(early_report.active_quarantined_subnets, 1);
    assert_eq!(early_report.active_pow_records, 1);

    // Advance time past quarantine and decay window (t+4,000ms: 4 decay steps = score 0)
    let expired_report = pipeline.run_maintenance(now_ms + 4000);
    assert_eq!(expired_report.quarantined_subnets_pruned, 1);
    assert_eq!(expired_report.decayed_pow_records_pruned, 1);
    assert_eq!(expired_report.active_quarantined_subnets, 0);
    assert_eq!(expired_report.active_pow_records, 0);
}

#[tokio::test]
async fn test_pipeline_spawn_background_maintenance_cleans_autonomously() {
    let pipeline = ShieldPipeline::builder()
        .with_quarantine(QuarantineConfig {
            infraction_threshold: 1,
            quarantine_duration_ms: 50,
            max_tracked_subnets: 50,
        })
        .with_adaptive_pow(AdaptivePowConfig {
            baseline_difficulty: 10,
            suspicious_difficulty: 12,
            hostile_difficulty: 14,
            severe_difficulty: 16,
            infraction_decay_ms: 50,
        })
        .build();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Trigger quarantine infraction
    pipeline.quarantine().record_and_check("192.168.1.100", now_ms);
    pipeline.adaptive_pow().record_infraction(
        "192.168.1.100",
        InfractionSeverity::Suspicious,
        now_ms,
    );

    assert_eq!(pipeline.quarantine().active_bans_count(), 1);
    assert_eq!(pipeline.adaptive_pow().tracked_ips_count(), 1);

    // Spawn background worker with 20ms interval
    let handle = pipeline.spawn_background_maintenance(Duration::from_millis(20));

    // Wait 120ms for expiration (50ms) and tick cleanup
    tokio::time::sleep(Duration::from_millis(120)).await;

    assert_eq!(pipeline.quarantine().active_bans_count(), 0);
    assert_eq!(pipeline.adaptive_pow().tracked_ips_count(), 0);

    handle.abort();
}

#[cfg(feature = "abuse-reporting")]
#[tokio::test]
async fn test_pipeline_honeypot_triggers_asynchronous_abuse_reporting() {
    let mock_transport = Arc::new(MockAbuseReporterTransport::new());
    let informant_config = InformantConfig {
        enabled: true,
        dry_run: false,
        api_key: Some("valid_key".to_string()),
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

    // Clean request - should NOT trigger report
    let clean_req = ShieldRequest {
        client_ip: "96.227.137.21",
        submitted_fields: &[("username".to_string(), "alice".to_string())],
        now_ms,
        ..Default::default()
    };
    let _ = pipeline.evaluate_perimeter(&clean_req);

    // Allow async tasks a moment to run
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(mock_transport.get_recorded_reports().len(), 0);

    // Honeypot trap tripped - SHOULD trigger async report
    let trapped_req = ShieldRequest {
        client_ip: "185.34.33.2",
        submitted_fields: &[
            ("username".to_string(), "bot".to_string()),
            ("website_url".to_string(), "http://evil.com".to_string()),
        ],
        target_uri: Some("/auth/login"),
        http_method: Some("POST"),
        user_agent: Some("curl/8.5.0"),
        now_ms,
        ..Default::default()
    };

    let verdict = pipeline.evaluate_perimeter(&trapped_req);
    assert!(matches!(
        verdict,
        ShieldVerdict::Deny(DenialReason::HoneypotTrapped { .. })
    ));

    // Wait for tokio async worker to complete dispatch
    tokio::time::sleep(Duration::from_millis(50)).await;

    let reports = mock_transport.get_recorded_reports();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].ip, "185.34.33.2");
    assert_eq!(reports[0].categories, "10,21");
    assert!(reports[0].comment.contains("185.34.33.2"));
    assert!(reports[0].comment.contains("/auth/login"));
    assert!(reports[0].comment.contains("website_url"));

    // Subsequent duplicate trap within cooldown should be suppressed
    let duplicate_verdict = pipeline.evaluate_perimeter(&trapped_req);
    assert!(matches!(
        duplicate_verdict,
        ShieldVerdict::Deny(DenialReason::HoneypotTrapped { .. })
    ));

    tokio::time::sleep(Duration::from_millis(50)).await;
    // Count remains 1 due to cooldown governor!
    assert_eq!(mock_transport.get_recorded_reports().len(), 1);
}

#[cfg(feature = "abuse-reporting")]
#[tokio::test]
async fn test_pipeline_abuse_reporting_opt_in_disabled_by_default() {
    let pipeline = ShieldPipeline::builder().build();

    // When abuse reporting feature is enabled but no informant configured, informant() is None
    assert!(pipeline.informant().is_none());
}
