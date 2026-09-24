//! # Layer 13: Autonomous Threat Harvester Adversarial TDD Suite
//!
//! Rigorous adversarial attack simulations verifying:
//! 1. Mathematical multi-subnet correlation (sybil & cache-pollution defense).
//! 2. Single-IP / single-subnet dictionary-fuzzing containment.
//! 3. IPv6 /48 boundary enforcement against address rotation within an ISP allocation.
//! 4. Autonomous elevation into `DecoyUriSentinel` and immediate L0.5 interception.
//! 5. CISA KEV / MITRE CVE bulk intelligence catalog ingestion.
//! 6. Sliding time-window decay and memory hygiene under `MaintenanceManager`.

use phylax::decoy_uri::{DecoyCategory, DecoyUriSentinel, DecoyUriVerdict};
use phylax::pipeline::{DenialReason, ShieldPipeline, ShieldRequest, ShieldVerdict};
use phylax::threat_harvester::{SubnetKey, ThreatHarvesterConfig, ThreatHarvesterEngine};
use std::net::IpAddr;

#[test]
fn test_adversarial_single_ip_fuzzing_flood_contained() {
    let sentinel = DecoyUriSentinel::default();
    let config = ThreatHarvesterConfig {
        promotion_subnet_threshold: 3,
        max_paths_per_subnet: 10,
        max_tracked_candidates: 100,
        window_duration_ms: 3_600_000,
        enabled: true,
    };
    let harvester = ThreatHarvesterEngine::new(config, sentinel.clone());
    let attacker_ip: IpAddr = "198.51.100.44".parse().unwrap();
    let now = 1_000_000;

    // Attacker fires 500 distinct randomized paths from the same IP / subnet
    for i in 0..500 {
        let fuzz_path = format!("/fuzz_exploit_candidate_{:04}", i);
        let verdict = harvester.ingest_anomalous_uri(&fuzz_path, attacker_ip, now + i as u64);
        assert!(
            verdict.is_none(),
            "Single IP must never promote any candidate path"
        );
    }

    // Subnet quota must strictly cap tracked candidates at 10 to prevent memory exhaustion
    assert_eq!(
        harvester.candidate_count(),
        10,
        "Subnet quota must clamp tracked candidates from single hostile subnet"
    );

    // None of the fuzzed paths must be registered in the active trap trie
    for i in 0..500 {
        let fuzz_path = format!("/fuzz_exploit_candidate_{:04}", i);
        assert!(
            !sentinel.contains_trap(&fuzz_path),
            "Fuzzed paths must not pollute active trap catalog"
        );
    }
}

#[test]
fn test_adversarial_distributed_zero_day_campaign_autonomous_elevation() {
    let sentinel = DecoyUriSentinel::default();
    let config = ThreatHarvesterConfig {
        promotion_subnet_threshold: 3,
        window_duration_ms: 3_600_000,
        max_tracked_candidates: 1_000,
        max_paths_per_subnet: 25,
        enabled: true,
    };
    let harvester = ThreatHarvesterEngine::new(config, sentinel.clone());

    let zero_day_probe = "/wp-content/plugins/zero-day-cms/upload_shell.php";
    assert!(!sentinel.contains_trap(zero_day_probe));

    let now = 2_000_000;

    // Node 1: Attacker from Subnet 1 (185.220.101.0/24 - Tor exit)
    let ip1: IpAddr = "185.220.101.5".parse().unwrap();
    let res1 = harvester.ingest_anomalous_uri(zero_day_probe, ip1, now);
    assert!(res1.is_none());
    assert!(!sentinel.contains_trap(zero_day_probe));

    // Node 2: Attacker from Subnet 2 (194.26.29.0/24 - Bulletproof host)
    let ip2: IpAddr = "194.26.29.12".parse().unwrap();
    let res2 = harvester.ingest_anomalous_uri(zero_day_probe, ip2, now + 100);
    assert!(res2.is_none());
    assert!(!sentinel.contains_trap(zero_day_probe));

    // Same subnet as Node 2 repeating the attack (194.26.29.99) -> Does NOT increment subnet count
    let ip2_repeat: IpAddr = "194.26.29.99".parse().unwrap();
    let res2_repeat = harvester.ingest_anomalous_uri(zero_day_probe, ip2_repeat, now + 200);
    assert!(
        res2_repeat.is_none(),
        "Same subnet must not fulfill multi-subnet threshold"
    );

    // Node 3: Attacker from Subnet 3 (45.154.255.0/24 - Datacenter proxy) -> 3rd Distinct Subnet!
    let ip3: IpAddr = "45.154.255.8".parse().unwrap();
    let promotion = harvester
        .ingest_anomalous_uri(zero_day_probe, ip3, now + 300)
        .expect("Coordinated attack across 3 distinct subnets must trigger autonomous promotion");

    assert_eq!(promotion.path, zero_day_probe);
    assert_eq!(promotion.distinct_subnets, 3);
    assert_eq!(promotion.total_hits, 4); // ip1, ip2, ip2_repeat, ip3
    assert_eq!(promotion.category, DecoyCategory::AdminCmsProbe);

    // Trap is now active in DecoyUriSentinel!
    assert!(sentinel.contains_trap(zero_day_probe));

    // Subsequent evaluation of any incoming request on this newly discovered honeyroute is caught in sub-microsecond time
    let verdict = sentinel.evaluate(zero_day_probe);
    match verdict {
        DecoyUriVerdict::Trapped {
            matched_path,
            category,
        } => {
            assert_eq!(matched_path, zero_day_probe);
            assert_eq!(category, DecoyCategory::AdminCmsProbe);
        }
        _ => panic!("Promoted path must immediately trap incoming probes"),
    }
}

#[test]
fn test_adversarial_ipv6_subnet_rotation_spoof_defeated() {
    let sentinel = DecoyUriSentinel::default();
    let config = ThreatHarvesterConfig {
        promotion_subnet_threshold: 3,
        ..Default::default()
    };
    let harvester = ThreatHarvesterEngine::new(config, sentinel.clone());
    let zero_day_path = "/mesh-internal/gateway/routes/refresh";

    // Hostile bot operates a full IPv6 /64 or /56 subnet allocation (e.g., 2001:db8:cafe::/48)
    // Rotating through millions of arbitrary IPv6 addresses inside its allocated /48
    let bot_ip_1: IpAddr = "2001:db8:cafe:0001:0000:0000:0000:0001".parse().unwrap();
    let bot_ip_2: IpAddr = "2001:db8:cafe:0002:aaaa:bbbb:cccc:dddd".parse().unwrap();
    let bot_ip_3: IpAddr = "2001:db8:cafe:ffff:1234:5678:9abc:def0".parse().unwrap();

    assert_eq!(
        SubnetKey::from_ip(bot_ip_1),
        SubnetKey::from_ip(bot_ip_2),
        "Same /48 IPv6 subnet prefix must match"
    );
    assert_eq!(
        SubnetKey::from_ip(bot_ip_1),
        SubnetKey::from_ip(bot_ip_3),
        "Same /48 IPv6 subnet prefix must match"
    );

    let now = 3_000_000;
    assert!(harvester.ingest_anomalous_uri(zero_day_path, bot_ip_1, now).is_none());
    assert!(harvester.ingest_anomalous_uri(zero_day_path, bot_ip_2, now + 10).is_none());
    assert!(harvester.ingest_anomalous_uri(zero_day_path, bot_ip_3, now + 20).is_none());

    // Still only 1 subnet observed
    assert!(!sentinel.contains_trap(zero_day_path));
    let candidate = harvester.get_candidate(zero_day_path).unwrap();
    assert_eq!(candidate.participating_subnets.len(), 1);
    assert_eq!(candidate.hit_count, 3);

    // Two legitimately separate IPv6 networks hit it (e.g. 2001:db8:beef::/48 and 2600:1f18:4567::/48)
    let remote_ip_2: IpAddr = "2001:db8:beef:0001::5".parse().unwrap();
    let remote_ip_3: IpAddr = "2600:1f18:4567:0002::9".parse().unwrap();

    assert!(harvester.ingest_anomalous_uri(zero_day_path, remote_ip_2, now + 30).is_none());
    let promotion = harvester.ingest_anomalous_uri(zero_day_path, remote_ip_3, now + 40);

    assert!(promotion.is_some(), "3 distinct /48 IPv6 blocks must successfully promote path");
    assert!(sentinel.contains_trap(zero_day_path));
}

#[test]
fn test_cisa_kev_mitre_cve_catalog_ingestion_and_interception() {
    let sentinel = DecoyUriSentinel::default();
    let harvester = ThreatHarvesterEngine::new(ThreatHarvesterConfig::default(), sentinel.clone());

    // Curated high-impact CVE exploitation endpoints
    let cve_catalog = [
        // CVE-2023-4966: Citrix Bleed memory disclosure
        ("/oauth/v20/token", DecoyCategory::Custom),
        // CVE-2022-22965: Spring4Shell RCE
        ("/helloworld/greeting", DecoyCategory::AdminCmsProbe),
        // CVE-2023-38606: Mobile / Webkit Zero-Click exploit stage
        ("/api/stage2/payload.bin", DecoyCategory::Custom),
        // CVE-2021-44228: Log4j JNDI probe
        ("/api/v1/search/jndi", DecoyCategory::Custom),
    ];

    let ingested = harvester.ingest_bulk_cve_catalog(&cve_catalog);
    assert_eq!(ingested, 4);

    for (cve_path, _) in &cve_catalog {
        assert!(
            sentinel.contains_trap(cve_path),
            "Ingested CVE path '{}' must be active trap",
            cve_path
        );
        match sentinel.evaluate(cve_path) {
            DecoyUriVerdict::Trapped { matched_path, .. } => {
                assert_eq!(matched_path, *cve_path);
            }
            _ => panic!("CVE path must trap immediately"),
        }
    }
}

#[test]
fn test_sliding_window_decay_and_maintenance_hygiene() {
    let sentinel = DecoyUriSentinel::default();
    let config = ThreatHarvesterConfig {
        promotion_subnet_threshold: 3,
        window_duration_ms: 60_000, // 60 seconds
        max_tracked_candidates: 50,
        max_paths_per_subnet: 10,
        enabled: true,
    };
    let harvester = ThreatHarvesterEngine::new(config, sentinel.clone());

    let pipeline = ShieldPipeline::builder()
        .with_threat_harvester(harvester.config().clone())
        .build();

    let now = 10_000_000;
    let ip1: IpAddr = "192.0.2.1".parse().unwrap();
    let ip2: IpAddr = "198.51.100.2".parse().unwrap();

    // 2 subnets hit a path at t=10,000,000
    pipeline.record_anomalous_uri("/temporary_candidate", ip1, now);
    pipeline.record_anomalous_uri("/temporary_candidate", ip2, now);
    assert_eq!(pipeline.threat_harvester().candidate_count(), 1);

    // Maintenance pass at t+30s (window still active)
    let report_mid = pipeline.run_maintenance(now + 30_000);
    assert_eq!(report_mid.threat_candidates_pruned, 0);
    assert_eq!(report_mid.active_threat_candidates, 1);

    // Maintenance pass at t+65s (window expired for inactive candidate)
    let report_expired = pipeline.run_maintenance(now + 65_000);
    assert_eq!(report_expired.threat_candidates_pruned, 1);
    assert_eq!(report_expired.active_threat_candidates, 0);
    assert_eq!(pipeline.threat_harvester().candidate_count(), 0);
}

#[test]
fn test_shield_pipeline_end_to_end_zero_day_harvesting_and_containment() {
    let pipeline = ShieldPipeline::builder()
        .with_quarantine(phylax::autonomous_quarantine::QuarantineConfig {
            infraction_threshold: 1,
            ..Default::default()
        })
        .with_threat_harvester(ThreatHarvesterConfig {
            promotion_subnet_threshold: 2, // 2 subnets for agile test promotion
            window_duration_ms: 100_000,
            ..Default::default()
        })
        .build();

    let zero_day_route = "/api/internal/debug_console.php";
    let now = 5_000_000;

    // Normal genuine traffic passes unimpeded
    let clean_req = ShieldRequest {
        client_ip: "203.0.113.19",
        target_uri: Some("/products/electronics"),
        now_ms: now,
        ..Default::default()
    };
    assert!(pipeline.evaluate_perimeter(&clean_req).is_allowed());

    // Threat actor from subnet 1 probes the zero-day path
    let promotion_1 = pipeline.record_anomalous_uri_str(zero_day_route, "198.51.100.10", now);
    assert!(promotion_1.is_none());

    // Threat actor from subnet 2 probes the zero-day path -> Correlated!
    let promotion_2 = pipeline.record_anomalous_uri_str(zero_day_route, "203.0.113.88", now + 50);
    assert!(promotion_2.is_some(), "2 distinct subnets must promote path");

    // From this moment on, ANY attacker from ANY IP hitting the promoted zero-day path is trapped at Layer 0.5!
    let attacker_req = ShieldRequest {
        client_ip: "45.33.32.1",
        target_uri: Some(zero_day_route),
        now_ms: now + 100,
        ..Default::default()
    };

    let verdict = pipeline.evaluate_perimeter(&attacker_req);
    match verdict {
        ShieldVerdict::Deny(DenialReason::DecoyUriTrapped { path, category }) => {
            assert_eq!(path, zero_day_route);
            assert_eq!(category, DecoyCategory::AdminCmsProbe.name());
        }
        other => panic!("Expected DecoyUriTrapped, got: {:?}", other),
    }

    // Attacker IP 45.33.32.1 was automatically quarantined and ratcheted in adaptive PoW!
    assert!(pipeline.quarantine().is_quarantined("45.33.32.1", now + 100));
}
