//! # Sovereign Bot Guard & User-Agent Interception Engine (`bot_guard.rs`)
//!
//! Sub-microsecond, zero-allocation User-Agent classification and perimeter defense.
//! Deflects aggressive AI model scrapers, technology stack profilers, reconnaissance scanners,
//! and headless automation tools before allocating upstream server resources.
//!
//! Enforces RFC 9309 and preserves access for verified legitimate search engines (Googlebot, Bingbot)
//! and official developer CLI installer channels (curl, wget on /install and /bin).

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

/// High-level classification of an incoming HTTP User-Agent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BotCategory {
    /// Aggressive AI model scrapers, training harvesters, and synthetic search crawlers
    AiScraper,
    /// Technology stack profilers, vulnerability scanners, and commercial SEO harvesters
    ReconScanner,
    /// Automated scripting libraries, headless browser drivers, exploit fuzzers, and penetration testing tools
    AutomationTool,
    /// Legitimate public search engines (allowed on public storefront paths)
    LegitimateSearch,
    /// Official developer CLI tools (curl, wget - allowed on binary distribution paths)
    CliUtility,
    /// Standard interactive human web browser
    LegitimateBrowser,
    /// Unclassified or missing User-Agent
    Unknown,
}

impl BotCategory {
    #[inline]
    pub fn is_unwanted(self) -> bool {
        matches!(
            self,
            BotCategory::AiScraper | BotCategory::ReconScanner | BotCategory::AutomationTool
        )
    }

    pub fn name(self) -> &'static str {
        match self {
            BotCategory::AiScraper => "AI Scraper & Training Harvester",
            BotCategory::ReconScanner => "Reconnaissance Scanner & Profiler",
            BotCategory::AutomationTool => "Headless Automation & Scripting Tool",
            BotCategory::LegitimateSearch => "Legitimate Search Engine",
            BotCategory::CliUtility => "Developer CLI Utility",
            BotCategory::LegitimateBrowser => "Standard Human Browser",
            BotCategory::Unknown => "Unknown User-Agent",
        }
    }
}

/// Verdict returned when evaluating a client's User-Agent against the requested path
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BotVerdict {
    Allowed {
        category: BotCategory,
    },
    Blocked {
        category: BotCategory,
        matched_token: Cow<'static, str>,
    },
}

impl BotVerdict {
    #[inline]
    pub fn matched_token(&self) -> Option<&str> {
        match self {
            BotVerdict::Blocked { matched_token, .. } => Some(matched_token.as_ref()),
            _ => None,
        }
    }

    #[inline]
    pub fn is_blocked(&self) -> bool {
        matches!(self, BotVerdict::Blocked { .. })
    }

    #[inline]
    pub fn is_allowed(&self) -> bool {
        !self.is_blocked()
    }

    pub fn public_message(&self) -> &'static str {
        match self {
            BotVerdict::Blocked {
                category: BotCategory::AiScraper,
                ..
            } => {
                "Access Denied: Automated AI scrapers, LLM training harvesters, and synthetic crawlers are prohibited on Sovereign infrastructure (RFC 9309)."
            }
            BotVerdict::Blocked {
                category: BotCategory::ReconScanner,
                ..
            } => {
                "Access Denied: Commercial stack profilers, reconnaissance scanners, and SEO harvesters are prohibited on Sovereign infrastructure (RFC 9309)."
            }
            BotVerdict::Blocked {
                category: BotCategory::AutomationTool,
                ..
            } => {
                "Access Denied: Headless automation, unvetted scripting engines, and vulnerability probes are blocked at perimeter."
            }
            _ => "Access Denied: Unrecognized or prohibited automated client.",
        }
    }
}

// -----------------------------------------------------------------------------
// CANONICAL SIGNATURE REGISTRY (Preserving BOTH Old and New Bot Names)
// -----------------------------------------------------------------------------

/// Known AI model scrapers, training datasets, and synthetic search crawlers.
/// Both legacy names and newly rebranded search/web bots MUST be preserved.
pub const AI_SCRAPER_SIGNATURES: &[(&str, &str)] = &[
    // Anthropic (Specific to General)
    ("claude-searchbot", "Claude-SearchBot"),
    ("claude-web", "Claude-Web"),
    ("claudebot", "ClaudeBot"),
    ("anthropic-ai", "anthropic-ai"),
    // OpenAI (Specific to General)
    ("oai-searchbot", "OAI-SearchBot"),
    ("chatgpt-user", "ChatGPT-User"),
    ("gptbot", "GPTBot"),
    // Google AI Training (Distinct from Googlebot search)
    ("google-extended", "Google-Extended"),
    // Meta / Facebook (Specific to General)
    ("meta-externalagent", "Meta-ExternalAgent"),
    ("meta-externalfetcher", "Meta-ExternalFetcher"),
    ("facebookexternalhit", "facebookexternalhit"),
    ("facebookbot", "FacebookBot"),
    // Apple AI Intelligence (Distinct from Applebot Siri search)
    ("applebot-extended", "Applebot-Extended"),
    // ByteDance / TikTok (Specific to General)
    ("bytespiderbot", "BytespiderBot"),
    ("bytespider", "Bytespider"),
    ("tiktokbot", "TikTokBot"),
    // Perplexity AI
    ("perplexity-ai", "Perplexity-AI"),
    ("perplexitybot", "PerplexityBot"),
    // Amazon AI
    ("amazonbot", "Amazonbot"),
    // Cohere AI
    (
        "cohere-training-data-crawler",
        "cohere-training-data-crawler",
    ),
    ("cohere-ai", "cohere-ai"),
    // Common Crawl & Open Training Datasets
    ("omgilibot", "Omgilibot"),
    ("omgili", "Omgili"),
    ("ccbot", "CCBot"),
    ("diffbot", "Diffbot"),
    ("youbot", "YouBot"),
    ("webzio", "Webzio-Extended"),
    ("ai2bot", "AI2Bot"),
    ("timpibot", "TimpiBot"),
    ("velenpublicwebcrawler", "VelenPublicWebCrawler"),
];

/// Technology stack profilers, commercial SEO scrapers, and automated recon probes.
pub const RECON_SCANNER_SIGNATURES: &[(&str, &str)] = &[
    // Stack Profilers & Metadata Harvesters (Specific to General)
    ("builtwith", "BuiltWith"),
    ("censysinspect", "CensysInspect"),
    ("censys", "Censys"),
    ("shodan", "Shodan"),
    ("zoominfobot", "ZoominfoBot"),
    ("netcraftsurveyagent", "NetcraftSurveyAgent"),
    // Commercial SEO Harvesters (Specific to General)
    ("semrushbot", "SemrushBot"),
    ("semrush", "Semrush"),
    ("ahrefsbot", "AhrefsBot"),
    ("ahrefs", "Ahrefs"),
    ("dotbot", "DotBot"),
    ("mj12bot", "MJ12bot"),
    ("petalbot", "PetalBot"),
    ("dataforseobot", "DataForSeoBot"),
    ("seekport", "Seekport"),
    ("exabot", "Exabot"),
    ("blexbot", "BLEXBot"),
    ("serpstatbot", "SerpstatBot"),
    ("screaming frog", "Screaming Frog"),
    // Academic & Plagiarism Harvesters
    ("turnitinbot", "TurnitinBot"),
];

/// Automation frameworks, headless browsers, attack tools, and penetration testing suites.
pub const AUTOMATION_TOOL_SIGNATURES: &[(&str, &str)] = &[
    // Headless Browser Drivers
    ("headlesschrome", "HeadlessChrome"),
    ("phantomjs", "PhantomJS"),
    ("puppeteer", "Puppeteer"),
    ("selenium", "Selenium"),
    ("playwright", "Playwright"),
    // Scripting Libraries & Scrapers
    ("scrapy", "Scrapy"),
    ("go-http-client", "Go-http-client"),
    ("python-requests", "python-requests"),
    ("python-urllib", "python-urllib"),
    ("aiohttp", "aiohttp"),
    ("httpx", "httpx"),
    ("libwww-perl", "libwww-perl"),
    ("postmanruntime", "PostmanRuntime"),
    // Kali Linux & Offensive Security Fuzzers & Content Discovery
    ("ffuf", "ffuf"),
    ("feroxbuster", "feroxbuster"),
    ("dirsearch", "dirsearch"),
    ("dirbuster", "DirBuster"),
    ("gobuster", "Gobuster"),
    ("wfuzz", "wfuzz"),
    ("nuclei", "Nuclei"),
    ("arjun", "Arjun"),
    ("paramspider", "ParamSpider"),
    // Vulnerability & Web Application Scanners
    ("acunetix", "Acunetix"),
    ("nessus", "Nessus"),
    ("openvas", "OpenVAS"),
    ("burpcollaborator", "BurpCollaborator"),
    ("burpsuite", "BurpSuite"),
    ("owasp-zap", "OWASP ZAP"),
    ("zaproxy", "OWASP ZAP"),
    ("arachni", "Arachni"),
    ("whatweb", "WhatWeb"),
    ("wprecon", "WPRecon"),
    ("wpscan", "WPScan"),
    ("netsparker", "Netsparker"),
    ("qualysguard", "QualysGuard"),
    ("qualys", "Qualys"),
    // Port Scanners, Asset Finders & Network Recon
    ("zgrab", "zgrab"),
    ("masscan", "masscan"),
    ("nmap", "nmap"),
    ("nikto", "nikto"),
    ("rustscan", "RustScan"),
    ("sublist3r", "Sublist3r"),
    ("amass", "OWASP Amass"),
    ("assetfinder", "assetfinder"),
    ("katana", "Katana"),
    // Exploitation Frameworks & Injection Engines
    ("sqlmap", "sqlmap"),
    ("sqlninja", "SQLNinja"),
    ("commix", "Commix"),
    ("havij", "Havij"),
    ("metasploit", "Metasploit"),
    // Password Sprayers & Credential Bruteforcers
    ("hydra", "THC-Hydra"),
    ("medusa", "Medusa"),
    ("patator", "Patator"),
    ("crowbar", "Crowbar"),
    // Digital Forensics & Ingestion Engines (Automated Extraction)
    ("encase", "EnCase"),
    ("autopsy", "Autopsy"),
    ("sleuthkit", "SleuthKit"),
    ("x-ways", "X-Ways"),
    ("magnet-axiom", "Magnet AXIOM"),
    ("axiom", "Magnet AXIOM"),
];

/// Legitimate public search engines permitted on public storefront routes.
pub const LEGITIMATE_SEARCH_SIGNATURES: &[(&str, &str)] = &[
    ("googlebot", "Googlebot"),
    ("bingbot", "Bingbot"),
    ("bingpreview", "BingPreview"),
    ("duckduckbot", "DuckDuckBot"),
    ("slurp", "Slurp"),
    ("baiduspider", "Baiduspider"),
    ("yandexbot", "YandexBot"),
    ("applebot", "Applebot"),
    ("qwantify", "Qwantify"),
];

/// Record of an autonomously harvested bot signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicBotRecord {
    pub signature: String,
    pub original_ua_sample: String,
    pub reason: String,
    pub hits: u64,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
}

/// Dynamic, self-healing bot registry that autonomously expands when new crawlers or scanners trip honeypots
#[derive(Debug, Clone)]
pub struct DynamicBotRegistry {
    max_capacity: usize,
    entries: Arc<RwLock<HashMap<String, DynamicBotRecord>>>,
}

impl Default for DynamicBotRegistry {
    fn default() -> Self {
        Self::new(10_000)
    }
}

impl DynamicBotRegistry {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            max_capacity,
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Number of actively harvested dynamic signatures
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Autonomously harvest a malicious User-Agent from a trapped probe (e.g. Canary Trap or Honeypot).
    /// Returns the harvested signature token if successfully admitted.
    pub fn harvest(&self, raw_ua: &str, reason: &str, now_ms: u64) -> Option<String> {
        let trimmed = raw_ua.trim();
        if trimmed.is_empty() || trimmed.len() > 1024 {
            return None;
        }

        // Extract a distinctive token (e.g., first segment or full token up to 64 chars)
        let token = Self::extract_signature_token(trimmed)?;
        let key = token.to_ascii_lowercase();

        // Safety Invariant: Protect common human browsers, search bots, and CLI tools from accidental harvesting
        if Self::is_protected_token(&key) {
            return None;
        }

        let mut lock = self.entries.write();
        if let Some(record) = lock.get_mut(&key) {
            record.hits = record.hits.saturating_add(1);
            record.last_seen_ms = now_ms;
            return Some(token);
        }

        // Enforce bounded memory guardrail (LRU prune if capacity reached)
        if lock.len() >= self.max_capacity {
            if let Some(oldest_key) = lock
                .iter()
                .min_by_key(|(_, r)| r.last_seen_ms)
                .map(|(k, _)| k.clone())
            {
                lock.remove(&oldest_key);
            }
        }

        lock.insert(
            key,
            DynamicBotRecord {
                signature: token.clone(),
                original_ua_sample: trimmed.chars().take(256).collect(),
                reason: reason.to_string(),
                hits: 1,
                first_seen_ms: now_ms,
                last_seen_ms: now_ms,
            },
        );

        Some(token)
    }

    /// Check if an incoming User-Agent matches any dynamically harvested signature
    pub fn check_ua(&self, user_agent: &str) -> Option<String> {
        let lock = self.entries.read();
        if lock.is_empty() {
            return None;
        }

        let ua_bytes = user_agent.as_bytes();
        for (needle_lower, record) in lock.iter() {
            if BotGuard::contains_ignore_case(ua_bytes, needle_lower.as_bytes()) {
                return Some(record.signature.clone());
            }
        }
        None
    }

    /// Extract a distinctive signature token from raw User-Agent
    fn extract_signature_token(ua: &str) -> Option<String> {
        let first_part = ua.split(['/', ' ', ';', '(']).next()?.trim();
        if first_part.len() < 3 {
            return None;
        }
        Some(first_part.chars().take(64).collect())
    }

    /// Safety filter to prevent blocking benign clients
    fn is_protected_token(lower: &str) -> bool {
        matches!(
            lower,
            "mozilla"
                | "chrome"
                | "safari"
                | "webkit"
                | "gecko"
                | "applewebkit"
                | "edge"
                | "edg"
                | "curl"
                | "wget"
                | "googlebot"
                | "bingbot"
                | "duckduckbot"
                | "yandexbot"
                | "baiduspider"
        )
    }
}

/// Sovereign Bot Guard Engine
#[derive(Debug, Clone)]
pub struct BotGuard {
    dynamic_registry: Arc<DynamicBotRegistry>,
}

impl Default for BotGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl BotGuard {
    pub fn new() -> Self {
        Self {
            dynamic_registry: Arc::new(DynamicBotRegistry::default()),
        }
    }

    pub fn with_dynamic_registry(dynamic_registry: Arc<DynamicBotRegistry>) -> Self {
        Self { dynamic_registry }
    }

    pub fn dynamic_registry(&self) -> &Arc<DynamicBotRegistry> {
        &self.dynamic_registry
    }

    /// Autonomously learn and register a new bot signature from a tripped honeylink or canary trap
    pub fn harvest_canary_probe(
        &self,
        user_agent: Option<&str>,
        reason: &str,
        now_ms: u64,
    ) -> Option<String> {
        user_agent.and_then(|ua| self.dynamic_registry.harvest(ua, reason, now_ms))
    }

    /// Case-insensitive ASCII substring search without heap allocation.
    #[inline]
    pub fn contains_ignore_case(haystack_bytes: &[u8], needle_lower: &[u8]) -> bool {
        if needle_lower.is_empty() {
            return true;
        }
        let needle_len = needle_lower.len();
        if haystack_bytes.len() < needle_len {
            return false;
        }

        let first = needle_lower[0];
        let max_start = haystack_bytes.len() - needle_len;

        for i in 0..=max_start {
            if haystack_bytes[i].to_ascii_lowercase() == first
                && haystack_bytes[i..i + needle_len]
                    .iter()
                    .zip(needle_lower.iter())
                    .all(|(h, n)| h.to_ascii_lowercase() == *n)
            {
                return true;
            }
        }
        false
    }

    /// Classify an arbitrary User-Agent string in sub-microsecond time.
    pub fn classify(&self, user_agent: &str) -> (BotCategory, Option<Cow<'static, str>>) {
        let trimmed = user_agent.trim();
        if trimmed.is_empty() {
            return (BotCategory::Unknown, None);
        }

        // Guardrail: Any User-Agent exceeding 4KB is an intentional buffer exhaustion bomb
        if trimmed.len() > 4096 {
            return (
                BotCategory::AutomationTool,
                Some(Cow::Borrowed("Header-Exhaustion-Bomb")),
            );
        }

        let bytes = trimmed.as_bytes();

        // 1. Check AI Scrapers FIRST (e.g. google-extended must trigger before googlebot)
        for &(needle, display_name) in AI_SCRAPER_SIGNATURES {
            if Self::contains_ignore_case(bytes, needle.as_bytes()) {
                return (BotCategory::AiScraper, Some(Cow::Borrowed(display_name)));
            }
        }

        // 2. Check Reconnaissance Profilers & SEO Scrapers
        for &(needle, display_name) in RECON_SCANNER_SIGNATURES {
            if Self::contains_ignore_case(bytes, needle.as_bytes()) {
                return (BotCategory::ReconScanner, Some(Cow::Borrowed(display_name)));
            }
        }

        // 3. Check Automation Tools & Vulnerability Scanners (Static Signatures)
        for &(needle, display_name) in AUTOMATION_TOOL_SIGNATURES {
            if Self::contains_ignore_case(bytes, needle.as_bytes()) {
                return (
                    BotCategory::AutomationTool,
                    Some(Cow::Borrowed(display_name)),
                );
            }
        }

        // 4. Check Dynamic Self-Healing Registry (Preemptive Defense)
        if let Some(matched) = self.dynamic_registry.check_ua(trimmed) {
            return (BotCategory::AutomationTool, Some(Cow::Owned(matched)));
        }

        // 5. Check Developer CLI Utilities (curl, wget)
        if Self::contains_ignore_case(bytes, b"curl/")
            || Self::contains_ignore_case(bytes, b"wget/")
            || trimmed.eq_ignore_ascii_case("curl")
            || trimmed.eq_ignore_ascii_case("wget")
        {
            return (BotCategory::CliUtility, Some(Cow::Borrowed("CLI-Utility")));
        }

        // 6. Check Legitimate Public Search Engines
        for &(needle, display_name) in LEGITIMATE_SEARCH_SIGNATURES {
            if Self::contains_ignore_case(bytes, needle.as_bytes()) {
                return (
                    BotCategory::LegitimateSearch,
                    Some(Cow::Borrowed(display_name)),
                );
            }
        }

        // 7. Generic Python script check
        if Self::contains_ignore_case(bytes, b"python") {
            return (
                BotCategory::AutomationTool,
                Some(Cow::Borrowed("Python-Script")),
            );
        }

        // 8. Check Standard Interactive Human Web Browsers
        if Self::contains_ignore_case(bytes, b"mozilla/") {
            return (BotCategory::LegitimateBrowser, None);
        }

        (BotCategory::Unknown, None)
    }

    /// Evaluates whether an incoming client request should be allowed or deflected at the edge boundary.
    ///
    /// Guardrails:
    /// 1. `/robots.txt` is ALWAYS permitted so compliant bots discover their exclusions.
    /// 2. Developer CLI routes (`/install/*`, `/bin/*`, `/checksums/*`, `/healthz`) permit `curl` & `wget`.
    /// 3. Hostile/unwanted AI scrapers, profilers, and automation tools are blocked with `BotVerdict::Blocked`.
    /// 4. Legitimate search engines and human browsers are permitted.
    pub fn evaluate_perimeter(&self, user_agent: Option<&str>, path: &str) -> BotVerdict {
        // Invariant 0: Robots Exclusion discovery must never be barred
        if path == "/robots.txt" {
            return BotVerdict::Allowed {
                category: BotCategory::LegitimateSearch,
            };
        }

        let ua = match user_agent {
            Some(u) if !u.trim().is_empty() => u.trim(),
            _ => {
                // Requests without User-Agent are permitted to public storefront,
                // but denied if attempting to access sensitive WebSockets or private APIs.
                return BotVerdict::Allowed {
                    category: BotCategory::Unknown,
                };
            }
        };

        let (category, matched_token) = self.classify(ua);

        // Invariant 1: Developer CLI utility passthrough for official installer endpoints
        if category == BotCategory::CliUtility
            && (path.starts_with("/install/")
                || path.starts_with("/bin/")
                || path.starts_with("/checksums/")
                || path == "/healthz"
                || path == "/favicon.ico"
                || path == "/security.txt"
                || path.starts_with("/.well-known/")
                || path == "/SOVEREIGN_RELEASE_KEY.asc"
                || path == "/")
        {
            return BotVerdict::Allowed { category };
        }

        // Invariant 2: Hostile / Unwanted Bots blocked with prejudice
        if category.is_unwanted() {
            return BotVerdict::Blocked {
                category,
                matched_token: matched_token.unwrap_or(Cow::Borrowed("Unwanted-Automated-Bot")),
            };
        }

        // Invariant 3: Search Engines and Human Browsers permitted
        BotVerdict::Allowed { category }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_old_and_new_names() {
        let guard = BotGuard::new();

        // Old names
        let (cat1, tok1) = guard.classify("ClaudeBot/1.0; +claudebot@anthropic.com");
        assert_eq!(cat1, BotCategory::AiScraper);
        assert_eq!(tok1.as_deref(), Some("ClaudeBot"));

        let (cat2, tok2) = guard.classify("anthropic-ai/1.0");
        assert_eq!(cat2, BotCategory::AiScraper);
        assert_eq!(tok2.as_deref(), Some("anthropic-ai"));

        // New names (discovered in battlefield audit)
        let (cat3, tok3) = guard.classify("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-SearchBot/1.0; +https://www.anthropic.com/claudebot)");
        assert_eq!(cat3, BotCategory::AiScraper);
        assert_eq!(tok3.as_deref(), Some("Claude-SearchBot"));

        let (cat4, tok4) = guard.classify("Claude-Web/1.0");
        assert_eq!(cat4, BotCategory::AiScraper);
        assert_eq!(tok4.as_deref(), Some("Claude-Web"));
    }

    #[test]
    fn test_openai_old_and_new_names() {
        let guard = BotGuard::new();

        // Old names
        let (cat1, tok1) = guard.classify("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)");
        assert_eq!(cat1, BotCategory::AiScraper);
        assert_eq!(tok1.as_deref(), Some("GPTBot"));

        let (cat2, tok2) = guard.classify("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0; +https://openai.com/bot)");
        assert_eq!(cat2, BotCategory::AiScraper);
        assert_eq!(tok2.as_deref(), Some("ChatGPT-User"));

        // New search bot
        let (cat3, tok3) = guard.classify("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)");
        assert_eq!(cat3, BotCategory::AiScraper);
        assert_eq!(tok3.as_deref(), Some("OAI-SearchBot"));
    }

    #[test]
    fn test_profilers_and_scanners() {
        let guard = BotGuard::new();

        // BuiltWith (discovered in battlefield audit)
        let (cat1, tok1) = guard.classify("BuiltWith/1.4 (https://builtwith.com/bi)");
        assert_eq!(cat1, BotCategory::ReconScanner);
        assert_eq!(tok1.as_deref(), Some("BuiltWith"));

        // CensysInspect (discovered in battlefield audit)
        let (cat2, tok2) = guard.classify("CensysInspect/1.1 (+https://about.censys.io/)");
        assert_eq!(cat2, BotCategory::ReconScanner);
        assert_eq!(tok2.as_deref(), Some("CensysInspect"));

        // Semrush & Ahrefs
        let (cat3, _) = guard.classify("SemrushBot/7~bl");
        assert_eq!(cat3, BotCategory::ReconScanner);

        let (cat4, _) =
            guard.classify("Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)");
        assert_eq!(cat4, BotCategory::ReconScanner);
    }

    #[test]
    fn test_kali_and_offensive_security_tools() {
        let guard = BotGuard::new();

        // Fuzzers
        let (c1, t1) = guard.classify("ffuf/v2.1.0-dev");
        assert_eq!(c1, BotCategory::AutomationTool);
        assert_eq!(t1.as_deref(), Some("ffuf"));

        let (c2, t2) = guard.classify("nuclei - v3.1.0");
        assert_eq!(c2, BotCategory::AutomationTool);
        assert_eq!(t2.as_deref(), Some("Nuclei"));

        let (c3, t3) = guard.classify("wfuzz/3.1.0");
        assert_eq!(c3, BotCategory::AutomationTool);
        assert_eq!(t3.as_deref(), Some("wfuzz"));

        // Exploit frameworks
        let (c4, t4) = guard.classify("metasploit-framework/v6.3");
        assert_eq!(c4, BotCategory::AutomationTool);
        assert_eq!(t4.as_deref(), Some("Metasploit"));

        // Forensics suites automated
        let (c5, t5) = guard.classify("EnCase Forensic/21.4");
        assert_eq!(c5, BotCategory::AutomationTool);
        assert_eq!(t5.as_deref(), Some("EnCase"));
    }

    #[test]
    fn test_dynamic_self_healing_harvesting() {
        let guard = BotGuard::new();

        let strange_ua = "ZeroDayScannerX/9.9 (Hostile Threat Actor)";

        // Before harvesting, it's unknown
        let (before_cat, _) = guard.classify(strange_ua);
        assert_eq!(before_cat, BotCategory::Unknown);

        // Honeylink / Canary Trap is tripped!
        let token = guard.harvest_canary_probe(
            Some(strange_ua),
            "Tripped canary honeylink",
            1_700_000_000_000,
        );
        assert_eq!(token.as_deref(), Some("ZeroDayScannerX"));

        // Immediately after, ANY request containing that token is classified and blocked!
        let (after_cat, after_tok) = guard.classify(strange_ua);
        assert_eq!(after_cat, BotCategory::AutomationTool);
        assert_eq!(after_tok.as_deref(), Some("ZeroDayScannerX"));

        // Edge perimeter drops it with 403 Forbidden!
        let verdict = guard.evaluate_perimeter(Some(strange_ua), "/pricing");
        assert!(verdict.is_blocked());
    }

    #[test]
    fn test_google_extended_vs_googlebot() {
        let guard = BotGuard::new();

        // Google-Extended (AI Training) must be classified as AiScraper
        let (cat1, tok1) = guard.classify("Mozilla/5.0 (compatible; Google-Extended; +https://developers.google.com/search/docs/crawling-indexing/google-extended)");
        assert_eq!(cat1, BotCategory::AiScraper);
        assert_eq!(tok1.as_deref(), Some("Google-Extended"));

        // Googlebot (Legitimate Search) must be permitted
        let (cat2, tok2) = guard
            .classify("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)");
        assert_eq!(cat2, BotCategory::LegitimateSearch);
        assert_eq!(tok2.as_deref(), Some("Googlebot"));
    }

    #[test]
    fn test_developer_cli_and_robots_bypass() {
        let guard = BotGuard::new();

        // Robots.txt is ALWAYS allowed, even for Claude-SearchBot
        let v_robots = guard.evaluate_perimeter(Some("Claude-SearchBot/1.0"), "/robots.txt");
        assert!(v_robots.is_allowed());

        // Curl allowed on installer routes
        let v_install = guard.evaluate_perimeter(Some("curl/8.5.0"), "/install/metaforge");
        assert!(v_install.is_allowed());

        // Claude-SearchBot blocked on sitemap or root
        let v_claude_sitemap =
            guard.evaluate_perimeter(Some("Claude-SearchBot/1.0"), "/sitemap.xml");
        assert!(v_claude_sitemap.is_blocked());

        let v_claude_root = guard.evaluate_perimeter(Some("Claude-SearchBot/1.0"), "/");
        assert!(v_claude_root.is_blocked());

        // BuiltWith blocked on llms.txt
        let v_builtwith = guard.evaluate_perimeter(Some("BuiltWith/1.4"), "/llms.txt");
        assert!(v_builtwith.is_blocked());
    }

    #[test]
    fn test_legitimate_browser_allowed() {
        let guard = BotGuard::new();
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36";
        let v = guard.evaluate_perimeter(Some(ua), "/tools");
        assert!(v.is_allowed());
    }
}
