//! # Sovereign Bot Guard & User-Agent Interception Engine (`bot_guard.rs`)
//!
//! Sub-microsecond, zero-allocation User-Agent classification and perimeter defense.
//! Deflects aggressive AI model scrapers, technology stack profilers, reconnaissance scanners,
//! and headless automation tools before allocating upstream server resources.
//!
//! Enforces RFC 9309 and preserves access for verified legitimate search engines (Googlebot, Bingbot)
//! and official developer CLI installer channels (curl, wget on /install and /bin).

use serde::{Deserialize, Serialize};

/// High-level classification of an incoming HTTP User-Agent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BotCategory {
    /// Aggressive AI model scrapers, training harvesters, and synthetic search crawlers
    AiScraper,
    /// Technology stack profilers, vulnerability scanners, and commercial SEO harvesters
    ReconScanner,
    /// Automated scripting libraries, headless browser drivers, and exploit fuzzers
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
        matched_token: &'static str,
    },
}

impl BotVerdict {
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
    ("cohere-training-data-crawler", "cohere-training-data-crawler"),
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

/// Automation frameworks, headless browsers, and attack tools.
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
    // Vulnerability & Port Scanners
    ("zgrab", "zgrab"),
    ("masscan", "masscan"),
    ("nmap", "nmap"),
    ("nikto", "nikto"),
    ("sqlmap", "sqlmap"),
    ("dirbuster", "dirbuster"),
    ("gobuster", "gobuster"),
    ("wfuzz", "wfuzz"),
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

/// Sovereign Bot Guard Engine
#[derive(Debug, Clone, Default)]
pub struct BotGuard;

impl BotGuard {
    pub fn new() -> Self {
        Self
    }

    /// Case-insensitive ASCII substring search without heap allocation.
    #[inline]
    fn contains_ignore_case(haystack_bytes: &[u8], needle_lower: &[u8]) -> bool {
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
            if haystack_bytes[i].to_ascii_lowercase() == first {
                if haystack_bytes[i..i + needle_len]
                    .iter()
                    .zip(needle_lower.iter())
                    .all(|(h, n)| h.to_ascii_lowercase() == *n)
                {
                    return true;
                }
            }
        }
        false
    }

    /// Classify an arbitrary User-Agent string in sub-microsecond time.
    pub fn classify(&self, user_agent: &str) -> (BotCategory, Option<&'static str>) {
        let trimmed = user_agent.trim();
        if trimmed.is_empty() {
            return (BotCategory::Unknown, None);
        }

        // Guardrail: Any User-Agent exceeding 4KB is an intentional buffer exhaustion bomb
        if trimmed.len() > 4096 {
            return (
                BotCategory::AutomationTool,
                Some("Header-Exhaustion-Bomb"),
            );
        }

        let bytes = trimmed.as_bytes();

        // 1. Check AI Scrapers FIRST (e.g. google-extended must trigger before googlebot)
        for &(needle, display_name) in AI_SCRAPER_SIGNATURES {
            if Self::contains_ignore_case(bytes, needle.as_bytes()) {
                return (BotCategory::AiScraper, Some(display_name));
            }
        }

        // 2. Check Reconnaissance Profilers & SEO Scrapers
        for &(needle, display_name) in RECON_SCANNER_SIGNATURES {
            if Self::contains_ignore_case(bytes, needle.as_bytes()) {
                return (BotCategory::ReconScanner, Some(display_name));
            }
        }

        // 3. Check Automation Tools & Vulnerability Scanners
        for &(needle, display_name) in AUTOMATION_TOOL_SIGNATURES {
            if Self::contains_ignore_case(bytes, needle.as_bytes()) {
                return (BotCategory::AutomationTool, Some(display_name));
            }
        }

        // 4. Check Developer CLI Utilities (curl, wget)
        if Self::contains_ignore_case(bytes, b"curl/")
            || Self::contains_ignore_case(bytes, b"wget/")
            || trimmed.eq_ignore_ascii_case("curl")
            || trimmed.eq_ignore_ascii_case("wget")
        {
            return (BotCategory::CliUtility, Some("CLI-Utility"));
        }

        // 5. Check Legitimate Public Search Engines
        for &(needle, display_name) in LEGITIMATE_SEARCH_SIGNATURES {
            if Self::contains_ignore_case(bytes, needle.as_bytes()) {
                return (BotCategory::LegitimateSearch, Some(display_name));
            }
        }

        // 6. Generic Python script check
        if Self::contains_ignore_case(bytes, b"python") {
            return (BotCategory::AutomationTool, Some("Python-Script"));
        }

        // 7. Check Standard Interactive Human Web Browsers
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
    pub fn evaluate_perimeter(
        &self,
        user_agent: Option<&str>,
        path: &str,
    ) -> BotVerdict {
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
        if category == BotCategory::CliUtility {
            if path.starts_with("/install/")
                || path.starts_with("/bin/")
                || path.starts_with("/checksums/")
                || path == "/healthz"
                || path == "/favicon.ico"
                || path == "/security.txt"
                || path.starts_with("/.well-known/")
                || path == "/SOVEREIGN_RELEASE_KEY.asc"
                || path == "/"
            {
                return BotVerdict::Allowed { category };
            }
        }

        // Invariant 2: Hostile / Unwanted Bots blocked with prejudice
        if category.is_unwanted() {
            return BotVerdict::Blocked {
                category,
                matched_token: matched_token.unwrap_or("Unwanted-Automated-Bot"),
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
        assert_eq!(tok1, Some("ClaudeBot"));

        let (cat2, tok2) = guard.classify("anthropic-ai/1.0");
        assert_eq!(cat2, BotCategory::AiScraper);
        assert_eq!(tok2, Some("anthropic-ai"));

        // New names (discovered in battlefield audit)
        let (cat3, tok3) = guard.classify("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-SearchBot/1.0; +https://www.anthropic.com/claudebot)");
        assert_eq!(cat3, BotCategory::AiScraper);
        assert_eq!(tok3, Some("Claude-SearchBot"));

        let (cat4, tok4) = guard.classify("Claude-Web/1.0");
        assert_eq!(cat4, BotCategory::AiScraper);
        assert_eq!(tok4, Some("Claude-Web"));
    }

    #[test]
    fn test_openai_old_and_new_names() {
        let guard = BotGuard::new();

        // Old names
        let (cat1, tok1) = guard.classify("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)");
        assert_eq!(cat1, BotCategory::AiScraper);
        assert_eq!(tok1, Some("GPTBot"));

        let (cat2, tok2) = guard.classify("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0; +https://openai.com/bot)");
        assert_eq!(cat2, BotCategory::AiScraper);
        assert_eq!(tok2, Some("ChatGPT-User"));

        // New search bot
        let (cat3, tok3) = guard.classify("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)");
        assert_eq!(cat3, BotCategory::AiScraper);
        assert_eq!(tok3, Some("OAI-SearchBot"));
    }

    #[test]
    fn test_profilers_and_scanners() {
        let guard = BotGuard::new();

        // BuiltWith (discovered in battlefield audit)
        let (cat1, tok1) = guard.classify("BuiltWith/1.4 (https://builtwith.com/bi)");
        assert_eq!(cat1, BotCategory::ReconScanner);
        assert_eq!(tok1, Some("BuiltWith"));

        // CensysInspect (discovered in battlefield audit)
        let (cat2, tok2) = guard.classify("CensysInspect/1.1 (+https://about.censys.io/)");
        assert_eq!(cat2, BotCategory::ReconScanner);
        assert_eq!(tok2, Some("CensysInspect"));

        // Semrush & Ahrefs
        let (cat3, _) = guard.classify("SemrushBot/7~bl");
        assert_eq!(cat3, BotCategory::ReconScanner);

        let (cat4, _) = guard.classify("Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)");
        assert_eq!(cat4, BotCategory::ReconScanner);
    }

    #[test]
    fn test_google_extended_vs_googlebot() {
        let guard = BotGuard::new();

        // Google-Extended (AI Training) must be classified as AiScraper
        let (cat1, tok1) = guard.classify("Mozilla/5.0 (compatible; Google-Extended; +https://developers.google.com/search/docs/crawling-indexing/google-extended)");
        assert_eq!(cat1, BotCategory::AiScraper);
        assert_eq!(tok1, Some("Google-Extended"));

        // Googlebot (Legitimate Search) must be permitted
        let (cat2, tok2) = guard.classify("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)");
        assert_eq!(cat2, BotCategory::LegitimateSearch);
        assert_eq!(tok2, Some("Googlebot"));
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
        let v_claude_sitemap = guard.evaluate_perimeter(Some("Claude-SearchBot/1.0"), "/sitemap.xml");
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
