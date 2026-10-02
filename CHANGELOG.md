# 📋 Phylax Changelog & Defense Ledger

All notable changes, defense layer releases, and architectural milestones for **Phylax** (`phylax`) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2026-10-01 (Sovereign BotGuard, AI Harvester Interception & RFC 9309 Defense)

### 🌟 Added & Enhanced
* **Sovereign Bot Guard & User-Agent Classification Engine (`src/bot_guard.rs` - Layer 14)**:
  - Sub-microsecond, zero-allocation User-Agent classification engine (`BotGuard`) executing in `<10ns`.
  - Comprehensive canonical signature registry covering both legacy and newly rebranded search/web bots:
    - **Anthropic**: `ClaudeBot`, `anthropic-ai`, `Claude-SearchBot`, `Claude-Web`
    - **OpenAI**: `GPTBot`, `ChatGPT-User`, `OAI-SearchBot`
    - **Google AI**: `Google-Extended` (isolated from legitimate search indexing)
    - **Meta / Apple**: `Meta-ExternalAgent`, `Meta-ExternalFetcher`, `FacebookBot`, `facebookexternalhit`, `Applebot-Extended`
    - **ByteDance / TikTok**: `Bytespider`, `TikTokBot`, `BytespiderBot`
    - **Profilers & Scanners**: `BuiltWith`, `CensysInspect`, `Censys`, `Shodan`, `SemrushBot`, `AhrefsBot`, `DotBot`, `MJ12bot`
    - **Automation & Exploit Tools**: `Scrapy`, `Go-http-client`, `python-requests`, `aiohttp`, `httpx`, `sqlmap`, `nmap`, `nikto`, `masscan`
  - Invariant rules:
    - `/robots.txt` bypass is permanently guaranteed so compliant crawlers discover their exclusions.
    - Developer CLI routes (`/install/*`, `/bin/*`, `/checksums/*`, `/healthz`) permit `curl` & `wget`.
    - Legitimate search engines (`Googlebot`, `Bingbot`, `DuckDuckBot`, `Slurp`, `Baiduspider`, `YandexBot`) are permitted on public storefronts.
* **Adversarial Self-Attack TDD Suite (`tests/adversarial_bot_guard_tests.rs`)**:
  - 7/7 comprehensive red-team test batteries passing in `<0.01s`:
    - Full registry coverage asserting every old and new signature variant.
    - Mixed-case mutations and whitespace padding evasion fuzzing (`cLaUdE-sEaRcHbOt`, `bUiLtWiTh`).
    - Terminal ANSI escape code & CSI/OSC poisoning neutralization.
    - Formula injection (`=cmd|...`) and code execution payload resistance.
    - Null-byte boundary corruptions (`\0`).
    - Header allocation bomb guardrail ($>4\text{KB}$ immediately flagged as buffer exhaustion attacks).
    - Zero false-positive invariant asserting 100% pass-through for legitimate search engines and human browsers.

---

## [0.2.1] - 2026-10-01 (Vendor-Agnostic Threat Intelligence, Dynamic Versioning & Sovereign Packaging)

### 🌟 Added & Enhanced
* **Vendor-Agnostic Threat Intelligence & Incident Sinks (Non-Patching BYOK Architecture)**:
  - Added native Syslog / CEF (Common Event Format) sink (`--syslog-cef`, `syslog_cef = true`) for 100% air-gapped, local SIEM audit logging with zero third-party external HTTP calls.
  - Enhanced generic webhook sink (`--webhook-url`, `--webhook-auth`) with structured JSON dossiers for direct alerting to Datadog, Splunk, Wazuh, Slack, or Discord.
  - Retained AbuseIPDB community sink (`--abuseipdb-key`) with built-in token-bucket rate limiting and 24-hour sliding deduplication cooldown.
  - Unified multi-sink parallel broadcast (`MultiSink`) when multiple destinations are specified.
* **Dynamic Clap CLI Versioning**:
  - Replaced static string literals with dynamic `#[command(version)]` binding directly to `Cargo.toml` (`0.2.1`).
* **Sovereign Release & Cryptographic Packaging Pipeline (`scripts/release.sh`)**:
  - Implemented automated release packaging adhering to `SOVEREIGN-SIGN-01`.
  - Generates SHA-256 digests (`.sha256`, `SHA256SUMS`) and detached OpenPGP Ed25519 signatures (`.asc`, `SHA256SUMS.asc`) using the sovereign release key (`4E428019A109578B`).
* **Clean-Room Distro-Agnostic Installer (`scripts/install.sh` & `scripts/install.ps1`)**:
  - Dynamic release tag discovery resolving `v*` tag names on GitHub Releases with zero-API-rate-limit redirect inspection.
  - Automatic download and installation of analytics suite (`phylax-analyze-traffic`, `phylax-threat-recon`) even during curl-piped one-liner executions without git cloning.
* **Agnostic Threat Reconnaissance Toolkit (`phylax-threat-recon`)**:
  - Added `--webhook <URL>` support for automated incident reporting to custom endpoints.
  - Auto-discovers credentials from `.env`, `.bashrc`, and `phylax.toml`.
  - Scrubbed machine-specific paths; supports standard `/var/log` paths and sovereign project roots.
* **Adversarial Test Assertions (`POC TDD+++++`)**:
  - 114/114 core unit, integration, and active defense tests passing in `< 0.15s`.
  - Verified on Buffalo NAS KVM VM (`citadel-vm1`) clean-room environment.
* **Cross-Platform Windows IOCP Engine & PowerShell 5.1/Core Hardening**:
  - Validated native compilation for `x86_64-pc-windows-gnu` PE32+ 64-bit binaries.
  - Executed automated 7-test verification suite on Windows Server 2022 KVM VM (`citadel-win1`):
    - Sub-microsecond microbenchmark on Windows: Honeypot validation `8.74 ns`, total perimeter evaluation `1005.09 ns` (> 994,000 req/sec/core).
    - In-memory Radix IP CIDR subnet blocking validated (`193.189.100.1` blocked by `193.189.100.0/24`).
  - Hardened `phylax-analyze-traffic.ps1` and `phylax-threat-recon.ps1` for PowerShell 5.1 ANSI (Windows-1252) parser compatibility by enforcing 7-bit ASCII status tokens, explicit positional parameter bindings (`Position = 0`), and `-f` format strings, eliminating emoji byte sequence parsing exceptions on legacy Windows PowerShell engines while preserving 100% parity on PowerShell Core 7+.

---

## [0.2.0] - 2026-09-28 (Sovereign Observability & Red-Team Suite)

### 🌟 Added
* **Cross-Platform Analytics & Threat Recon Suite (`tools/analytics/`)**:
  - Implemented 100% feature-parity red-team and traffic intelligence tools across POSIX `/bin/sh` and PowerShell Core (`.ps1`).
  - Added `phylax-analyze-traffic` with Native Sovereign Context Auto-Discovery ("Royalty Mode") for auto-detecting SQLite WAL, journalctl, and application log stores across `rmediatech`, `matrix`, `propylea`, and standalone systems.
  - Added `phylax-threat-recon` for autonomous IP threat correlation, multi-subnet anomaly detection, and AbuseIPDB reputation auditing.
* **Automated Red-Team Fuzzing Battery (`tools/redteam_script_fuzzer/`)**:
  - Enforced Adversarial Self-Attack invariant validating telemetry scripts against ANSI escape sequence injection, ReDoS patterns, shell injection payloads, and symlink traversals.
* **Cryptographic Provenance Release Signing (`SOVEREIGN-SIGN-01`)**:
  - Published Ed25519 sovereign public release key (`SOVEREIGN_RELEASE_KEY.asc`, Key ID: `4E428019A109578B`).
  - Automated detached GPG signature generation (`.asc`) and SHA-256 manifests across distributed releases.
* **Closed-Loop Zero-Day Threat Harvester (Layer 13)**:
  - Added mathematical clustering over anomalous `404` probe paths across distinct IPv4 subnets.
  - Autonomous elevation from passive tracking into in-memory active decoy trie.

---

## [0.1.0] - 2026-09-16 (13-Layer Sovereign Edge Defense Engine)

### 🌟 Added
* **13-Layer In-Memory Defense Engine**:
  - **Layer 1 (CIDR Blocklist)**: Radix IP trie evaluating millions of hostile IPv4/IPv6 ranges in `< 25ns`.
  - **Layer 2 (Allowlist / Fast Path)**: Microsecond whitelist bypass for known trusted internal IPs and loopback.
  - **Layer 3 (HTTP Method Gate)**: Rejection of non-standard and dangerous HTTP verbs.
  - **Layer 4 (Protocol Strictness)**: Enforces RFC HTTP compliance and header sanitization.
  - **Layer 5 (Host Header Alignment)**: Rejection of forged Host headers and direct IP scanning.
  - **Layer 6 (Header Hygiene)**: Stripping suspicious hop-by-hop headers and proxy injection attempts.
  - **Layer 7 (User-Agent Bot Classifier)**: Sub-microsecond regex and token classifier intercepting headless scrapers, vulnerability scanners, and AI crawling bots.
  - **Layer 8 (Honeypot Decoy Fields)**: Invisible HTML traps (`website_url`, `company_fax`) that trigger immediate bot deflection upon population.
  - **Layer 9 (Decoy Path Prefix Trie)**: Nanosecond interception of scanning paths (`/.env`, `/wp-admin`, `/.git/config`) returning stealth `404 Not Found`.
  - **Layer 10 (Dynamic Latency Token Guard)**: Cryptographically enforces human cognitive interaction delays ($\ge 1.5$s) using HMAC-SHA256 tokens.
  - **Layer 11 (Quadratic Adaptive PoW)**: Progressive client-side CPU Proof-of-Work challenge scaling quadratically for repeat offenders.
  - **Layer 12 (Reverse Slowloris Tarpit)**: Asynchronous slow-trickle socket hostage mode exhausting bot connection pools with zero server CPU overhead.
  - **Layer 13 (Threat Harvester & Collaborative Abuse Reporting)**:
    - Asynchronous event dispatcher submitting forensic incident dossiers to **AbuseIPDB** v2 API under strict token-bucket rate limits.
* **Coturn WebRTC Relay Guard (`TurnGuard`)**:
  - Cryptographic session-bound ephemeral credentials preventing unauthorized WebRTC TURN relay bandwidth theft.
* **Axum & Hyper Middleware Integrations**:
  - Zero-allocation Axum middleware layers for seamless drop-in protection in Rust web services.
