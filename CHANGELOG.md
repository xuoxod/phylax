# 📋 Phylax Changelog & Defense Ledger

All notable changes, defense layer releases, and architectural milestones for **Phylax** (`phylax`) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-10-01 (Threat Reconnaissance Hardening & Production Tooling)

### 🌟 Added & Enhanced
* **Production Build & Deployment Tooling (`Makefile` & `scripts/install.sh`)**:
  - Added centralized `Makefile` supporting `build`, `release`, `test`, `test-analytics`, and `install` targets.
  - Enhanced `scripts/install.sh` to install both the core `phylax` CLI engine and the cross-platform analytics suite (`phylax-analyze-traffic`, `phylax-threat-recon`) to `~/.local/bin`.
* **Host Journalctl Auto-Discovery & Resilient Piping**:
  - Implemented automatic fallback to host `journalctl -u propylea.service` and system log facilities in `phylax-analyze-traffic` when explicit file paths are omitted.
  - Added non-blocking FIFO/pipe detection preventing hang states during piped standard input processing.
* **Autonomous AbuseIPDB Forensics (`phylax-threat-recon`)**:
  - Integrated real-time IP reputation checks, score caching, and threat vector correlation directly into the analytics toolkit.
* **Adversarial Test Assertions**:
  - Verified 51/51 core unit tests, 4/4 POC TDD analytics tests, and 4/4 red-team fuzzer vectors.

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
