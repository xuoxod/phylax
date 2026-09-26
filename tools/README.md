# 🛡️ Phylax Sovereign Analytics & Observability Suite

> **Sovereign Ecosystem Standard:** Directive 7 (`GEMINI.md`)  
> **Architecture:** Zero-dependency, pure POSIX `/bin/sh` + Native PowerShell Core (`.ps1`).  
> **Security Invariant:** Defensively hardened against log poisoning, ANSI escape terminal hijacking, command injection, and ReDoS buffer attacks.

---

## 🌟 Overview & Duality Architecture

The Phylax Analytics Suite operates in two seamless operational modes:

1. **Universal Agnostic Mode:** Ingests any standard access log, combined web log, or JSON stream via pipe or file argument. Runs on Linux (Musl/Glibc), macOS, FreeBSD, Solaris/illumos, and Windows.
2. **Native Sovereign Auto-Discovery ("Royalty Mode"):** When executed within a Sovereign Ecosystem project (`rmediatech`, `matrix`, `propylea`, `phylax`) without arguments, it automatically discovers local logs, databases, and telemetry stores to deliver instant forensic intelligence.

---

## 🚀 Quickstart & Usage

### 1. POSIX Shell (`phylax-analyze-traffic.sh`)

```bash
# Ingest live piped stream (e.g. journalctl or log tail)
journalctl -u rmediatech -n 200 --no-pager | phylax-analyze-traffic.sh

# Analyze a specific access log file
./tools/analytics/phylax-analyze-traffic.sh /var/log/access.log

# Emit structured JSON for piping into jq or alerts
cat /var/log/access.log | phylax-analyze-traffic.sh --json | jq .
```

### 2. Windows / PowerShell Core (`phylax-analyze-traffic.ps1`)

```powershell
# Analyze log file
.\tools\analytics\phylax-analyze-traffic.ps1 -InputPath C:\logs\access.log

# Pipe stream & output JSON
Get-Content C:\logs\access.log | .\tools\analytics\phylax-analyze-traffic.ps1 -Json
```

---

## 🧠 Intelligence & Gap Discovery

The analyzer doesn't just calculate status codes; it extracts strategic insights:

* **Latency Profiling:** Upstream microsecond execution times and averages.
* **404 Market Demand Discovery:** Differentiates between hostile vulnerability scanners (WordPress, Spring Actuators, Truffle Web3 secret probes) and **🔥 Potential Market Demand / Missing APIs** where users or integrators are seeking unbuilt endpoints (e.g., `/api/v1/stream`, `/sdk`).
* **Multi-Subnet Ingress Correlation:** Groups hostile and legitimate traffic by IPv4 `/24` and IPv6 `/48` CIDR blocks.

---

## 🧪 Testing & Adversarial Verification

All scripts must pass both standard TDD verification and adversarial self-attack fuzzing:

```bash
# Run the POC TDD Test Suite (file, pipe, JSON schema, category assertions)
./tools/tests/test_analytics.sh

# Run the Adversarial Red-Team Fuzzer (command injection, ANSI escapes, quote breakouts, 100KB ReDoS)
./tools/tests/redteam_fuzzer.sh
```
