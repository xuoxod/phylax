# Chapter 6: Production Deployment & Runbook

> **Namespace:** `phylax::ops`  
> **Previous:** [05: Autonomous Abuse Intelligence](05_AUTONOMOUS_ABUSE_INTELLIGENCE.md) | **Return:** [Master Index](INDEX.md)

---

## 1. Hardware Sizing & Capacity Planning

Because `phylax` executes zero-allocation bitwise comparisons and radix tree lookups in memory, its compute and RAM requirements are exceptionally minimal:

| Deployment Tier | Daily Request Volume | Recommended vCPU | RAM Allocation | Deployment Topology |
|---|---|---|---|---|
| **Starter / Edge Node** | Up to 5,000,000 req/day | 1 vCPU (AMD/Intel) | `256 MB` | Embedded inside Axum/Actix binary |
| **Enterprise SFU Cluster** | 50,000,000+ req/day | 2 – 4 vCPUs | `512 MB – 1 GB` | Embedded across application workers |
| **Standalone Proxy Gate** | 100,000,000+ req/day | 4 – 8 vCPUs | `1 GB – 2 GB` | Standalone `phylax serve` WAF daemon |

---

## 2. Reverse Proxy Integration (Caddy & Nginx)

When deploying behind a frontend TLS terminator such as **Caddy**, ensure client IP headers are correctly propagated:

### Caddyfile Configuration (`/etc/caddy/Caddyfile`)

```caddyfile
app.example.com {
    encode zstd gzip

    # Preserve real client IP for Phylax edge evaluation
    header {
        X-Real-IP {remote_host}
        X-Forwarded-For {remote_host}
    }

    # Proxy to Phylax-protected Axum backend
    reverse_proxy 127.0.0.1:3000 {
        header_up Host {host}
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

---

## 3. Systemd Service Unit (Standalone WAF Mode)

When running `phylax` as a standalone reverse proxy daemon in `/usr/local/bin/phylax`:

Create `/etc/systemd/system/phylax.service`:

```ini
[Unit]
Description=Phylax Sovereign Edge Defense Proxy Daemon
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=phylax
Group=phylax
ExecStart=/usr/local/bin/phylax serve --config /etc/phylax/phylax.toml
Restart=always
RestartSec=3s
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

# Security Sandboxing
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/phylax /etc/phylax
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now phylax.service
sudo systemctl status phylax.service
```

---

## 4. Verification & Testing Runbook

### Test 1: Verify Stealth Deception Black Hole
Send a registration request containing a non-empty decoy honeypot field (`website_url`):

```bash
$ curl -i -X POST http://127.0.0.1:3000/api/auth/register \
       -H "Content-Type: application/json" \
       -d '{"username":"bot_tester","email":"bot@test.com","website_url":"http://malicious.xyz"}'

HTTP/1.1 201 Created
Content-Type: application/json

{"status":"SUCCESS","user_id":0,"uuid":"usr_stealth_trap","message":"Account created successfully."}
```
✅ **Expected Behavior:** Returns `201 Created`. Zero database rows are inserted, and the IP is logged/quarantined in memory.

### Test 2: Verify Perimeter Ghosting (404 Drop)
Send a probe from a quarantined IP or simulated hostile subnet:

```bash
$ curl -i http://127.0.0.1:3000/api/auth/register \
       -H "X-Forwarded-For: 185.220.101.5"

HTTP/1.1 404 Not Found
Content-Type: text/plain

404 Not Found
```
✅ **Expected Behavior:** Returns generic `404 Not Found`. The attacker cannot detect firewall presence.

### Test 3: Solve PoW Challenge Client-Side
Issue a challenge and compute the valid SHA-256 nonce using the CLI:

```bash
# 1. Issue challenge
$ phylax challenge --difficulty 12
{"challenge":"...","difficulty":12,"expires_at":...}

# 2. Solve challenge
$ phylax solve --seed "<CHALLENGE_SEED>" --difficulty 12
Solved puzzle in 4.2ms. Nonce: 38291
```

---

## 5. Epilogue: The Sovereign Security Manifesto

The modern web does not need heavier middleboxes, invasive cloud proxies, or external data brokers inspecting private packets.

By embedding mathematically sound, cost-hierarchical defenses directly into modern compiled systems (Rust), application authors regain complete sovereignty over:
- **Their Users' Privacy**: Zero telemetry leaks to third-party ad/tracking networks.
- **Their Application Latency**: Sub-microsecond edge evaluation preserving real-time audio, video, and WebSocket performance.
- **Their Defense Posture**: Active stealth deception that turns attackers' automation against themselves.

`phylax` stands watch.

---

[← Return to Master Index](INDEX.md)
