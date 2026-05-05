# Guardian Auto-Discovery Engine — Design Spec

**Date:** 2026-05-05
**Status:** Approved
**Goal:** AI-driven system that probes server environments and auto-configures Guardian to adapt to any architecture — at install time AND when connecting to monitored servers.

---

## Overview

Guardian Auto-Discovery is a unified TypeScript module (`src/discovery/`) that:
1. Executes deep scans of server environments (local or via SSH)
2. Sends the structured snapshot to a Cloud LLM (Gemini)
3. Receives an architecture-aware configuration recommendation
4. Presents results to the user for confirmation before applying

## When Discovery Runs

| Trigger | Context | Transport |
|---------|---------|-----------|
| `install.sh` | Local server being set up | Local shell |
| `/add-server` (Telegram) | Remote server being added to monitoring | SSH |
| Periodic re-discovery (24h) | Existing monitored servers | SSH |

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                 src/discovery/                          │
├────────────────────────────────────────────────────────┤
│                                                        │
│  Entry Points:                                         │
│  • cli.ts (install.sh --local)                         │
│  • remote.ts (add-server via SSH)                      │
│                                                        │
│  Core:                                                 │
│  • probes/ (5 probe categories)                        │
│  • aggregator.ts (merge → ServerSnapshot)              │
│  • analyzer.ts (Gemini prompt + Zod validation)        │
│  • config-generator.ts (snapshot → .env + yml)         │
│  • presenter.ts (terminal + Telegram display)          │
│                                                        │
└────────────────────────────────────────────────────────┘
```

## Deep Scan Probes

### 1. Network Probe (`probes/network.ts`)
- SSH port detection (`ss -tlnp | grep ssh`)
- All listening ports and services (`ss -tlnp`)
- Network interfaces and IPs (`ip addr`)
- DNS configuration (`/etc/resolv.conf`)
- Hostname and domain

### 2. Reverse Proxy Probe (`probes/proxy.ts`)
- Traefik: Docker container, labels, static/dynamic config
- Nginx: `nginx -t`, sites-enabled, upstream configs
- Caddy: `caddy validate`, Caddyfile
- HAProxy: `haproxy -c`, config file
- SSL certificates: Let's Encrypt paths, expiry dates
- Configured domains

### 3. Docker Probe (`probes/docker.ts`)
- Docker/Podman version and runtime
- Running containers (`docker ps --format json`)
- Networks (`docker network ls`)
- Volumes (`docker volume ls`)
- Compose files found on system
- Images present

### 4. Security Probe (`probes/security.ts`)
- Firewall: iptables rules, nftables, ufw status
- fail2ban: active jails, recent bans
- SELinux/AppArmor status
- SSH config: PermitRootLogin, PasswordAuth, Port
- Users with shell access (`/etc/passwd` filtered)
- Sudo configuration
- Cron jobs (global + per-user)

### 5. System Probe (`probes/system.ts`)
- OS and version (`/etc/os-release`)
- Kernel version (`uname -a`)
- CPU/RAM/Disk (`lscpu`, `free -m`, `df -h`)
- Installed packages (apt/dnf/apk list --installed)
- Active systemd services
- Uptime and load average
- Recent logs: auth.log (last 50 logins), syslog (last 100 entries)

### Probe Execution
- Each probe has individual 10s timeout
- Total scan timeout: 120s
- Probes run in parallel where possible
- Each probe reports `{ success: boolean, data: {...}, error?: string, durationMs: number }`
- Partial failures are acceptable — AI analyzes with whatever data is available

## AI Analysis

### Prompt Design

The complete ServerSnapshot JSON is sent to Gemini with a structured system prompt:

```
You are an expert DevOps engineer. Analyze this server snapshot and generate
the optimal configuration for Guardian Blue Team SIEM.

Rules:
1. If Traefik detected → configure Guardian as service in same network with labels
2. If Nginx detected → generate server block or upstream config
3. If SSH on non-standard port → set HOST_SSH_PORT accordingly
4. If fail2ban active → integrate with jail monitoring
5. If Docker present → mount /var/run/docker.sock
6. Adapt HEALTHCHECK to available tools (wget vs curl)
7. Generate .env with all detected values filled
8. Generate docker-compose.yml adapted to found architecture
9. If no Docker on server → generate systemd unit file instead
```

### Response Schema (Zod-enforced)

```typescript
interface DiscoveryResult {
  summary: string;
  architecture: "traefik-docker" | "nginx-standalone" | "nginx-docker" |
                "caddy" | "haproxy" | "bare-metal" | "unknown";
  confidence: number; // 0-100
  
  env: Record<string, string>;
  dockerCompose?: string;
  systemdUnit?: string;
  proxyConfig?: string; // nginx/caddy block to add
  
  warnings: string[];
  recommendations: string[];
  
  monitoringProfile: {
    services: string[];
    logPaths: string[];
    criticalPorts: number[];
    customChecks: string[];
  };
}
```

### Fallback
- If Gemini fails or response doesn't validate: use heuristic templates
- Heuristic templates: pre-built configs for common architectures (Traefik, Nginx, Caddy, bare-metal)
- Always works, just less "smart" about edge cases

## Presentation

### Terminal (install.sh)

Box-formatted display showing:
- Server summary (OS, architecture, SSH port, proxy, containers)
- Confidence percentage
- Warnings (security issues found)
- Config summary (how many env vars, which compose variant)
- Actions: [V]iew full config, [A]pply, [E]dit first, [Q]uit

### Telegram (/add-server)

Markdown message with:
- Server summary
- Monitoring profile (services, logs, ports)
- Warnings
- Inline buttons: [Approve] [Edit] [Cancel]

## Integration Flows

### install.sh

```
1. Banner display
2. Prompt for Gemini API key (or detect from env var)
3. Clone Guardian repo
4. npm install (probe dependencies)
5. Execute: npx tsx src/discovery/cli.ts --local --api-key=$KEY
   → Run all 5 probes locally (parallel)
   → Aggregate into ServerSnapshot
   → Send to Gemini for analysis
   → Receive DiscoveryResult
6. Present results, ask for confirmation
7. If approved:
   → Write .env (with discovered values)
   → Write docker-compose.yml (adapted to architecture)
   → docker compose up -d
8. Post-install: health check + Telegram test notification
```

### /add-server (Telegram)

```
1. User: /add-server <ip> -p <port> -u <user>
2. Test SSH connection
3. Execute all 5 probes via SSH (parallel)
4. Aggregate into ServerSnapshot
5. Send to Gemini for analysis
6. Generate monitoring profile
7. Present results in Telegram
8. User approves → server added to monitoring rotation
```

### Re-discovery (periodic, every 24h)

```
1. For each monitored server:
   → Execute probes via SSH
   → Compare with last known snapshot
2. If significant change detected:
   → New container appeared
   → Proxy configuration changed
   → New port exposed
   → Service stopped/started
3. Notify via Telegram with diff
4. Do NOT auto-apply changes — require user approval
```

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Probe timeout (10s) | Mark probe as failed, continue with others |
| Total scan timeout (120s) | Abort remaining probes, analyze partial data |
| Gemini API timeout (30s) | Retry 1x, then fall back to heuristics |
| Gemini response invalid | Fall back to heuristic templates |
| SSH connection failure | Report error, suggest checking credentials |
| No Docker on server | Generate systemd unit instead of compose |
| Confidence < 70% | Extra warning in presentation, suggest manual review |
| Apply failure | Rollback to `.env.bak` / `docker-compose.yml.bak` |

## File Structure

```
src/discovery/
├── cli.ts                  # Entry point for install.sh (local scan)
├── remote.ts               # Entry point for add-server (SSH scan)
├── types.ts                # ServerSnapshot, DiscoveryResult, ProbeResult types
├── aggregator.ts           # Merge probe results into ServerSnapshot
├── analyzer.ts             # Send to Gemini, validate response, fallback
├── config-generator.ts     # DiscoveryResult → .env + docker-compose.yml
├── presenter.ts            # Terminal box + Telegram message formatting
├── templates/              # Heuristic fallback templates
│   ├── traefik.yml
│   ├── nginx.yml
│   ├── caddy.yml
│   ├── bare-metal.yml
│   └── systemd.service
└── probes/
    ├── index.ts            # Parallel probe runner
    ├── network.ts          # Port scanning, interfaces, DNS
    ├── proxy.ts            # Reverse proxy detection
    ├── docker.ts           # Container runtime detection
    ├── security.ts         # Firewall, fail2ban, SSH config
    └── system.ts           # OS, packages, services, logs
```

## Security Considerations

- Probe data may contain sensitive info (users, firewall rules) — never log raw snapshots
- Gemini API call sends server info to Google — document this in install flow
- SSH keys are never included in snapshot
- Passwords/tokens in .env are never sent to AI — only structural data
- Re-discovery diffs are sanitized before Telegram display

## Dependencies

- `ssh2` — SSH connection for remote probes (already used by host-security.service)
- Gemini API — already configured in Guardian
- No new external dependencies required

## Out of Scope (future)

- Auto-remediation (auto-fix security issues found)
- Multi-cloud provider detection (AWS/GCP/Azure metadata)
- Kubernetes/Swarm cluster discovery
- Network topology mapping between multiple servers
