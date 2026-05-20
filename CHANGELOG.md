# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.4] - 2026-05-20

### Fixed
- Performance collector RX-bytes parser: `/proc/net/dev` lines have a space after the `iface:` label on modern kernels, so the previous `parts[0].substring(colonIdx + 1)` returned `""` and `rxBps` was always `0`. Now reads `parts[1]` directly when the label ends in `:`. Effect: `network_rx_bps` anomaly detection finally works.
- Network totals no longer double/triple-count container traffic. Added `isVirtualInterface()` filter for `veth*`, `docker*`, `br-*`, `cni*`, `cali*`, `flannel*`, `weave*`, `kube-*` (was: `lo` only). On hosts running Docker, total `network_tx_bps` previously counted the same byte through veth → docker0 → eth0; sum now reflects actual link utilization.
- Anomaly detector no longer emits inverse alerts for `journal_errors` and `kernel_errors`. Added `INCREASE_ONLY_METRICS` directional gate — drops below the mean (system getting quieter) are no longer treated as anomalies. The σ statistic is still computed for debug logs; only the alert emission is gated.

## [3.0.3] - 2026-05-20

### Fixed
- `/health` endpoint now reports the actual `package.json` version (was hardcoded to `2.1.0`); same source feeds the `guardian_start` audit log.
- FIM and SSH-keys collectors no longer log spurious "collection failed via SSH" warns when the remote shell loop ends on an unreadable file (e.g. `/etc/shadow` for non-root users). The remote command now ends with `; exit 0`, so partial reads are returned via stdout instead of being discarded by `execFile` on non-zero exit.
- KEV ingest switched from `cisa.gov/sites/default/files/feeds/...` (Akamai-blocked from datacenter IPs, returns HTTP 403) to the official GitHub mirror at `cisagov/kev-data`. A descriptive `User-Agent` header is also sent.

## [1.0.0] - 2026-05-03

### Added
- Plugin architecture for extensible notifications
- Multi-channel notifications: Telegram, Discord, Slack, WhatsApp, Email, ntfy, Webhook
- Mini dashboard with HTMX (server-side rendered, zero JS build)
- SQLite support for zero-config homelab deployment
- CVE monitor with OSV.dev integration and interactive approval
- Centralized constants configuration
- Docker one-liner deployment
- GitHub Actions CI/CD pipeline
- AGPLv3 license

### Changed
- Refactored from private tool to standalone open-source project
- Telegram integration moved to plugin system
- All workers now use NotifierManager for delivery

### Removed
- AutomaBotHub integration (all related code removed)
- Hardcoded Telegram-only notification paths
