# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
