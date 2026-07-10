# Roadmap Guardian

Última atualização: 2026-05-31

## Tier 0 — Blast radius reduction (NOVO, supersede Tier 1 anterior)

Status: 🟡 aguardando autorização do usuário (2026-05-29)
Estimativa: 6-8h

- [ ] Schema: tabela `install_tokens` + colunas em `soc_servers` (`host_fingerprint`, `install_method`, `os_family`)
- [ ] `guardian-shell` Python wrapper em `/usr/local/sbin/guardian-shell` com allowlist regex
- [ ] Bootstrap script generator (`src/discovery/install.ts`)
- [ ] Endpoint `/install/:token` no dashboard
- [ ] SSH collector ajustado: `StrictHostKeyChecking=yes` + fingerprint pinned + comando via wrapper
- [ ] Heartbeat worker — alerta se servidor silenciar > 5min
- [ ] UI dashboard `add-server.html`: comando curl|bash + box pra fingerprint
- [ ] Compatibilidade legacy preservada (`install_method='legacy'`)
- [ ] Testar end-to-end em servidor de teste

**Decisões já tomadas:**
- Ubuntu 22.04+/Debian 12+ como primário (RHEL/Fedora best-effort com OS detection)
- Rsyslog push em tempo real adiado pra v2 (heartbeat sozinho cobre 80%)
- Usar `GUARDIAN_BASE_URL` existente (HTTPS) pra servir install script
- Append-only triggers no PostgreSQL adiado pra v2

## Tier 1 — Auth/IP fixes (round 1, 1-2h)

Status: ✅ concluído (2026-05-29, commit 8d3acea)

- [x] CIDR helper `isPrivateIp()` em `src/utils/sanitize.ts` — cobre RFC1918 + loopback + link-local + IPv6 ULA
- [x] `/webhook/telegram` fail-closed — responde 503 se `TELEGRAM_WEBHOOK_SECRET` ausente
- [x] `/health`: version leak removido

## Tier 2 — Firewall correctness (round 1, 3-4h)

Status: ✅ concluído (2026-05-29/30, commits c6a85b3 + 3fd7320)

- [x] Chain `GUARDIAN-INPUT` dedicada com jump em INPUT pos 1 — `iptables -F INPUT` do operador não apaga mais regras Guardian
- [x] Rate-limit inserido em `GUARDIAN-INPUT` (não em INPUT cru); aborta se chain não puder ser criada
- [x] `block-ip.ts`: 3º fallback `tryIptables` após fail2ban + UFW falharem; `BlockMethod` exportado e propagado pelos 4 callsites
- [x] **SYN flood**: escalação rate-limit → block permanente removida (srcIP spoofável = risco de self-DoS em DNS público); rate-limit local em `GUARDIAN-INPUT` mantido
- [x] Probe `-S` frágil removido de `iptables-chain.ts` — vai direto para `-N` (idempotente, tolerante a race e a iptables-nft/legacy coexistência)

## Tier 3 — Parsing/observabilidade (round 2)

Status: ⚪ não iniciado

- [ ] Detectar OS no `/add-server` e ramificar log path (auth.log vs secure vs journalctl)
- [ ] Contador de "linhas não-reconhecidas" no normalizer (Prometheus metric)
- [ ] Validar IP no normalize, não só no block
- [ ] `runMulti`: usar `;` ou comandos separados quando saída parcial importa
- [ ] Container process: parsear por header em vez de posição (`[, , cpu, , command, ...]` é frágil)

## Tier 4 — Doc/auth consistency (round 1)

Status: ⚪ não iniciado

- [ ] Alinhar README "always permanent" com default 24h em `block-ip.ts`
- [ ] Log error em `getBlockedIps`
- [ ] Migrar dashboard tokens pra httpOnly cookie + Authorization header
- [ ] Postgres password: env obrigatório (sem fallback `:-guardian_secret`)

## Documentação (paralelo aos tiers)

Status: 🟡 estrutura aprovada 2026-05-29, conteúdo aguardando

- [ ] README PT atualizado com features faltantes (noise reduction, IP threat ML, threat hunter, DGA, Markov, STL, CVE feeds, block propagation, multi-AI cascade, modelo de instalação)
- [ ] README EN atualizado em paralelo
- [ ] `docs/pt/00-introducao.md`
- [ ] `docs/pt/instalacao/01-pre-requisitos.md`
- [ ] `docs/pt/instalacao/02-primeira-instalacao.md`
- [ ] `docs/pt/instalacao/03-variaveis-ambiente.md`
- [ ] `docs/pt/instalacao/04-adicionar-servidor.md` (depende de Tier 0 estar pronto)
- [ ] `docs/pt/instalacao/05-telegram-setup.md`
- [ ] `docs/pt/operacao/01-dashboard-tour.md`
- [ ] `docs/pt/operacao/02-lendo-alertas.md`
- [ ] `docs/pt/operacao/03-respondendo-incidente.md`
- [ ] `docs/pt/operacao/04-bloqueios-manuais.md`
- [ ] `docs/pt/operacao/05-comandos-telegram.md`
- [ ] `docs/pt/operacao/06-relatorio-diario.md`
- [ ] `docs/pt/arquitetura/01-visao-geral.md`
- [ ] `docs/pt/arquitetura/02-pipeline-detalhado.md`
- [ ] `docs/pt/arquitetura/03-workers.md`
- [ ] `docs/pt/arquitetura/04-intelligence.md`
- [ ] `docs/pt/arquitetura/05-ai-providers.md`
- [ ] `docs/pt/arquitetura/06-database.md`
- [ ] `docs/pt/arquitetura/07-noise-reduction.md`
- [ ] `docs/pt/arquitetura/08-modelo-de-seguranca.md`
- [ ] `docs/pt/avancado/01-criar-playbook.md`
- [ ] `docs/pt/avancado/02-criar-notifier.md`
- [ ] `docs/pt/avancado/03-detection-rules.md`
- [ ] `docs/pt/avancado/04-treinar-ml.md`
- [ ] `docs/pt/avancado/05-postgresql-prod.md`
- [ ] `docs/pt/faq.md`
- [ ] `docs/pt/troubleshooting.md`
- [ ] Tradução EN completa

## Histórico (recent done)

- 2026-05-30: Tier 2 round 2 — iptables-chain -S probe removido (fix Debian 12 / iptables-nft coexistência)
- 2026-05-29: Tier 2 round 1 — GUARDIAN-INPUT chain + SYN-flood escalation drop + iptables 3rd fallback
- 2026-05-29: Tier 1 — CIDR helper, webhook fail-closed, /health version leak
- 2026-05-29: v3.1.0 deployed em prod
- 2026-05-29: discovery_baselines DB-backed (substitui Map em memória)
- 2026-05-29: verifyBlock signature retorna `{verified, method}`
- 2026-05-29: 4 rows backfilled em blocked_ips com `method='ufw'`
- 2026-05-28: container security detail + AI analysis + mobile scroll + threat hunter
- 2026-05-28: geo-attacks always includes dangerous IPs
- 2026-05-28: ONNX IP classifier treinado + Alpine/musl onnxruntime fix
- 2026-05-28: IP threat ML classifier + Attack Map enrichment
