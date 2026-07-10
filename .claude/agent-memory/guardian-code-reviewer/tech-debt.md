# Dívida técnica conhecida

Última atualização: 2026-05-29

Issues catalogadas que não bloqueiam mas devem ser atacadas eventualmente. Quando vejo PR perto dessas áreas, sinalizo como 🟡 sugestão pra encostar enquanto está fresco.

## Modelo de instalação legacy

**Localização:** `src/collectors/ssh-collector.ts`, `src/services/server.service.ts`
**Problema:** `StrictHostKeyChecking=accept-new` é TOFU — vulnerável a MITM no primeiro contato. Chave SSH sem passphrase. Root direto na frota.
**Plano:** Tier 0 do roadmap (guardian-shell). Aprovado, não implementado.
**Quando atacar:** quando usuário autorizar.

## SQLite com features que só existem em PG

**Localização:** `src/intelligence/markov-user-profile.service.ts`, `src/workers/intelligence.worker.ts`
**Problema:** Materialized views (`user_command_transitions`, `user_command_thresholds`) só existem em PG. SQLite tem fallback, mas é mais lento.
**Plano:** documentado em ADR-004. Aceitar trade-off por enquanto.
**Quando atacar:** se tiver demanda real de prod em SQLite (improvável, dev usa SQLite).

## Hardcoded `auth.log` path em alguns coletores

**Localização:** múltiplos collectors em `src/collectors/`
**Problema:** Ubuntu tem `/var/log/auth.log`, RHEL tem `/var/log/secure`, journald tem path nenhum. Hardcode quebra em RHEL.
**Plano:** após Tier 0, `soc_servers.os_family` decide path. Por enquanto, prod só tem Ubuntu então não causa bug.
**Quando atacar:** quando primeiro RHEL real for adicionado.

## Falta CIDR helper

**Localização:** `isPrivateIp()` em `src/utils/sanitize.ts` (provável)
**Problema:** 3× `startsWith('172.')` em vez de validar 172.16.0.0/12 corretamente. Aceita 172.32.x.y como privado quando não é.
**Plano:** Tier 1 do roadmap. CIDR helper unificado.
**Quando atacar:** próximo PR que toque IP validation.

## `/webhook/telegram` fail-open

**Localização:** `src/server.ts` ou rota Telegram
**Problema:** se `TELEGRAM_BOT_TOKEN` ausente, webhook ainda aceita request. Atacante pode injetar mensagens falsas.
**Plano:** Tier 1 — fail-closed (rejeitar se token ausente).
**Quando atacar:** próximo PR no Telegram.

## `/health` expõe versão

**Localização:** endpoint `/health`
**Problema:** versão pública = atacante sabe quais CVEs aplicam.
**Plano:** Tier 1 — remover ou auth.
**Quando atacar:** próximo PR no dashboard.

## SYN flood autoblock self-DoS

**Localização:** detection rule #7 (provavelmente em `src/pipeline/rules/`)
**Problema:** awk extrai Local Address (do servidor!) em vez do peer. Bloqueia IP do próprio servidor → self-DoS.
**Plano:** **REMOVER** o autoblock. Manter só alerta + `tcp_syncookies=1`.
**Severidade:** 🔴 alto risco se trigger ocorrer em prod. Mitigação: usuário sabe e não está em ambiente alvo de SYN flood ativo.
**Quando atacar:** Tier 2 do roadmap.

## Rate-limit chain sem ordering determinístico

**Localização:** `src/playbooks/actions/` (rate-limit related)
**Problema:** Insere/deleta em chain comum, sem ordering garantido. Race conditions com fail2ban.
**Plano:** chain `GUARDIAN_RATELIMIT` dedicada (Tier 2).
**Quando atacar:** Tier 2.

## Container process parsing frágil

**Localização:** parser de `docker stats` ou `top` em `src/collectors/`
**Problema:** `[, , cpu, , command, ...]` quebra se Docker mudar formato.
**Plano:** parsear por header em vez de posição (Tier 3).
**Quando atacar:** Tier 3.

## Postgres password fallback inseguro

**Localização:** `docker-compose.yml` ou env loading
**Problema:** `${POSTGRES_PASSWORD:-guardian_secret}` permite default fraco.
**Plano:** env obrigatório, sem fallback (Tier 4).
**Quando atacar:** Tier 4.

## README "always permanent" vs default 24h

**Localização:** README PT vs `src/playbooks/actions/block-ip.ts`
**Problema:** doc fala "permanente", código defaulta 24h.
**Plano:** alinhar (Tier 4 + docs writer).
**Quando atacar:** quando docs writer atualizar README.

## Como atualizar este arquivo

- Issue identificada em review: anota com localização + plano
- Issue corrigida: move pra "Histórico" no fim (não delete — referência futura)
- Issue revisita prioridade: atualiza "Quando atacar"
