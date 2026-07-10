# Histórico de incidentes / near-miss

Última atualização: 2026-05-29

## Convenção

Cada entrada:
- **Data**
- **Tipo** (incidente real, near-miss, lição teórica)
- **O que aconteceu**
- **Lição** (vira regra na allowlist, no bootstrap, ou em anti-padrão)

## Entradas

### 2026-05-29 — lição teórica (não houve incidente real)
**Tipo:** Análise inicial do modelo legacy
**O que aconteceu:** Usuário perguntou sobre como instalar Guardian de forma segura. Análise mostrou que modelo atual (root + chave sem passphrase + accept-new) tem blast radius de root na frota inteira se chave do container Guardian vazar.
**Lição:**
- `command=` em authorized_keys é a defesa primária (mesmo se chave vazar, atacante só roda guardian-shell)
- `restrict` em vez de `no-port-forwarding,no-X11-forwarding,...` (mais simples e cobre mais)
- Heartbeat out-of-band detecta servidor que "silenciou" — atacante root pode parar de mandar logs mas não tem como impedir Guardian de notar a ausência

### Padrão observado nos commits recentes
**Tipo:** Lição operacional (não é incidente)
**O que aconteceu:** Vários commits 2026-05-28/29 corrigem false-positives e edge cases (FIM, container security, geo-attacks). Indica que sistema é sensível a churn — mudanças no modelo de instalação devem ter rollback fácil.
**Lição:**
- Toda mudança no SSHCollector mantém compat legacy via `install_method` flag
- Migração de servidor legacy → guardian-shell é **opt-in**, nunca automática
- Bootstrap em servidor de teste antes de prod, sempre

## Quando este arquivo deve mudar

- Houve incidente real → registrar em < 24h, mesmo que análise não esteja completa
- Detectou near-miss → registrar com mitigação aplicada
- Auditoria/pentest encontrou algo → registrar com plano + data alvo de correção
