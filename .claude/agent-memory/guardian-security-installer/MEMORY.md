# Memória do guardian-security-installer

Última atualização: 2026-05-29

## Índice

- [Modelo de instalação atual](install-model-current.md) — como o Guardian é instalado HOJE (legacy)
- [Modelo aprovado guardian-shell](install-model-approved.md) — alvo, ainda não implementado
- [Allowlist do guardian-shell](allowlist.md) — regex aceitos + timeouts + justificativa
- [OS quirks](os-quirks.md) — diferenças Ubuntu/Debian/RHEL/Fedora que importam
- [Componentes a criar](components-todo.md) — arquivos novos + modificações em arquivos existentes
- [Histórico de incidentes](incidents.md) — vazamentos, near-miss, lições aprendidas

## Estado atual

**Modelo em produção (legacy):**
- Usuário: `root` na frota inteira
- Chave SSH sem passphrase em `/root/.ssh/id_ed25519`
- `NOPASSWD: ALL` no sudoers (efetivamente — login é root direto)
- `StrictHostKeyChecking=accept-new` em código (TOFU fraco)
- Blast radius: comprometer Guardian = root em N servidores

**Modelo aprovado (não implementado):**
- Usuário dedicado `guardian` em cada servidor
- Python wrapper `/usr/local/sbin/guardian-shell` com allowlist regex
- Sudoers de 1 linha: `guardian ALL=(root) NOPASSWD: /usr/local/sbin/guardian-shell`
- `authorized_keys` com `command="/usr/local/sbin/guardian-shell"` + `restrict`
- `StrictHostKeyChecking=yes` + fingerprint pinned no `soc_servers.host_fingerprint`
- Bootstrap via token one-shot TTL 15min: `curl -fsSL $GUARDIAN_BASE_URL/install/$TOKEN | sudo bash`
- Heartbeat worker — alerta Telegram se servidor silenciar > 5min

## Onde paramos (2026-05-29)

Modelo desenhado e aprovado pelo usuário. Aguardando autorização explícita pra começar Tier 0 da implementação (6-8h estimado).

Próximo passo se autorizado:
1. Schema: criar tabela `install_tokens` + colunas em `soc_servers`
2. Implementar `src/discovery/install.ts` (gerador de bootstrap)
3. Endpoint `/install/:token` no dashboard com TTL 15min
4. Ajustar `SSHCollector` pra `StrictHostKeyChecking=yes` + fingerprint
5. Heartbeat worker
6. UI `add-server.html` com box do fingerprint
7. Preservar compat legacy via `install_method='legacy'` em `soc_servers`
8. Testar end-to-end em servidor de teste antes de migrar prod

## Como me usar

Quando o usuário pedir:
- "implementa o modelo de instalação seguro" → siga roadmap acima, em ordem
- "explica o que muda" → leia `install-model-current.md` + `install-model-approved.md`
- "que comandos o guardian-shell aceita?" → leia `allowlist.md`
- "vai funcionar em RHEL?" → leia `os-quirks.md`

## Anti-padrões inegociáveis

- Nunca `NOPASSWD: ALL` em código novo
- Nunca `StrictHostKeyChecking=accept-new` ou `=no` em código novo
- Nunca chave SSH sem passphrase E sem `command=` restriction (precisa pelo menos um dos dois)
- Nunca interpolar input do dashboard direto em comando shell (passe pelo `guardian-shell` validado)
- Nunca shell-out de notificação rodando NO servidor monitorado (atacante root mata o processo) — toda notificação sai do Guardian central
