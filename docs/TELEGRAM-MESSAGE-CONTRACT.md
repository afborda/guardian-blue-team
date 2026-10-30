# Contrato das mensagens do Telegram

Toda mensagem enviada pelo Guardian deve ser legível por uma pessoa cansada, às 3 da manhã, no celular. Este documento define o formato, o tom e o ciclo de vida — e serve de checklist para revisar copy nova.

## Regra de ouro

Uma mensagem responde, nesta ordem:

1. **O que aconteceu** — fato, servidor, quando.
2. **O que isso significa** — só quando ajuda; sem jargão.
3. **O que fazer agora** — ou a frase explícita “não precisa fazer nada”.
4. **Como agir** — botão quando houver ação; prazo e consequência quando houver decisão.

Se a mensagem não cabe em uma tela (~1.200 caracteres), ela é um relatório, não um alerta.

## Contrato técnico

`src/telegram/messaging/types.ts`:

```ts
interface MessageSpec {
  kind: 'incident' | 'approval' | 'cve' | 'login' | 'block' | 'anomaly' | 'report' | 'system';
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;                 // sentence case, <= 60 chars
  lead: string;                  // 1 frase: o que aconteceu
  facts?: MessageFact[];         // máx. 5; IP/ID/comando com code: true
  meaning?: string;              // máx. 2 frases
  action?: MessageAction;        // required, steps (<=3), deadline, ifIgnored
  sections?: MessageSection[];   // relatórios: blocos de detalhe em texto puro
  footer?: string;
  buttons?: MessageButton[];     // callback_data <= 64 bytes
  dedupeKey?: string;
}
```

Fluxo:

```
worker/playbook
  → copy/<família>.ts      (conteúdo)
  → messaging/render.ts    (HTML + teclado)
  → messaging/sender.ts    (entrega)
```

Nenhum worker deve montar HTML nem chamar `api.telegram.org` diretamente. A única exceção são `setWebhook`/`setMyCommands`, que não são mensagens.

## Regras de estilo

- Título em sentence case. Nada de `PLAYBOOK ALERT`, `CRITICO`, `[HIGH]`.
- Sem entidades HTML (`&#128680;`); use o emoji direto ou nenhum.
- IP, ID, comando e fingerprint em `<code>`; nunca em backticks.
- No máximo 3 emojis por mensagem: ícone de severidade + 1 por seção.
- Tempo sempre em BRT, com data quando não for hoje: `30/10, 16:08 (BRT)`.
- Números em pt-BR: `1.234`, `38%`, `3,5`.
- Se não houver ação: escrever “Não precisa fazer nada.”
- Se houver ação: verbo no imperativo, no máximo 3 passos, com prazo e consequência.
- Nunca mostrar `undefined`, `NaN`, `null`, stack trace, JSON cru ou resumo técnico em inglês.
- Explicar termos uma vez: “KEV (falhas já exploradas na vida real)”.

## Famílias

| Família | Arquivo | Pergunta que responde |
|---|---|---|
| `incident` | `copy/incident.ts` | O que foi detectado e preciso decidir algo? |
| `approval` | `copy/approval.ts` | O que vai acontecer se eu aprovar? |
| `cve` | `copy/cve.ts` | Qual falha, quão grave, atualizo agora? |
| `login` | `copy/login.ts` | Foi você? |
| `block` | `copy/block.ts` | O bloqueio está de pé? |
| `anomaly` | `anomaly-copy.ts` | O servidor está só ocupado ou tem algo errado? |
| `report` | `copy/system.ts` | O que precisa de mim no relatório? |
| `system` | `copy/system.ts` | Caça, discovery, backup, container inesperado. |

## Exemplos

Incidente com ação pendente:

```
🟠 Força bruta no SSH

O servidor hetzner-prod registrou 20 tentativas de login em 30/10, 16:08 (BRT).

• Servidor: hetzner-prod
• IP: 203.0.113.50
• Incidente: #42

O que isso significa
Alguém tentou adivinhar a senha do SSH. Se o IP não é seu, bloquear é seguro.

O que fazer agora
1. Confira se reconhece esse IP.
2. Se não reconhecer, bloqueie agora.
Sem botão? Use /block 203.0.113.50.

[Bloquear IP] [Ver reputação]
[Falso positivo] [Confirmar] [Monitorar]
```

Incidente já contido:

```
🟡 Varredura de portas

...

O que já foi feito
O IP 198.51.100.7 já está bloqueado. Não precisa fazer nada.

[Desbloquear] [Ver reputação]
```

Aprovação:

```
🟠 Preciso da sua autorização

O Guardian quer atualizar a imagem do container em hetzner-prod.

O que vai acontecer se você aprovar
1. Baixar a imagem corrigida
2. Recriar o container
3. Avisar a equipe
Responda até 30/10, 16:38 (BRT).
Se ninguém responder, nada será executado.

[Aprovar] [Rejeitar]
```

## Ciclo de vida

- **Incidente:** uma mensagem por incidente, inclusive para categorias sem playbook. `IncidentAlertService` decide individual vs. digest (crítico/alto sempre individual; lote > 3 vira resumo).
- **Playbook:** se o incidente tem mensagem, o playbook **edita** a mesma mensagem (“O que já foi feito”). Não manda uma segunda.
- **Aprovação:** mensagem própria com prazo de 30 min. Ao aprovar/rejeitar, a mensagem é editada com o resultado e os botões somem. Ao expirar, vira “Pedido expirado — nada foi executado”.
- **Login:** mensagem própria; ao responder, é editada e os botões somem.
- **CVE:** mensagem própria com “Atualizar agora” somente quando existe correção.
- **Feedback:** falso positivo/confirmar/monitorar editam a mensagem do incidente e alimentam o filtro de ruído.

## Entrega

`src/telegram/messaging/sender.ts`:

- escape HTML de todo valor dinâmico;
- chunk em blocos de 3.800 caracteres, sem cortar tag no meio;
- 400 de parse → reenvia sem `parse_mode`;
- 429 → respeita `retry_after` (máx. 3 s) e tenta 1 vez;
- 5xx/timeout → 1 retry curto;
- `TELEGRAM_DRY_RUN=1` registra o payload e não envia;
- log estruturado `telegram_send` (`kind`, `chat_id`, `message_id`, `ok`, `status`, `latency_ms`, `chars`).

## Verificação

```bash
npm run type-check
npm test
npm run preview:telegram
npm run preview:telegram -- --family incident
npm run preview:telegram -- --json
# envia para o chat de teste (exige TELEGRAM_TEST_CHAT_ID)
npm run preview:telegram -- --send

# só o sender pode falar com a API de mensagens
grep -rn "api.telegram.org" src --include=*.ts
```

Checklist manual (chat de teste):

- [ ] incidente com IP não bloqueado → botão “Bloquear” funciona
- [ ] incidente já bloqueado → mostra “Desbloquear”, não “Bloquear”
- [ ] aprovação → aprovar edita com resultado e remove botões
- [ ] aprovação → rejeitar edita e diz que nada foi executado
- [ ] aprovação → deixar expirar (30 min) edita para “expirado”
- [ ] CVE com correção → “Atualizar agora” aparece
- [ ] CVE sem correção → “Atualizar agora” não aparece
- [ ] login → “Não sou eu” escala o incidente
- [ ] relatório diário → seção “Precisa de você” no topo
- [ ] mensagem com nome de servidor contendo `<` não quebra o HTML

## Rollout

- `TELEGRAM_COPY_V2=all` (padrão) — mensagens novas.
- `TELEGRAM_COPY_V2=legacy` — volta o formato antigo de incidente/playbook; CVE/login/bloqueio continuam no formato novo.
- `TELEGRAM_DRY_RUN=1` — desenvolvimento.
- `TELEGRAM_TEST_CHAT_ID` — chat de teste para `npm run preview:telegram -- --send`.

## Limitações conhecidas

- Listas por família (`incident,approval,...`) estão reservadas; hoje o flag é `all` ou `legacy`.
- Relatórios diário/semanal agora usam resumo + seção de detalhes; o corpo detalhado ainda é gerado em texto e tem HTML removido antes de renderizar.
- O vínculo incidente ↔ mensagem é em memória: após restart, a próxima atualização vira uma mensagem nova (sem mudança de schema nesta fase).
