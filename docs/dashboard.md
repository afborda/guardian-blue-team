# Dashboard

Guardian inclui um dashboard web server-rendered com HTMX — zero JavaScript frameworks, carregamento instantaneo.

---

## Acesso

```
URL: https://seu-dominio/dashboard?token=SEU_DASHBOARD_TOKEN
```

O token e definido em `DASHBOARD_TOKEN` no `.env`. Sem ele, o dashboard retorna 401.

---

## Paginas

| Pagina | URL | Descricao |
|--------|-----|-----------|
| **Overview** | `/dashboard` | KPIs, pipeline visualization, ameacas recentes, acoes recentes |
| **Fleet Health** | `/dashboard/health` | Cards por servidor com score e metricas (load, mem, disk) |
| **Server Detail** | `/dashboard/health/:id` | Metricas detalhadas, discos, unidades com falha |
| **Scores Grid** | `/dashboard/scores` | Tabela comparativa: servidores x 6 dimensoes |
| **Incidents** | `/dashboard/incidents` | Incidentes abertos com severidade e timeline |
| **Servers** | `/dashboard/servers` | Servidores registrados + last seen + status |
| **CVE Alerts** | `/dashboard/cve` | CVEs pendentes com acoes (atualizar, ignorar) |
| **IP Blocks** | `/dashboard/blocks` | IPs bloqueados ativos com botao de desbloqueio |
| **Security Logs** | `/dashboard/logs` | Eventos de seguranca recentes (filtravel por tipo/severidade) |
| **Timeline** | `/dashboard/timeline` | Eventos em ordem cronologica com correlacao visual |
| **Attack Map** | `/dashboard/map` | Distribuicao geografica dos IPs atacantes |
| **API Status** | `/dashboard/apis` | Status de saude dos servicos e APIs externas |

---

## Stack Tecnica

| Componente | Tecnologia |
|-----------|-----------|
| Rendering | Server-side HTML (Express templates) |
| Interatividade | [HTMX 2.0](https://htmx.org/) — atualizacao parcial sem reload |
| Estilo | CSS custom (dark theme, sem frameworks) |
| Charts | Nenhum framework (CSS bars, conic-gradient circles) |
| Responsivo | CSS Grid + media queries (mobile-first) |

**Peso da pagina**: ~15KB HTML + ~8KB CSS + ~14KB HTMX = **~37KB total** (sem fontes externas).

---

## Design

- **Dark theme** otimizado para NOC/SOC (low eye strain)
- Cores semanticas: verde=ok, amarelo=warning, vermelho=critical, azul=info
- Glow effects para chamar atencao em metricas criticas
- Score circles com conic-gradient animado
- Tabelas com hover highlight e zebra striping
- Cards com border-glow proporcional a severidade

---

## Auto-refresh

Paginas usam `hx-trigger="load delay:30s"` para atualizar dados sem reload:
- Overview: atualiza stats a cada 30s
- Incidents: polling a cada 15s
- Logs: streaming de novos eventos

---

## Mobile

O dashboard e responsivo:
- Grid colapsa para coluna unica em telas < 1024px
- Navegacao horizontal com scroll
- Touch-friendly (botoes com min-height 44px)
- Testado em iPhone SE e Android Chrome
