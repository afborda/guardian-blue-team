# Prompts para Imagem — Arquitetura do Guardian

> Foco: **arquitetura completa** mostrando o fluxo de dados, o que acontece em cada servidor monitorado e como o Guardian Central os controla.

**Conceito:** Diagrama isométrico cinematográfico tipo *blueprint vivo*. Um servidor central ("Guardian Central") orquestra três servidores monitorados (`Server-01`, `Server-02`, `Server-Master`), mostrando o que cada um expõe via SSH e como os dados sobem pelo pipeline. Estética dark + neon (cyan + magenta + amber). Sem dados sensíveis.

---

## 1. Prompt para Google Gemini (Imagen 3 / Imagen 4)

```
A cinematic isometric architecture diagram of a distributed cybersecurity system, rendered as a dark futuristic blueprint coming to life. View angle: 35° isometric from above-right. Color palette: deep onyx black (#0a0a0f) and dark navy (#0f1424) backgrounds, with vivid neon cyan (#00FFFF) for data flows, electric magenta (#FF00FF) for AI/ML processing, and amber (#FFB800) for active threats and automated responses.

LAYOUT (left to right, in three vertical zones):

ZONE 1 — MONITORED SERVERS (left third):
Three glowing holographic server racks stacked vertically, each labeled clearly:
- "SERVER-01" (top) — small floating icons orbiting it: a lock (auth.log), a shield (UFW firewall), a terminal cursor (sudo), DNS waveform
- "SERVER-02" (middle) — orbiting icons: Docker whale silhouette, container boxes, network nodes
- "SERVER-MASTER" (bottom) — orbiting icons: a database cylinder, a globe, a key (SSH keys), file integrity hash symbols

Each server emits ~15 thin glowing data streams labeled with tiny tags ("auth.log", "ufw", "syslog", "dpkg", "docker events", "ps aux", "netstat", "FIM hash", "cron", "DNS", "sudo", "audit", "container-process", "container-network", "CVE scan"). All streams converge through a single secure SSH tunnel — depicted as a thick translucent cyan beam with light packets racing inside it.

ZONE 2 — GUARDIAN CENTRAL PIPELINE (middle, the largest element):
A massive horizontal holographic pipeline labeled "GUARDIAN CENTRAL" at the top. Inside the pipeline, six stacked stages glow in sequence with light flowing through them:
1. "COLLECTORS" — 20 small parallel intake ports
2. "NORMALIZER" — converging arrows funneling logs into a unified stream
3. "ML PRE-ENRICHER" — magenta neural network nodes (DGA Classifier, Markov Chain) with one tiny label "ONNX"
4. "DETECTOR" — a circular buffer with "30 RULES" floating around it, pulsing red when a match occurs
5. "ENRICHER" — a globe icon with red attack vectors merging with the stream (Threat Intelligence: AbuseIPDB, VirusTotal)
6. "CORRELATOR" — events merging into glowing incident orbs

Above the pipeline, four stacked luminous orbs in magenta represent the AI cascade with arrows showing fallback order: "OLLAMA" → "GEMINI" → "OPENAI" → "CLAUDE". A label reads "AI CASCADE — local-first".

Below the pipeline, a row of 17 small worker icons spinning at different speeds, labeled with tiny intervals: "EventCollector 2min", "Intelligence 1h", "ThreatHunter 4h", "FIM 4h", "CVE 6h", "Daily Report 08:00", etc.

ZONE 3 — AUTOMATED RESPONSE (right third):
A wall of hexagonal shield emblems lighting up. Floating action tags:
- "BLOCK-IP → UFW / iptables / fail2ban" (amber)
- "RATE-LIMIT" (cyan)
- "KILL-PROCESS" (red)
- "ISOLATE-CONTAINER" (magenta)
- "NOTIFY → Telegram" (cyan with a small paper-plane icon)

Arrows flow from the shield wall back to the three servers on the left, completing a closed loop — the Guardian sends commands BACK via SSH to enforce blocks. This return path is rendered as thinner amber beams flowing right-to-left.

GLOBAL VISUAL ELEMENTS:
- A faint grid floor under the entire scene with neon grid lines
- Volumetric fog at floor level
- Lens flares at the brightest neon sources
- Subtle scanning radar sweep across the floor
- A small watchful eye motif embedded inconspicuously in the Guardian Central pipeline header
- Long motion-blur trails on data streams to convey speed
- Slight chromatic aberration on neon edges
- Film grain

Typography: thin futuristic monospace font, all-caps labels, small size to keep diagram readable but not cluttered.

Mood: dark, controlled, surgical — the calm of total observability. Never panicked, always vigilant.

Style: cinematic 3D isometric render, ultra-detailed, 8K, sharp focus across the whole diagram (deep depth of field). Inspired by: Tron Legacy, Mr. Robot UI, the Matrix code-rain blueprints, Watch Dogs ctOS map, Cyberpunk 2077 Net architecture.

Aspect ratio: 16:9 widescreen. No real IPs, no real hostnames, no readable code. All text is stylized labels only as listed above.
```

---

## 2. Prompt para ChatGPT (DALL-E 3 / GPT-Image-1)

```
Cinematic ultra-wide architecture diagram of a futuristic distributed security platform, rendered in isometric 3D as a holographic blueprint floating in a dark void. The whole scene reads like a single living schematic — three monitored servers on the left, the Guardian Central brain in the middle, and an automated response wall on the right, all connected by glowing neon data flows.

LEFT — THE THREE MONITORED SERVERS:
Three sleek holographic server racks stacked vertically and slightly offset for depth: "SERVER-01" at the top, "SERVER-02" in the middle, "SERVER-MASTER" at the bottom. Each server pulses softly with cyan vital-signs lighting. Around each server orbit small glowing icons representing what's being watched — a padlock (authentication logs), a shield (firewall), a terminal prompt (sudo commands), a Docker whale (containers), a hash symbol (file integrity), a DNS waveform, a clock (cron jobs), a key (SSH keys).

From each server, dozens of thin neon data streams flow rightward, labeled with tiny tags: "auth.log", "ufw", "sudo", "docker events", "DNS", "syslog", "FIM", "container-process", "CVE scan", "netstat", "dpkg", "audit", "cron", "ps aux", "container-network". All streams gather into a single thick translucent cyan SSH tunnel — packets of light racing inside it like in a fiber-optic cable shot.

CENTER — GUARDIAN CENTRAL (the masterpiece of the scene):
A large luminous horizontal pipeline labeled "GUARDIAN CENTRAL" with six glowing stages light-flowing left to right:
1. COLLECTORS — twenty parallel intake ports drinking data from the SSH tunnel
2. NORMALIZER — converging funnels turning chaos into uniform structure
3. ML PRE-ENRICHER — magenta neural-network glow with "DGA / MARKOV / ONNX" labels
4. DETECTOR — a circular buffer with "30 RULES" orbiting it, occasionally flashing red on a match
5. ENRICHER — a glowing globe with red attack vectors merging in (label: "THREAT INTEL")
6. CORRELATOR — small events merging into bigger glowing incident orbs

Floating ABOVE the pipeline, a vertical AI cascade of four luminous magenta orbs connected by cascading arrows: "OLLAMA" (top, brightest — local), then "GEMINI", "OPENAI", "CLAUDE". A subtitle reads "AI CASCADE — LOCAL-FIRST FALLBACK".

Floating BELOW the pipeline, a row of 17 small spinning worker gears, each with a tiny interval label: "EventCollector · 2min", "Intelligence · 1h", "ThreatHunter · 4h", "FIM · 4h", "CVE Monitor · 6h", "DDoS Escalation · 2min", "Block Propagation · 2min", "Daily Report · 08:00 BRT", etc. The faster ones blur from rotation speed.

A small storage cylinder below labeled "PostgreSQL — soc_incidents, security_events, blocked_ips, behavior_profiles".

RIGHT — AUTOMATED RESPONSE WALL:
A vertical wall of glowing hexagonal shields, each lighting up with an action label as data hits it:
- "BLOCK-IP" (amber) — sub-labels: "UFW · iptables · fail2ban"
- "RATE-LIMIT" (cyan) — "GUARDIAN-INPUT chain"
- "KILL-PROCESS" (red)
- "ISOLATE-CONTAINER" (magenta) — sub-labels: "pause · disconnect · restart"
- "NOTIFY" (cyan with a Telegram paper-plane icon) — sub-label: "human-in-the-loop approval"

CLOSED LOOP — THE BEST PART:
Thinner amber beams flow from the shield wall BACK to the three servers on the left, depicting the return commands ("iptables -A GUARDIAN-INPUT -s X -j DROP", "docker pause", "pkill"). This makes it visually obvious that Guardian doesn't just watch — it acts. The closed loop is the entire story.

GLOBAL ATMOSPHERE:
Deep dark void background with a faint neon hex grid floor. Volumetric fog hugging the floor. Lens flares from the brightest neon sources. A slow radar sweep crossing the entire floor. A subtle, almost invisible watchful eye motif embedded in the Guardian Central header — surveillance without paranoia.

Motion conveyed by long light trails on the data streams, like a long-exposure shot of a fiber backbone.

Mood: dark, surgical, calm-but-alert. Like the situation room of a black-ops cyber unit. No chaos, just total observability and instant response.

Color palette: 90% black and dark navy. Cyan (#00FFFF) for data flows, magenta (#FF00FF) for AI/ML, amber (#FFB800) for blocks and warnings. No other saturated colors.

Style: cinematic 3D isometric render, ultra-detailed, sharp focus across the entire diagram, chromatic aberration on neon edges, subtle film grain. Inspired by: Tron Legacy, Mr. Robot, Cyberpunk 2077 Net architecture, the Matrix mainframe room, Watch Dogs ctOS dashboards, Blade Runner 2049 holograms.

Aspect ratio: 16:9. No real IP addresses, no real hostnames, no readable code or log lines. All text is stylized labels exactly as listed above.
```

---

## 3. Prompt curto/alternativo

```
Isometric 3D cyberpunk architecture diagram, dark + neon (cyan, magenta, amber). LEFT: three holographic servers labeled "Server-01", "Server-02", "Server-Master", each emitting ~15 labeled data streams (auth.log, ufw, sudo, docker, DNS, syslog, FIM, CVE, etc.) that converge into a single SSH tunnel. CENTER: a large pipeline labeled "GUARDIAN CENTRAL" with six glowing stages — Collectors → Normalizer → ML Pre-Enricher (DGA/Markov/ONNX) → Detector (30 rules) → Enricher (Threat Intel globe) → Correlator. Above the pipeline: AI cascade of four orbs (Ollama, Gemini, OpenAI, Claude). Below: 17 spinning worker gears with intervals. RIGHT: hexagonal shield wall with action tags (Block-IP, Rate-Limit, Kill-Process, Isolate-Container, Notify Telegram). Amber return beams flow from shields back to servers — closed loop. Hex grid floor, volumetric fog, motion blur, lens flares, watchful eye motif. Tron + Mr. Robot + Cyberpunk 2077 aesthetic. Cinematic, 8K, ultra-detailed, 16:9. No real IPs or hostnames.
```

---

## 4. Mapeamento — elemento visual ↔ código real

### Servidores monitorados (zona esquerda)

| Ícone orbitando | Collector real | Comando SSH executado |
|-----------------|----------------|----------------------|
| 🔒 Cadeado | `auth-collector` | `journalctl -u ssh` ou `cat /var/log/auth.log` |
| 🛡️ Escudo | `ufw-collector` | `cat /var/log/ufw.log` |
| ⚡ Terminal | `sudo-collector` | `journalctl -u sudo` |
| 🐳 Docker | `docker-collector` | `docker events --since` |
| #️⃣ Hash | `fim-collector` | `sha256sum /etc/passwd /etc/shadow ...` |
| 🌐 DNS waveform | `dns-collector` | `journalctl -u systemd-resolved` |
| 🔑 Chave | `ssh-keys-collector` | `cat ~/.ssh/authorized_keys` |
| ⏰ Relógio | `cron-collector` | `crontab -l` |
| 📦 Caixa | `package-collector` | `cat /var/log/dpkg.log` |
| 📊 Gráfico de rede | `network-collector` | `ss -tunap`, `netstat -i` |

### Pipeline (zona central)

| Estágio visual | Arquivo real | O que faz |
|---------------|-------------|-----------|
| **Collectors** (20 portas) | `src/collectors/*.ts` | Coleta paralela via SSH ControlMaster |
| **Normalizer** (funil) | `src/pipeline/normalizer.ts` | Regex + parsers → `NormalizedEvent` |
| **ML Pre-Enricher** (rede neural magenta) | `src/intelligence/dga-enricher.ts` + `markov-enricher.ts` | DGA Classifier ONNX + Markov surprisal |
| **Detector** (buffer circular) | `src/pipeline/detector.ts` | 30 regras síncronas em buffer 2000 eventos |
| **Enricher** (globo) | `src/pipeline/enricher.ts` | AbuseIPDB + VirusTotal + SSH Behavior Score |
| **Correlator** (orbes de incidente) | `src/pipeline/correlator.ts` | Janela 10min agrupa em incidentes |

### Cascata de IA (acima do pipeline)

| Orbe | Provider | Uso |
|------|---------|-----|
| 🟣 Ollama (mais brilhante) | local | Threat Hunter, advisory de bloqueio, RAG de incidentes |
| 🟣 Gemini | API cloud | Fallback se Ollama falhar |
| 🟣 OpenAI | API cloud | 2º fallback |
| 🟣 Claude | API cloud | 3º fallback |

### Workers (abaixo do pipeline)

17 engrenagens girando — cada uma representa um worker de `src/workers/`:
`EventCollectorWorker (2min)`, `IntelligenceWorker (1h)`, `ThreatHunterWorker (4h)`, `FIMWorker (4h)`, `CVEMonitorWorker (6h)`, `DDoSEscalationWorker (2min)`, `BlockPropagationWorker (2min)`, `BlockReconcileWorker (15min)`, `BlockCleanupWorker (5min)`, `ScoreCalculatorWorker (5min/1h)`, `IpThreatScorerWorker (2h)`, `ContainerSecurityWorker (vários)`, `VulnScannerWorker (semanal)`, `DailyReportWorker (08:00 BRT)`, `MetricsRetentionWorker (24h)`, `CVEIntelFeedsWorker`, `DiscoveryWorker`.

### Resposta automatizada (zona direita)

| Escudo hexagonal | Ação real | Implementação |
|-----------------|-----------|---------------|
| 🟧 BLOCK-IP | `block-ip` | `src/playbooks/actions/block-ip.ts` — UFW/iptables (chain GUARDIAN-INPUT)/fail2ban |
| 🟦 RATE-LIMIT | `rate-limit` | `src/playbooks/actions/rate-limit.ts` |
| 🟥 KILL-PROCESS | `kill-process` | `src/playbooks/actions/kill-process.ts` |
| 🟪 ISOLATE-CONTAINER | `pause` + `disconnect` + `restart` | `src/playbooks/actions/container-actions.ts` |
| 🟦 NOTIFY | `notify` | Telegram com inline buttons (aprovação manual) |

### Loop fechado (feixes amber voltando)

Os feixes amber que voltam dos escudos para os servidores representam:
- `BlockPropagationWorker` propagando blocks novos via SSH a cada 2min
- `BlockReconcileWorker` verificando estado real do firewall a cada 15min
- Comandos imediatos de playbook (kill-process, docker pause) executados via SSH

---

## 5. Variações de ênfase (escolher uma)

### A. Ênfase em "o que vemos" (observabilidade)
Adicionar: *"The three servers on the left are partially transparent, revealing internal processes glowing inside — like a CT scan of each machine. Every running process, every open file, every SSH session is faintly visible. Make it clear that the Guardian sees everything."*

### B. Ênfase em "o que fazemos" (ação automatizada)
Adicionar: *"Make the amber return beams from the shield wall extra prominent — thicker, faster, more particles. Show one server on the left actively receiving a 'BLOCK-IP' command — a small attacker icon being kicked out by an animated boot. Action over observation."*

### C. Ênfase em "tempo real" (velocidade)
Adicionar: *"Add timer overlays at each pipeline stage: 'COLLECT < 2s', 'NORMALIZE < 50ms', 'DETECT < 5ms', 'CORRELATE < 100ms'. The data races through the entire pipeline in under a second — show motion blur extreme enough to almost streak the entire diagram."*

### D. Ênfase em "inteligência" (ML + IA)
Adicionar: *"Make the magenta ML Pre-Enricher and the AI Cascade orbs the brightest elements in the entire scene — pulsing with neural activity. Add tiny floating equations and matrix patterns around them. The intelligence is the protagonist."*

---

## 6. Negative prompt

```
no real IP addresses, no real hostnames, no readable log content, no human faces, no corporate logos, no Windows desktop, no light/bright background, no pastel colors, no cartoon style, no flat 2D, no stock-photo look, no clutter, no watermarks, no garbled text, no lens dirt, no blurry foreground
```

---

## 7. Dicas de geração

- **Gemini Imagen 3/4:** Usar prompt #1 inteiro. Se cortar, priorizar as três zonas (esquerda/centro/direita) e o loop fechado
- **DALL-E 3 / ChatGPT:** Usar prompt #2 — narrativa cinematográfica preserva a história
- **Midjourney:** Prompt #3 + `--ar 16:9 --style raw --v 6 --stylize 750`
- **Stable Diffusion:** Prompt #3 como positive + #6 como negative + LoRA "isometric architecture" ou "blueprint diagram"

> Se a imagem ficar muito carregada, pedir uma segunda versão com a instrução: *"Simplify by removing the worker gear row at the bottom — keep only the three zones and the AI cascade. Increase the size of each remaining element."*
