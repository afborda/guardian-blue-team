# Prompts para Geração de Imagem — Guardian Visual

> Prompts otimizados por plataforma, baseados na arquitetura real descrita em `docs/GUARDIAN-ANALYSIS.md`.

**Conceito visual unificado:** Dashboard de SOC futurístico, estética dark + neon (cyan + magenta + amber para warnings), Tron/Synthwave/Mr. Robot vibe. Sensação de **velocidade**, **controle** e **vigilância**. Sem dados sensíveis (servidores genéricos: `Server-01`, `Server-02`, `Server-Master`).

---

## 1. Prompt para Google Gemini (Imagen 3 / Imagen 4)

> Gemini responde melhor a prompts **estruturados, técnicos e descritivos**, com referências de estilo explícitas.

```
A dark, futuristic Security Operations Center (SOC) command dashboard, isometric 3D render, cinematic perspective from slightly above. Dominant color palette: deep black (#0a0a0f) and dark navy backgrounds with vivid neon cyan (#00FFFF) and electric magenta (#FF00FF) glow accents, with amber (#FFB800) used sparingly for active threat warnings. High-tech, Tron-inspired, synthwave aesthetic.

The scene shows a holographic security pipeline flowing left-to-right with motion blur and light streaks suggesting high speed: 
1. Three labeled server nodes on the left — "Server-01", "Server-02", "Server-Master" — rendered as glowing rack-mounted units with pulsing cyan status indicators and SSH connection beams flowing outward
2. A processing pipeline with six glowing stages connected by neon data streams: "COLLECT", "NORMALIZE", "DETECT", "ENRICH", "CORRELATE", "RESPOND"
3. Floating holographic panels around the pipeline showing: real-time event counters, abstract attack pattern graphs (sine waves, heatmaps), neural network nodes (representing ML), and a globe with red attack vectors converging
4. On the right side: an automated response zone showing shield icons activating, firewall barriers materializing, and small "BLOCKED" tags lighting up

Visual elements to emphasize:
- Speed: long light trails, motion blur on data packets, particles streaking through the pipeline
- Control: clean grid lines, perfectly aligned holographic panels, calm but powerful HUD elements
- Surveillance/vigilance: glowing eye motif subtly embedded in the central control panel, scanning radar sweep
- Dark, ominous mood: deep shadows, volumetric fog, atmospheric haze, lens flares from neon sources

Typography: thin monospace font for labels, slight chromatic aberration on text. Resolution and detail: ultra-detailed, 8K quality, sharp focus on foreground pipeline, slight depth-of-field blur on background. Aspect ratio: 16:9 widescreen.

No real IP addresses, no real hostnames, no readable code or logs. All text is stylized labels only.

Style references: Tron Legacy, Mr. Robot UI, Cyberpunk 2077 dashboards, Watch Dogs hacking screens.
```

---

## 2. Prompt para ChatGPT (DALL-E 3 / GPT-Image-1)

> DALL-E 3 funciona melhor com prompts **narrativos e cinematográficos**, com adjetivos sensoriais fortes.

```
Cinematic, ultra-wide hero shot of a futuristic cyber-defense command center at night, viewed from a low isometric angle. The atmosphere is intensely dark — deep onyx black floor reflecting neon highlights — but alive with electric energy and a sense of relentless speed.

In the center floats a massive holographic security pipeline made of pure cyan and magenta neon light, six luminous stages flowing left to right: COLLECT → NORMALIZE → DETECT → ENRICH → CORRELATE → RESPOND. Streams of glowing data particles race through the pipeline like liquid lightning, leaving long light trails that suggest blistering speed.

On the left, three sleek holographic server units labeled "SERVER-01", "SERVER-02", and "SERVER-MASTER" pulse with rhythmic cyan light. Thin laser-like SSH beams arc from each server toward the pipeline, carrying packets of light. Above each server, small status indicators show heartbeat rhythms.

Around the pipeline, several semi-transparent holographic UI panels float in mid-air:
- A neural network diagram with glowing magenta nodes (representing the ML models — DGA classifier, IP threat scorer)
- A world map with delicate red attack vectors converging on the pipeline
- A real-time threat counter, abstract waveforms, and a sweeping radar circle in cyan
- A vertical AI cascade showing four luminous orbs stacked: "OLLAMA", "GEMINI", "OPENAI", "CLAUDE", with light flowing top-down

On the right, an automated response zone glows brighter than the rest: hexagonal shield emblems materialize and lock into place, neon firewall walls rise up, and small tags reading "BLOCKED", "ISOLATED", "NEUTRALIZED" light up in amber.

Subtle visual storytelling:
- A faint, watchful glowing eye motif embedded in the central control sphere — silent vigilance
- Scanning radar sweep across the floor grid, suggesting constant surveillance
- Volumetric fog at floor level, neon reflections on a wet-looking surface
- Lens flares from the brightest light sources

Mood: dark, controlled, dangerous-but-disciplined — like the protagonist's hideout in Mr. Robot crossed with the inside of the Tron grid. Powerful, fast, watchful, never panicked.

Color palette: 90% deep black and dark navy, with brilliant cyan (#00FFFF), electric magenta (#FF00FF), and warning amber (#FFB800) as the only saturated colors.

Style: cinematic 3D render, ultra-detailed, sharp focus on the pipeline with shallow depth of field on the background, chromatic aberration on neon edges, film grain. Inspired by Tron Legacy, Cyberpunk 2077, Mr. Robot, Blade Runner 2049.

Aspect ratio: 16:9. No real IP addresses, no hostnames, no readable text beyond stylized labels listed above.
```

---

## 3. Prompt curto/alternativo (caso a plataforma limite o tamanho)

```
Dark cyberpunk SOC dashboard, isometric 3D render. Neon cyan and magenta on deep black. Three glowing holographic servers labeled "Server-01", "Server-02", "Server-Master" on the left, connected by SSH light beams to a six-stage security pipeline (COLLECT → NORMALIZE → DETECT → ENRICH → CORRELATE → RESPOND). Floating holographic panels show ML neural networks, an AI cascade (Ollama, Gemini, OpenAI, Claude), and a world map with attack vectors. Right side: shields activating, "BLOCKED" tags glowing amber. Motion blur and light streaks convey speed. Subtle watchful eye motif in the center. Volumetric fog, neon reflections, Tron Legacy / Mr. Robot aesthetic. Cinematic, 8K, ultra-detailed, 16:9. No real IPs or hostnames.
```

---

## 4. Variações temáticas (escolher uma como destaque)

### A. Foco em velocidade
> Adicionar ao prompt: *"Extreme motion blur on data particles, long light trails like a Formula 1 night race, suggesting that detection-to-response happens in milliseconds. Time-warp effect around the pipeline center."*

### B. Foco em controle
> Adicionar ao prompt: *"A central command throne with a single operator's silhouette (back-view, no face) sitting calmly at the center, hands hovering over a transparent multi-touch console — total mastery, no chaos."*

### C. Foco em vigilância
> Adicionar ao prompt: *"Multiple watchful eye motifs subtly embedded in different panels, a slow radar sweep crossing the entire scene, scanning grid lines covering the floor."*

---

## 5. Mapeamento — elementos visuais ↔ realidade do Guardian

| Elemento visual | O que representa no código |
|-----------------|----------------------------|
| 3 servidores holográficos | Servers monitorados via SSH (`servers` table) |
| Feixes SSH conectando servidores ao pipeline | `SSH ControlMaster` reutilizando conexões a cada 2 min |
| Pipeline de 6 estágios | `Collectors → Normalizer → Detector → Enricher → Correlator → Ingestor` |
| Painel de rede neural | DGA Classifier ONNX + IP Threat Classifier ONNX |
| Cascata de 4 orbes (Ollama → Gemini → OpenAI → Claude) | `AIProvider` com fallback em cascata (`src/services/ai-provider.ts`) |
| Globo com vetores de ataque convergindo | `Threat Intelligence` (AbuseIPDB + VirusTotal) + Threat Hunter Worker |
| Escudos hexagonais ativando | `Playbooks` automatizados (block-ip, rate-limit, kill-process) |
| Tags "BLOCKED" em amber | Tabela `blocked_ips` com método (UFW / iptables / fail2ban) |
| Olho vigilante central | `IntelligenceWorker` + `ThreatHunterWorker` (análise proativa a cada 4h) |
| Varredura de radar | Workers de monitoramento contínuo (FIM 4h, CVE 6h, IP scorer 2h) |
| Velocidade / motion blur | Pipeline síncrono — detecção em milissegundos sobre buffer circular de 2000 eventos |

---

## 6. Negative prompt (o que evitar)

Para plataformas que aceitam negative prompt (Stable Diffusion, Midjourney `--no`):

```
no real IP addresses, no real hostnames, no readable log lines, no human faces visible, no corporate logos, no Windows UI elements, no light/bright background, no pastel colors, no cartoonish style, no flat 2D design, no stock-photo look, no clutter, no lens dirt, no watermarks, no text artifacts
```

---

## 7. Dicas finais

- **Gemini Imagen:** Aceita prompts longos e estruturados — use o prompt #1 inteiro
- **ChatGPT/DALL-E 3:** Pode reescrever o prompt internamente; use o #2 para preservar a narrativa cinematográfica
- **Midjourney:** Use o prompt curto #3 + parâmetros `--ar 16:9 --style raw --v 6 --stylize 750`
- **Stable Diffusion:** Use o #3 como positive prompt e o #6 como negative prompt; aplicar LoRA "synthwave" ou "cyberpunk" se disponível
