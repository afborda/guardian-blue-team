#!/usr/bin/env bash
# Benchmark real AI latency for each Guardian use case
# Usage: bash scripts/benchmark-ai.sh
set -euo pipefail

OLLAMA_URL="http://ollama:11434"
MODEL="${OLLAMA_MODEL:-qwen3:4b}"
EMBED_MODEL="nomic-embed-text"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'

call_ollama() {
  local label="$1"
  local system="$2"
  local prompt="$3"
  local start end ms

  start=$(date +%s%3N)
  local body
  body=$(printf '{"model":"%s","prompt":"%s","system":"%s","stream":false}' \
    "$MODEL" \
    "$(echo "$prompt" | head -c 800 | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read())[1:-1])')" \
    "$(echo "$system" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read())[1:-1])')")

  local out
  out=$(curl -sf --max-time 180 "$OLLAMA_URL/api/generate" \
    -H 'Content-Type: application/json' \
    -d "$body" 2>/dev/null) || { echo -e "  ${RED}✗ timeout / error${NC}"; return; }

  end=$(date +%s%3N)
  ms=$((end - start))

  local tokens
  tokens=$(echo "$out" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("eval_count",0))' 2>/dev/null || echo "?")
  local response_preview
  response_preview=$(echo "$out" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("response","")[:120].replace("\n"," "))' 2>/dev/null || echo "")

  if   [ "$ms" -lt 10000 ]; then color="$GREEN"
  elif [ "$ms" -lt 30000 ]; then color="$YELLOW"
  else color="$RED"; fi

  printf "  ${color}%ds${NC} (%s tokens)  →  %s\n" "$((ms/1000))" "$tokens" "$response_preview"
}

call_embed() {
  local label="$1"
  local text="$2"
  local start end ms dims

  start=$(date +%s%3N)
  local out
  out=$(curl -sf --max-time 30 "$OLLAMA_URL/api/embeddings" \
    -H 'Content-Type: application/json' \
    -d "{\"model\":\"$EMBED_MODEL\",\"prompt\":\"$text\"}" 2>/dev/null) || { echo -e "  ${RED}✗ error${NC}"; return; }
  end=$(date +%s%3N)
  ms=$((end - start))

  dims=$(echo "$out" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(len(d.get("embedding",[])))' 2>/dev/null || echo "?")
  printf "  ${GREEN}%dms${NC} (%s dims)\n" "$ms" "$dims"
}

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Guardian AI Benchmark — modelo: $MODEL${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""

# ── 1. Embedding (RAG memory) ────────────────────────────────────────────────
echo -e "${CYAN}[1] Embedding (RAG / incident memory)${NC}"
call_embed "embed" "ssh brute force attack 45 attempts port 22 blocked ip 185.234.219.78 unauthorized login"
echo ""

# ── 2. Block Advisor ─────────────────────────────────────────────────────────
echo -e "${CYAN}[2] Block Advisor — decidir se bloqueia IP${NC}"
call_ollama "block_advisor" \
  "Responda apenas com JSON válido, sem markdown." \
  "Você é um SOC analyst decidindo a resposta para um incidente de segurança. EVENTO: Tipo: brute_force, Severidade: high, IP: 185.234.219.78, Servidor: hetzner-prod. CONTEXTO: 45 tentativas SSH em 10 min, IP com AbuseIPDB score 87/100. HISTÓRICO RAG: incidente similar em 2024-01 com mesmo /24. DECISÃO: responda JSON {\"action\":\"block\"|\"monitor\"|\"ignore\",\"confidence\":0-100,\"reason\":\"...\"}."

# ── 3. Root Cause ────────────────────────────────────────────────────────────
echo -e "${CYAN}[3] Root Cause Analysis${NC}"
call_ollama "root_cause" \
  "Você é um analista de infraestrutura. Responda sempre em JSON válido." \
  "Analise a causa raiz deste incidente: tipo=brute_force, 45 eventos SSH em 10 min, IP 185.234.219.78 (score 87), servidor hetzner-prod. Eventos recentes no mesmo servidor: port_scan 3h atrás, 2 falhas de autenticação. Responda JSON {\"rootCause\":\"...\",\"confidence\":0-100,\"recommendations\":[]}."

# ── 4. Discovery Analyzer ────────────────────────────────────────────────────
echo -e "${CYAN}[4] Discovery Analyzer — mudanças de infraestrutura${NC}"
call_ollama "discovery" \
  "You are a server security analyst. Respond with valid JSON only." \
  "Server scan diff for hetzner-prod: NEW services=[containerd,apparmor,systemd-resolved], NEW ports=[53,2222], REMOVED ports=[]. Port 2222: socat TCP-LISTEN:2222,bind=172.26.0.1 -> 127.0.0.1:49222 (sshd mux). Analyze and respond JSON {\"riskLevel\":\"low|medium|high\",\"findings\":[],\"recommendation\":\"...\",\"confidence\":0-100}."

# ── 5. Threat Hunter ─────────────────────────────────────────────────────────
echo -e "${CYAN}[5] Threat Hunter — análise proativa (prompt maior)${NC}"
call_ollama "threat_hunt" \
  "Responda apenas com JSON válido. Seja conservador: prefira falso negativo a falso positivo." \
  "Você é analista SOC sênior. Analise eventos das últimas 4h no hetzner-prod. EVENTOS (resumo): 120x brute_force de 15 IPs distintos, 3x port_scan, 1x unauthorized_login (bloqueado). IPs bloqueados: 12. Nenhum acesso bem-sucedido suspeito. Containers: todos healthy. PERGUNTA: há padrão de ameaça coordenada ou persistente? Responda JSON {\"findings\":[{\"type\":\"...\",\"severity\":\"low|medium|high|critical\",\"description\":\"...\",\"recommendation\":\"...\"}],\"overallRisk\":\"low|medium|high\",\"summary\":\"...\"}."

# ── 6. SOC Analyst (/ask) ────────────────────────────────────────────────────
echo -e "${CYAN}[6] SOC Analyst — resposta a pergunta manual (/ask)${NC}"
call_ollama "soc_ask" \
  "You are a SOC analyst assistant. Answer security questions based on available data in Portuguese (BR)." \
  "O IP 185.234.219.78 foi bloqueado 3 vezes esta semana. É um atacante persistente ou scanner automatizado? Contexto: sempre tenta porta 22, horários variados, AbuseIPDB score 87."

# ── 7. Recommendations ───────────────────────────────────────────────────────
echo -e "${CYAN}[7] Recommendations — sugestões de hardening${NC}"
call_ollama "recommendations" \
  "Você é um consultor de infraestrutura. Responda apenas com JSON válido." \
  "Servidor hetzner-prod, Ubuntu 22.04, 8 containers Docker, score de segurança 72/100. Problemas detectados: 3 containers sem health check, porta 22 exposta, fail2ban ativo. Gere 3 recomendações prioritárias. JSON {\"recommendations\":[{\"priority\":1,\"title\":\"...\",\"description\":\"...\",\"effort\":\"low|medium|high\"}]}."

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  Benchmark completo${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo "  Verde  = <10s   Amarelo = 10-30s   Vermelho = >30s"
echo ""
