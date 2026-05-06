# Inteligencia ML

Guardian usa Machine Learning **local e leve** para reduzir falsos positivos e detectar ameacas que regras estaticas perdem.

---

## Por que ML num SIEM leve?

| Problema sem ML | Solucao com ML |
|----------------|----------------|
| Seu proprio login de IP novo gera alerta | ML sabe seus horarios e IPs habituais — nao alerta |
| Container reinicia 1x e gera incidente | ML sabe que 1 restart/semana e normal para esse container |
| 100+ alertas/dia, maioria falso positivo | Scoring 0-1 filtra ruido — so escala quando score > 0.7 |
| Ataque coordenado nao detectado (nenhuma regra individual dispara) | Combinacao de fatores anomalos gera score alto |

**Impacto estimado**: reducao de ~50% em falsos positivos apos 7 dias de aprendizado.

---

## SSH Behavior Profiling

Aprende o comportamento normal de cada usuario SSH:

### O que rastreia (por usuario, por servidor)

| Metrica | Como usa |
|---------|---------|
| Horarios de login | Mapa de frequencia por hora (0-23) |
| IPs conhecidos | Top 20 IPs mais frequentes |
| Fingerprints | Chaves SSH utilizadas |
| Velocidade de login | Media de logins/dia |
| Primeira/ultima vez | Janela temporal do perfil |

### Scoring (0 a 1)

| Fator | Peso | Exemplo |
|-------|------|---------|
| IP desconhecido | +0.3 | Login de IP nunca visto antes |
| Horario incomum | +0.3 | Login as 3am quando usuario so loga 9-18h |
| Fingerprint nova | +0.2 | Chave SSH nunca usada por este usuario |
| Velocidade alta | +0.2 | 3x mais logins que a media |

**Resultado**:
- Score >= 0.7 → severidade elevada para `high`
- Score >= 0.85 → severidade elevada para `critical`
- Score < 0.3 → login normal, nao gera ruido

### Exemplo real

```
Usuario: admin
Horario: 03:22 (nunca logou entre 00-06)
IP: 185.220.101.34 (nunca visto)
Fingerprint: SHA256:abc123 (conhecida)

Score: 0.6 (unknown_ip + unusual_hour)
Acao: Alerta medium, nao escala
```

Se o mesmo login tivesse fingerprint nova: score 0.8 → alerta high.

---

## Container Behavior Profiling

Aprende o comportamento normal de cada container Docker:

### O que rastreia (por container, por servidor)

| Metrica | Como calcula |
|---------|-------------|
| CPU normal | Media + desvio padrao (atualizado incrementalmente) |
| Memoria normal | Media + desvio padrao |
| Restarts/semana | Contagem de eventos de restart em 7 dias |
| Uptime medio | Tempo entre starts consecutivos |

### Anomalias detectadas

| Anomalia | Condicao | Severidade |
|----------|----------|-----------|
| Crashloop | 3+ restarts/semana OU uptime medio < 1h | high/critical |
| Memory leak | Memoria > 1.5x da media normal | high |
| CPU spike | CPU > 3 desvios padrao acima do normal | high |
| Container desapareceu | Perfil existe mas container nao esta rodando | medium |

### Exemplo: Deteccao de crypto mining

```
Container: web-app
CPU normal: 5.2% (stdDev: 3.1%)
CPU atual: 94.7%

Desvio: (94.7 - 5.2) / 3.1 = 28.9σ
Score: 0.95 (cpu_28.9σ_above_normal)
Acao: Alerta critical + playbook pause_container
```

---

## Anomaly Detection (Z-Score)

Detecta desvios estatisticos em qualquer metrica do servidor:

- **Janela**: 7 dias de dados historicos
- **Threshold**: 2.5 desvios padrao
- **Metricas**: load, memoria, disco, I/O, conexoes
- **Ciclo**: a cada 1 hora

Quando uma metrica excede 2.5σ do valor esperado:
- `medium`: 2.5-3.5σ
- `critical`: > 3.5σ

---

## Trend Prediction (Regressao Linear)

Preve esgotamento de recursos antes que aconteca:

- **Disco**: com base na taxa de crescimento diario, calcula quando atingira 90%
- **Memoria**: detecta tendencia de uso crescente
- **Confianca**: R² da regressao (descarta predicoes com baixa confianca)

**Alertas**:
- Disco chegara a 90% em < 7 dias → alerta high
- Disco chegara a 90% em < 14 dias → alerta medium

---

## Consumo de Recursos do ML

| Componente | RAM adicional | CPU | Frequencia |
|-----------|---------------|-----|-----------|
| SSH Profiling | ~2MB (perfis em JSONB) | < 0.1% | 1x/hora |
| Container Profiling | ~2MB (perfis em JSONB) | < 0.1% | 1x/hora |
| Anomaly Detection | ~5MB (janela 7 dias) | < 0.5% (pico) | 1x/hora |
| Trend Prediction | ~3MB (dados de regressao) | < 0.2% | 1x/hora |
| **Total** | **~12MB** | **< 1% medio** | **Ciclo de 1h** |

O ML nao depende de Ollama nem de nenhum provider externo — roda puramente em codigo TypeScript com estatistica basica.

---

## Como melhora com o tempo

| Tempo | Comportamento |
|-------|-------------|
| Dia 1 | Sem baselines — todos os logins tem score 0.3-0.4 (incerto) |
| Dia 3 | Perfis iniciais formados — comeca a distinguir normal vs anomalo |
| Semana 1 | Baselines estaveis — scoring preciso, falsos positivos caem |
| Mes 1 | Perfis maduros — detecta ate mudancas sutis de comportamento |

Nao requer treinamento manual, configuracao de thresholds, ou intervencao humana.
