# Falsos positivos calibrados

Última atualização: 2026-05-29

Casos onde minha primeira análise sugeriu "isto é problema" mas no contexto do Guardian é correto. Calibração pra evitar ruído em reviews futuros.

## Convenção

Cada entrada:
- **Padrão que sinalizei**
- **Por que parecia errado**
- **Por que é correto no Guardian**
- **Como diferenciar de bug real**

## Entradas

(vazio por enquanto — popular quando casos surgirem em revisões reais)

## Casos típicos esperados

Esta lista é especulativa, vou confirmar conforme encontrar:

### API de processo Node em utils/

`src/utils/execFileNoThrow.ts` é o wrapper safe que outros módulos usam. Se vejo a API de processo em um worker direto, é problema; em `utils/`, é o ponto de definição autorizado.

### `console.log` em scripts/

Scripts em `scripts/` (treino de ML, utilitários standalone) podem usar `console.log` legitimamente — não passam pelo logger pino. Só o código em `src/` deve usar logger estruturado.

### Imports relativos sem `.js` em arquivos de teste

Tests em `tests/` rodam via Vitest que tem resolution diferente. Se `tests/foo.test.ts` importa `'./helpers'` sem `.js`, pode ser intencional. Confirmar configuração antes de sinalizar.

### `any` em tipo de retorno do AI provider

Respostas de LLM são genuinamente `unknown`. `any` aqui é menos problema que sobre-tipagem de algo que muda.

## Como atualizar este arquivo

- Sinalizei algo, usuário/architect explicou que é correto: registra com explicação completa
- Padrão recorrente que sempre flago e sempre é OK: adiciona como "calibração permanente"
- Padrão que era OK antes mas virou bug (mudança no projeto): move pra `recurring-bugs.md`
