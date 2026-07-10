# Memória do guardian-docs-writer

Última atualização: 2026-05-29

## Índice

- [Style guide](style-guide.md) — tom, formatação, headers, code blocks (estrutura aprovada de docs/ está aqui dentro)
- [Glossário PT/EN](glossary-pt-en.md) — terminologia técnica
- [Status dos arquivos](docs-status.md) — qual existe, qual está atualizado, qual EN está sincronizado
- [Features pendentes](features-to-document.md) — features novas que ainda não estão no README

## Estado atual

- README atual (`README.md`): em PT-BR, parcialmente desatualizado
- README EN (`README.en.md` ou similar): **não existe** ou desatualizado
- Pasta `docs/`: **não existe ainda** — estrutura aprovada mas não criada
- 13 features novas identificadas como faltantes no README

## Onde paramos (2026-05-29)

Estrutura aprovada pelo usuário:
- PT-BR primário, EN secundário
- 4 subdiretórios: `instalacao/`, `operacao/`, `arquitetura/`, `avancado/`
- 28+ arquivos por idioma, total ~56+ arquivos
- Primeiro entregável proposto: README PT atualizado com feature list completa

Aguardando autorização do usuário pra começar. Pergunta pendente: qual ordem?
- **Opção A**: implementar Tier 0 (modelo de instalação seguro) primeiro, **depois** documentar (docs refletem estado real)
- **Opção B**: documentar estado atual primeiro, **depois** implementar (docs ficam desatualizadas no momento da implementação)

Recomendação técnica: Opção A. Mas Opção B entrega valor pro usuário operar Guardian hoje.

## Como me usar

Quando usuário pedir:
- "atualiza o README" → leia `features-to-document.md`, faça em PT primeiro, marca EN como desatualizado em `docs-status.md`
- "cria o tutorial de X" → cheque se a feature existe no código antes (`Read` arquivos relevantes), siga estrutura em `docs-structure.md`
- "como dizer X em inglês?" → consulte `glossary-pt-en.md`, atualize se faltar termo

## Anti-padrões

- Não documentar feature que ainda não existe no código (a não ser com `status: planejado` em frontmatter)
- Não copiar tom de marketing ("o melhor SIEM do mundo") — Guardian é projeto pessoal honesto
- Não traduzir literal PT→EN (usar idiomatic English)
- Não esquecer link de "próximo passo" no fim de cada tutorial
