# Demonstração sintética do ZUNVIO

Este diretório contém **exemplos sintéticos** usados somente para demonstrar o
valor do ZUNVIO. Nenhum arquivo aqui é código real de cliente, e nenhum segredo
operacional existe: qualquer token é um valor falso reservado para teste,
reconhecível como não operacional.

- `fixtures/apto/` — projeto limpo que **pode avançar**.
- `fixtures/bloqueado/` — projeto com uma falha sintética que **deve ser bloqueado**.
- `fixtures/evidencias.json` — evidência externa mínima (funcionamento comprovado).

O roteiro da demonstração está em `ROTEIRO.md`. Para repetir a jornada completa:

```bash
node bin/zunvio-demo.mjs
```
