# ZUNVIO — scan gratuito (distribuição de teste)

A ZUNVIO analisa **uma versão exata** de um projeto de software e responde, com prova,
à pergunta que importa antes de publicar: **podemos avançar com esta versão?**

A análise é 100% local e **somente leitura** — nada no projeto é alterado (o relatório
comprova a imutabilidade ao final) e nada sai da sua máquina.

## Usar sem instalar nada da ZUNVIO

Com Node.js 20+ e Git na máquina:

```
npx github:marlonsjbb/zunvio-free analyze CAMINHO\DA\PASTA
```

Exemplo:

```
npx github:marlonsjbb/zunvio-free analyze D:\Projetos\meu-sistema
```

## Ou instalar o comando `zunvio` de vez

```
npm install -g github:marlonsjbb/zunvio-free
zunvio analyze CAMINHO\DA\PASTA
```

## Requisitos

| Ferramenta | Obrigatória? | Como conferir |
| --- | --- | --- |
| Node.js 20+ | Sim | `node --version` |
| Git | Sim | `git --version` |
| Gitleaks | Sim (portão de segredos) | `gitleaks version` — instala com `winget install gitleaks` |
| Semgrep | Não | sem ele, o portão de segurança estática fica honestamente "não comprovado" |

## Como ler o resultado

Leia nesta ordem: **DECISÃO** (PUBLICAR · NÃO PUBLICAR · INCONCLUSIVO) →
**COBERTURA** (quanto foi de fato comprovado) → **Próximas ações** (o que fazer).
Score alto nunca compensa um bloqueador; na dúvida, a ZUNVIO não autoriza avançar.

## Sobre esta distribuição

- Conteúdo: somente os arquivos necessários para o scan gratuito (CLI `analyze` e
  `verify`), extraídos da linha principal do produto.
- Proveniência: base `main@688293e` do repositório principal + correção da projeção
  do Evidence Pack (contrato de ingestão).
- **Código-fonte disponível para avaliação. Todos os direitos reservados — MASS.**
  Esta é uma distribuição de teste; não é uma licença de uso livre nem um pacote
  de código aberto.
