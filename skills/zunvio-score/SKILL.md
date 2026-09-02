---
name: zunvio-score
description: Analisa a prontidão de publicação de uma versão exata de um projeto de software e devolve uma decisão com prova (PUBLICAR, NÃO PUBLICAR ou INCONCLUSIVO). Use quando o usuário digitar /zunvio-score ou pedir para analisar um projeto com a ZUNVIO.
---

# ZUNVIO Score

A ZUNVIO responde, com prova, se uma versão exata de um projeto pode ser publicada.
A análise é 100% local e somente leitura: nada no projeto é alterado e nada sai da
máquina da pessoa.

## Como executar

Requisitos na máquina: Node.js 20+ e Git.

```
npx -y zunvio-score analyze "<caminho-da-pasta-do-projeto>"
```

Para analisar um repositório público remoto, clone primeiro em uma pasta temporária
e analise a pasta clonada.

## Motores de análise

A ferramenta usa dois motores externos: Gitleaks (detector de segredos) e Semgrep
(analisador de padrões perigosos no código). Se algum estiver faltando, ela oferece
instalação automática verificada, mas NUNCA instala sem consentimento. Em terminal
não interativo (o caso típico de um agente), a instalação só acontece com a variável
de ambiente ZUNVIO_AUTO_MOTORES=1.

Regra para o agente: pergunte ao usuário antes. Explique que a ZUNVIO quer baixar o
Gitleaks (release oficial no GitHub, hash SHA-256 conferido, guardado em ~/.zunvio)
e/ou o Semgrep (PyPI oficial, versão fixada, ambiente Python isolado em ~/.zunvio,
requer Python 3.10+). Só rode com ZUNVIO_AUTO_MOTORES=1 depois do "sim" explícito do
usuário. Sem os motores a análise continua funcionando, com os portões
correspondentes marcados como NÃO COMPROVADO.

## Como interpretar o resultado

O código de saída do comando É a decisão, nunca um erro do processo:

- 0 = PUBLICAR
- 1 = NÃO PUBLICAR (existe bloqueador comprovado)
- 2 = INCONCLUSIVO (não foi possível comprovar o suficiente)

Apresente ao usuário, nesta ordem: a DECISÃO, a COBERTURA (quanto foi de fato
comprovado) e as Próximas ações que o próprio relatório lista. Score alto nunca
compensa um bloqueador; na dúvida, a ZUNVIO não autoriza avançar.

## Limites obrigatórios

- Nunca imprima segredos encontrados nem trechos brutos de achados; use os
  identificadores e severidades que o relatório já mostra.
- Nunca cole o JSON completo do Evidence Pack na conversa.
- Não tente "consertar" a decisão: se deu NÃO PUBLICAR ou INCONCLUSIVO, explique a
  causa e as ações que o relatório recomenda.
- Nunca use os termos APROVADO, CERTIFICADO ou VERIFIED para descrever o resultado;
  o vocabulário da decisão é PUBLICAR, NÃO PUBLICAR e INCONCLUSIVO.
