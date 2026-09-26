# Roteiro da demonstração do ZUNVIO

Este roteiro explica, em linguagem comum, como apresentar o valor do ZUNVIO em
menos de um minuto. Ele usa **projetos sintéticos** — nenhum código real de
cliente e nenhum segredo operacional.

## O que vamos mostrar

O ZUNVIO olha um projeto e responde a uma pergunta simples: **podemos avançar?**
E, quando a resposta é "não", ele diz **o que bloqueou, por que importa e o que
fazer agora**. Quando corrigimos o problema, a decisão muda junto — só porque a
evidência mudou, sem trapaça.

## Como executar

```bash
node bin/zunvio-demo.mjs
```

Um único comando roda a jornada completa, em diretórios temporários, sem internet
e sem alterar nada fora desses diretórios.

## O que aparece e como explicar

1. **"Preparando o ZUNVIO neste computador…"**
   → A preparação é feita **uma única vez**. Depois disso, em qualquer projeto,
   basta usar `/zunvio-score`.

2. **Projeto "apto" (limpo, com evidência)**
   → Decisão: `PUBLICAR`. Podemos avançar? **Sim** — e o porquê é verificável: todos os arquivos foram lidos por inteiro pelo scanner de segredos e todo o histórico Git esperado foi varrido, sem nenhum achado (LC-06).
   → O que foi comprovado? `90%` dos portões — o ZUNVIO é honesto: não afirma o
   que não verificou (os 10% restantes são cobertura opcional, declarada).

3. **Projeto "bloqueado" (com um token falso de teste)**
   → Decisão: `NÃO PUBLICAR`.
   → O que bloqueou? Um token sintético detectado no código.
   → Por que importa? Credencial exposta pode dar acesso indevido.
   → O que fazer agora? Remover/rotacionar o token e rodar de novo.

4. **Correção (remover o token) e reanálise**
   → O `HEAD` (versão analisada) muda, o bloqueio some e a decisão volta para `PUBLICAR`.
   → Isso prova que a decisão **responde à evidência**, não a cache, regra
   alterada ou "relaxamento" de portão.

5. **Provas**
   → Para cada análise, o ZUNVIO gera um recibo (Evidence Pack) com hash.
   → O recibo da análise "bloqueada" continua válido e verificável depois da
   correção — o histórico é auditável.

## As seis perguntas (resumo)

| Pergunta | Onde aparece na saída |
|---|---|
| Podemos avançar? | `Decisão: PUBLICAR` / `NÃO PUBLICAR` (`PUBLICAR` só com a cobertura de segredos demonstrada) |
| O que foi comprovado? | `Cobertura: N%` |
| O que bloqueou? | `→ o que bloqueou` |
| Por que importa? | `→ Importa porque…` |
| O que fazer agora? | `→ O que fazer…` |
| Onde estão as provas? | `→ Provas (Evidence Packs/receipts)` |

## Limitações (o que a demo NÃO prova)

- Não é certificação de segurança absoluta: a decisão vale para a versão analisada
  e para o que foi possível verificar.
- São projetos sintéticos, não o repositório real de um cliente.
- Um segredo que já foi **commitado** exige, na prática, também **rotacionar a
  credencial** e limpar o histórico; a demo simplifica gerando um release limpo,
  e registra essa limitação honestamente.

Os detalhes técnicos (caminhos, hashes, motores) ficam na seção "Detalhes
técnicos" da própria saída do comando.
