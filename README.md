# ZUNVIO Score

Responde, com prova, se uma versão exata do seu projeto está pronta para publicar.

A análise é uma leitura estática local: roda na sua máquina e só lê o projeto (não executa nem altera nada). O ZUNVIO não envia intencionalmente o código analisado a serviços externos como parte dessa análise.
O resultado é uma decisão — `PUBLICAR`, `NÃO PUBLICAR` ou `INCONCLUSIVO` — acompanhada do que a sustenta e do que ficou
de fora. O resultado separa achados do cliente, limites de cobertura do motor e falhas do próprio motor, e sai também
como um artefato JSON verificável.

---

## Começar

Na pasta do projeto (um repositório Git):

```bash
npx zunvio-score
```

Ou indique a pasta:

```bash
npx zunvio-score caminho/do/projeto
```

Na primeira execução o ZUNVIO prepara os dois motores de análise, sem instalar nada fora da pasta `~/.zunvio`:

- **Gitleaks** (segredos): baixado do release oficial, com o SHA-256 conferido.
- **Semgrep** (segurança do código): instalado num ambiente Python isolado (~150 MB).

Requisitos: **Node.js 20.10+**, **Git** e **Python 3.10+** (usado só para instalar o Semgrep). Sem um dos motores a
análise ainda roda, mas a parte correspondente fica `NÃO COMPROVADO` e a decisão não chega a `PUBLICAR`.

## Os comandos

| Comando | Para quê |
|---|---|
| `npx zunvio-score [pasta]` | Analisa o projeto e mostra a decisão, os achados e o que fazer agora. |
| `npx zunvio-score init [pasta]` | Perguntas em linguagem simples sobre o projeto: o que ele faz, quem usa, que dados trata, como foi testado. |
| `npx zunvio-score revisar <chave> [pasta]` | Registra a sua revisão de um item marcado **REVISÃO NECESSÁRIA**. |
| `npx zunvio-score glossario` | Explica os termos usados no resultado. |
| `npx zunvio-score verify <arquivo.json>` | Confere se um resultado em JSON não foi alterado. |

### `init`: descrever o projeto

Sem saber o que o projeto é e como foi testado, o ZUNVIO não tem como afirmar que ele está pronto — e diz isso.
O `init` faz as perguntas e explica, em cada uma, por que ela importa. As respostas ficam **fora do repositório**
(em `~/.zunvio/projetos/`), valem para a versão analisada e são tratadas como **declaração sua**, não como prova.
O resultado mostra o que foi declarado e o que ainda precisa ser comprovado.

### `revisar`: registrar a revisão de um item

Alguns achados vêm como **REVISÃO NECESSÁRIA**: o padrão existe no código, mas o risco não foi demonstrado (por exemplo,
uma URL montada a partir de uma variável cuja origem não se conhece). Se você revisou e não é risco no seu contexto,
cada item mostra o comando pronto, com a chave dele:

```bash
npx zunvio-score revisar 3f9a1c0b7d2e4a65 --justificativa "o host vem da configuração interna, não do usuário"
```

A revisão é **evidência adicional, não prova de segurança**:

- vale só para **REVISÃO NECESSÁRIA** — um **RISCO DEMONSTRADO** nunca é liberado por revisão;
- o achado continua no resultado, marcado como "revisado por humano e aceito neste contexto", com autor, data e justificativa;
- se o código em volta do item mudar, a revisão perde a validade e o item volta a impedir a publicação;
- fica no arquivo `.zunvio-baseline.json` do projeto, para ser versionada junto com o código.

## O que você recebe

- **Decisão e motivo principal**, com o que fazer agora.
- **Achados** explicados em português: o que foi encontrado, por que importa e o que foi (ou não) demonstrado.
- **Score e cobertura**: o score é secundário — score alto não compensa um bloqueio.
- **Relatório HTML** para compartilhar, gravado fora do projeto (o caminho aparece no fim da análise). É gerado
  localmente e mostra decisão, cobertura, achados, revisões, limitações, versão do motor e o hash que protege o resultado.
- **Evolução** desde a análise anterior: achados novos, resolvidos e persistentes, e mudança de score e de decisão.
- **Resultado em JSON** (`--json`), com hash canônico, verificável depois com `npx zunvio-score verify`.

## Como ler o resultado

Códigos de saída:

| Código | Decisão | Significado |
|---|---|---|
| `0` | `PUBLICAR` | Tudo o que é obrigatório foi avaliado e nada impede a publicação. |
| `1` | `NÃO PUBLICAR` | Algo no projeto impede a publicação: risco demonstrado, revisão pendente ou evidência que falta. |
| `2` | `INCONCLUSIVO` | A análise não conseguiu cobrir o necessário (motor ausente, falha, tempo esgotado). |
| `3` | erro | Uso inválido ou falha operacional. |

Cada verificação termina em um destes estados:

| Estado | Significado |
|---|---|
| `ATENDE` | Evidência válida e suficiente. |
| `NÃO ATENDE` | A evidência mostra um problema. |
| `NÃO COMPROVADO` | Evidência ausente, inválida ou não produzida. Ausência de evidência nunca vale como sucesso. |
| `NÃO APLICÁVEL` | Não se aplica a este projeto, com justificativa registrada. |

## Opções

```text
--json                   Resultado em JSON
--relatorio <arquivo>    Onde gravar o relatório HTML
-d, --diff               Compara com uma versão anterior (--base <ref>, --head <ref>)
-c, --contract <arquivo> Descrição do projeto em JSON (alternativa ao init)
-e, --evidence <arquivo> Evidências em JSON (alternativa ao init)
--no-banner              Sem a arte no topo do resultado
-h, --help               Ajuda
-v, --version            Versão
```

## Limites

- A análise é estática: não executa o projeto e não vê o que só acontece em produção.
- Cobre os arquivos, motores e regras registrados no resultado; o que fica de fora aparece como limitação.
- Arquivos que um motor conseguiu ler só em parte aparecem nomeados, com o motivo; leitura parcial nunca conta como prova.
- A decisão vale para a versão exata analisada (o commit registrado no resultado).

## Termos de uso

Uso gratuito para analisar projetos seus ou de terceiros que você tenha autorização para analisar, inclusive em uso
comercial e em CI. O código é proprietário: não pode ser redistribuído, revendido, oferecido como serviço nem
reutilizado em outro software sem autorização. Os termos completos estão em [LICENSE.md](LICENSE.md).

Site: https://zunvio.com.br/
