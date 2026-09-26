<div align="center">

<img src="marca/zunvio-wordmark-color.png" alt="ZUNVIO" width="480" />

<br />

### Confiança antes de publicar.

**Analise uma versão exata do seu projeto e descubra, com evidências, se ela está pronta para publicação.**

```bash
npx zunvio-score
```

[Site](https://zunvio.com.br/) · [Termos de uso](LICENSE.md)

</div>

---

## O que é o ZUNVIO?

Criar software ficou mais rápido. Saber se ele está realmente pronto para publicar continua difícil.

O **ZUNVIO** faz uma análise estática local do projeto e transforma o resultado em uma decisão simples:

| Decisão | O que significa |
|---|---|
| **PUBLICAR** | As verificações obrigatórias foram avaliadas e nada impede a publicação dentro do escopo analisado. |
| **NÃO PUBLICAR** | Há risco demonstrado, revisão pendente ou evidência obrigatória ausente. |
| **INCONCLUSIVO** | O ZUNVIO não conseguiu analisar o necessário para sustentar uma decisão. |

A regra é simples: **ausência de evidência nunca é tratada como sucesso.**

O ZUNVIO não executa nem altera o projeto durante a análise. O código é analisado localmente e não é intencionalmente enviado aos serviços do ZUNVIO como parte dessa análise.

## Comece em um comando

Na raiz de um repositório Git:

```bash
npx zunvio-score
```

Ou informe outra pasta:

```bash
npx zunvio-score caminho/do/projeto
```

Na primeira execução, o ZUNVIO prepara os motores necessários dentro de `~/.zunvio`.

**Requisitos**

- Node.js 20.10+
- Git
- Python 3.10+ para o ambiente isolado do Semgrep

Se algum motor obrigatório não estiver disponível, o ZUNVIO não transforma essa ausência em aprovação: a cobertura correspondente fica **NÃO COMPROVADA**.

## O que você recebe

Uma análise não termina apenas com um score. O ZUNVIO entrega:

- **decisão de publicação**, acompanhada do motivo principal;
- **achados em português**, explicando o que foi observado e por que importa;
- **cobertura da análise**, incluindo o que não pôde ser verificado;
- **próxima ação**, quando a evidência permite indicá-la;
- **evolução entre análises**, com itens novos, resolvidos e persistentes;
- **relatório HTML local** para leitura e compartilhamento;
- **Evidence Pack em JSON**, com integridade verificável.

O score é secundário. **Uma pontuação alta nunca compensa um bloqueio.**

## Um resultado que não esconde incerteza

Cada verificação termina em um estado explícito:

| Estado | Significado |
|---|---|
| **ATENDE** | Há evidência válida e suficiente. |
| **NÃO ATENDE** | A evidência demonstra um problema. |
| **NÃO COMPROVADO** | A evidência é ausente, inválida ou insuficiente. |
| **NÃO APLICÁVEL** | A verificação não se aplica, com justificativa registrada. |

Arquivos lidos apenas parcialmente são identificados. Falhas e limites de cobertura não viram aprovação silenciosa.

## Fluxo recomendado

### 1. Analise

```bash
npx zunvio-score
```

Leia a decisão, os achados e a cobertura.

### 2. Descreva o contexto do projeto

```bash
npx zunvio-score init
```

O `init` faz perguntas em linguagem simples sobre o projeto, seus usuários, dados e testes.

Essas respostas são **declarações do usuário**, não provas produzidas pelo ZUNVIO. Essa distinção permanece visível no resultado.

### 3. Corrija ou revise

Quando existe **RISCO DEMONSTRADO**, ele precisa ser corrigido.

Quando um item está em **REVISÃO NECESSÁRIA**, o ZUNVIO encontrou um padrão, mas não possui evidência suficiente para afirmar o risco. Depois de revisar o contexto, você pode registrar a decisão:

```bash
npx zunvio-score revisar <chave> --justificativa "motivo da revisão"
```

A revisão:

- não apaga o achado;
- não libera um **RISCO DEMONSTRADO**;
- registra autor, data e justificativa;
- perde validade se o contexto relevante do código mudar;
- permanece auditável no resultado.

### 4. Analise novamente

```bash
npx zunvio-score
```

O ZUNVIO mostra o que surgiu, o que permaneceu e o que foi resolvido desde a análise anterior.

### 5. Verifique a evidência

```bash
npx zunvio-score verify resultado.json
```

O `verify` confere a integridade do resultado em JSON.

## Comandos

| Comando | Função |
|---|---|
| `npx zunvio-score [pasta]` | Analisa o projeto. |
| `npx zunvio-score init [pasta]` | Registra o contexto declarado do projeto. |
| `npx zunvio-score revisar <chave> [pasta]` | Registra uma revisão humana para item elegível. |
| `npx zunvio-score glossario` | Explica os termos do resultado. |
| `npx zunvio-score verify <arquivo.json>` | Verifica a integridade de um resultado. |

## Opções principais

```text
--json                   Resultado em JSON
--relatorio <arquivo>    Caminho do relatório HTML
-d, --diff               Compara duas versões
-c, --contract <arquivo> Contexto do projeto em JSON
-e, --evidence <arquivo> Evidências em JSON
--no-banner              Oculta a arte do terminal
-h, --help               Ajuda
-v, --version            Versão
```

## Como a análise funciona

O ZUNVIO usa análise estática e executa os motores localmente.

- **Semgrep** participa da análise de segurança do código.
- **Gitleaks** participa da análise do histórico Git para segredos.
- O ZUNVIO também produz e verifica evidências próprias de cobertura e decisão.

O resultado registra versões, cobertura e limitações relevantes para que uma execução não aparente mais confiança do que a evidência permite.

## Limitações

O ZUNVIO é uma camada de evidência para apoiar a decisão de publicação, não uma certificação de segurança.

- A análise é estática e não observa comportamentos que existam somente em execução ou produção.
- A cobertura é limitada aos arquivos, regras e motores registrados no resultado.
- Leitura parcial não conta como análise completa.
- A decisão vale para a versão exata analisada.
- Uma decisão **PUBLICAR** significa que os gates definidos foram satisfeitos dentro do escopo analisado; não significa ausência absoluta de vulnerabilidades.

## Uso em CI

O processo retorna códigos de saída apropriados para automação:

| Código | Resultado |
|---:|---|
| `0` | PUBLICAR |
| `1` | NÃO PUBLICAR |
| `2` | INCONCLUSIVO |
| `3` | Erro operacional ou uso inválido |

## Privacidade e execução local

A análise do código-fonte realizada pelo ZUNVIO CLI ocorre localmente. O ZUNVIO não envia intencionalmente o conteúdo do código analisado aos serviços do ZUNVIO como parte dessa análise local.

Semgrep e Gitleaks são componentes de terceiros e permanecem sujeitos às respectivas licenças e comportamentos.

## Termos de uso

O ZUNVIO pode ser usado gratuitamente para analisar projetos próprios ou de terceiros quando você possui autorização, inclusive em uso comercial e CI.

O software é proprietário. Redistribuição, revenda, oferta como serviço e reutilização do software em outro produto dependem dos termos aplicáveis.

Consulte [LICENSE.md](LICENSE.md) para os termos completos.

---

<div align="center">

**Confiança antes de publicar.**

[Conheça o ZUNVIO](https://zunvio.com.br/)

</div>
