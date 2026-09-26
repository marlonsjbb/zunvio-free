# Rulepack do ZUNVIO

Este diretório é a configuração EFETIVA dos dois motores externos que o ZUNVIO
usa para prova positiva (Gitleaks e Semgrep). O hash de cada arquivo alimenta o
`configHash` da identidade do sensor correspondente no Evidence Pack (B5) — uma
mudança aqui é visível na evidência publicada, nunca silenciosa.

## Cobertura atual (MASS-324)

| Rulepack | Regras | O que cobre |
|---|---|---|
| `gitleaks/gitleaks.toml` | 12 | GitHub (PAT clássico + fine-grained), chave de API genérica, AWS, GCP, Azure Storage, Stripe, Slack, SendGrid, npm, JWT literal, chave privada PEM |
| `semgrep/default-rules.yaml` | 11 (PL-05) | `eval` (e `mathjs.eval`), `child_process.exec`/`execSync`, segredo de sessão hardcoded, objeto da requisição como locals de template, `Math.random()` em contexto de segurança, JWT hardcoded, SQL injection (concatenação), path traversal (concatenação), SSRF (concatenação), execução dinâmica de código (`Function`/`vm`), algoritmo criptográfico fraco |

**Total: 21 padrões de detecção** (era 8: 4+4, antes da MASS-324).

### Ampliação de recall (PL-05)

A PL-05 mantém o estilo sintático, sem taint, e não amplia classes. Ela fecha os gaps DENTRO da cobertura medidos
na Bancada Pública v1:

- **SQL, path e SSRF**: o valor pode vir montado de três formas: com `+`, com template literal que tem `${...}`,
  ou numa variável atribuída assim no mesmo escopo, antes da chamada.
- **path**:
  - receptor ligado a `fs`/`fs/promises`;
  - também `appendFile`, `unlinkSync`, `createReadStream`/`createWriteStream`;
  - também `res.sendFile`/`res.download`.
- **SSRF**: clientes axios (todos os métodos), `needle`, `got`, `request`, `superagent` (`request` só ligado ao pacote npm, inclusive `.get`/`.post`) e `http(s).request` (`http(s).get` fica fora: o pré-filtro do Semgrep casa "http"+"get" em qualquer URL — desvio D2).
- **`zunvio.child-process-exec`**: agora cobre `execSync`, que usa o mesmo shell de `exec`, com a mesma identidade de
  símbolo da PL-03.
- **`zunvio.insecure-dynamic-code`**: agora cobre `Function(...)` sem `new`.
- **`zunvio.eval-detection`**: agora cobre `.eval/.evaluate` do `mathjs`, só com o receptor ligado ao pacote.
- **`zunvio.weak-crypto-algorithm`**: agora cobre os pacotes npm `md5` e `sha1`, só com a chamada ligada ao pacote.
- **Duas regras novas**:
  - `zunvio.hardcoded-session-secret`: segredo literal em `session()`/`cookieSession()`/`cookieParser()`;
  - `zunvio.template-locals-from-request`: objeto inteiro `req.body/query/params` passado como variáveis de
    `res.render`.

O significado (`src/models/finding-meaning.mjs`, modelo `pl05-1.0`) decide o efeito de cada achado:

- **INFORMATIVO:** valor montado só com constantes, `__dirname`/`__filename`, `process.cwd()` ou `process.env`.
- **RISCO_DEMONSTRADO:** entrada da requisição demonstrada pelo fluxo local.
- **REVISAO_NECESSARIA:** todo o resto.

## Critério de curadoria

Isto **não é** o ruleset padrão completo do Gitleaks ou do Semgrep importado
sem revisão — os dois motores têm, prontos de fábrica, centenas de regras
cada, e importar tudo sem curadoria trocaria o problema original (cobertura
rasa) por um novo (ruído/falso positivo alto, sem controle sobre o que cada
regra realmente cobre). O critério usado para cada regra nova:

1. **Formato público e documentado do provedor** (Gitleaks) — só prefixos e
   estruturas oficialmente documentados pelo próprio provedor (`AIza` do
   Google, `sk_live_`/`rk_live_` da Stripe, `xox[baprs]-` do Slack, `SG.` do
   SendGrid, `AccountKey=` de connection string do Azure Storage, `npm_` do
   npm, `github_pat_` do GitHub fine-grained PAT). Um padrão genérico
   (`jwt-token`) foi incluído à parte por ter estrutura verificável (`eyJ...`
   três segmentos base64url) independente de provedor.
2. **Idioma de risco mais comum da categoria, não a categoria inteira**
   (Semgrep) — cada regra nova cobre o padrão sintático mais frequente da sua
   classe de CWE (concatenação de string em `.query()`/`fs.*`/`fetch`/`axios`,
   `Function()`/`vm.*` dinâmico, hash MD5/SHA1), no mesmo estilo sintático
   simples (`pattern`/`pattern-either`, sem modo `taint`) já usado pelas 4
   regras originais. Isto é uma limitação deliberada, não um descuido: sem
   rastreamento de dado (taint tracking), qualquer tentativa de cobrir a
   categoria inteira sintaticamente aumentaria FP sem aumentar precisão real.
   Documentada por regra na mensagem (`message`) de cada uma.
3. **Medido antes de entrar**: toda regra nova foi validada contra o corpus
   de referência do benchmark MASS-80 (`benchmark/corpus/`, coorte
   "saudável" + "incompleta" + "adversarial", que juntas cobrem código
   genuinamente limpo e conteúdo hostil) antes de ser aceita — ver seção
   abaixo.

## Medição de falso positivo (MASS-324)

Comparação direta Gitleaks/Semgrep, com as mesmas flags reais usadas pelos
scanners do ZUNVIO (`src/scanners/gitleaks.mjs`, `src/scanners/semgrep.mjs`),
antes (4+4 regras) e depois (12+9 regras) contra os 8 casos do corpus que são
código genuinamente limpo (nenhum segredo real, nenhuma vulnerabilidade
real): `clean-basico`, `clean-evidencia-completa`, `clean-projeto-maior`,
`funcionamento-motor-falhou`, `nao-aplicavel-sem-justificativa`,
`contrato-malformado`, `prompt-injection-hostil`, `unicode-bidi-trojan`.

| Caso | Antes | Depois |
|---|---|---|
| Todos os 8 casos "limpos" acima | 0 achados (Gitleaks + Semgrep) | 0 achados (Gitleaks + Semgrep) |

**Zero falso positivo novo** nos 8 casos limpos. Os 8 casos das coortes
"vulnerável"/"adversarial" (código com problema real de propósito) mantiveram
os mesmos achados de antes, com uma exceção esperada: `fake-secret-documentacao`
passou de 1 para 2 achados do Gitleaks. Essa fixture foi desenhada
deliberadamente (`benchmark/corpus/MANIFESTO.json`) com **dois** formatos de
segredo falso lado a lado (`AKIA...` e `github_pat_...`) para medir a taxa de
FP do sensor de padrão contra formato-sem-ser-segredo-real — o rulepack
anterior só tinha regra para o primeiro formato; a nova regra
`github-pat-fine-grained` fecha exatamente essa lacuna que a própria fixture
já previa. Não é uma regressão nem um FP inesperado: é o comportamento que a
fixture foi construída para verificar, agora com cobertura real.

A suíte completa de testes (`npm test`) e o benchmark MASS-80
(`node benchmark/runner.mjs`) foram re-executados após a ampliação: os 17
gold labels continuam batendo (ver `benchmark/relatorio.md` e o comentário de
evidência na MASS-324 para os números desta rodada específica).

## Limites conhecidos, declarados

- As 5 regras novas de Semgrep são puramente sintáticas (sem `taint`): detectam
  o idioma de concatenação direta, não rastreiam se o dado concatenado
  realmente vem de uma fonte externa. Um `$DB.query(base + "WHERE id = 1")`
  com `base` constante também dispara — é um trade-off deliberado de
  simplicidade/consistência com as regras originais, não uma regra "taint-aware".
- (PL-05) O que continua fora do desenho, por exigir rastreamento de dado (taint):
  - montagem por `path.join`/`path.resolve`;
  - valor cru de um parâmetro sem montagem, por exemplo `fetch(url)` com `url = req.body.url`;
  - fluxo entre arquivos (segredo em `config.js` usado em `session()`);
  - `execFile` sem shell;
  - segredo de fallback em `process.env.X || 'literal'`.
- Nenhuma regra nova cobre Python, Go ou outras linguagens — o rulepack de
  Semgrep permanece `javascript`/`typescript`, mesmo escopo das 4 regras
  originais.
- A contagem de padrões continua sendo uma fração pequena do que os rulesets completos de
  mercado (Gitleaks community rules, Semgrep Registry) cobrem. Isto é
  cobertura curada e defensável, não cobertura exaustiva — não deve ser
  comunicado como equivalente a um scanner com milhares de regras.
