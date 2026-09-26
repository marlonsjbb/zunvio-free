// PL-03 (fechamento) — SIGNIFICADO DO FINDING.
//
//   MATCH → CONTEXTO → EVIDÊNCIA → SIGNIFICADO → DECISÃO
//
// O padrão sintático casar não é, sozinho, risco de publicação. Este módulo transforma a evidência DETERMINÍSTICA
// disponível num de três significados, sempre com as propriedades que foram (ou não) demonstradas:
//   RISCO_DEMONSTRADO  → há evidência suficiente de risco na propriedade analisada. Bloqueia.
//   REVISAO_NECESSARIA → o sinal existe, mas falta contexto para concluir. Continua bloqueando (decisão
//                        conservadora), mas nunca é apresentado como vulnerabilidade comprovada.
//   INFORMATIVO        → o padrão é tecnicamente verdadeiro, mas a evidência demonstra a AUSÊNCIA da propriedade
//                        de risco (ex.: comando constante, código constante, uso protocolar). Não bloqueia.
//
// Restrições (decisão de arquitetura da PL-03):
//  - nada de LLM no caminho de decisão; nada de dataflow genérico: o "fluxo local" é limitado a 3 saltos de
//    atribuição, 60 linhas acima da chamada, no mesmo arquivo;
//  - o CONTEXTO DO ARQUIVO (teste, exemplo, vendor, build…) é registrado como evidência e NUNCA decide sozinho
//    (decisão MASS-399 AJ-01B: nome de diretório não prova ausência de risco);
//  - só há regra de INFORMATIVO/RISCO onde a investigação PL-03 observou a classe; o resto é REVISAO_NECESSARIA.

import { mascararNaoCodigo, argumentosDaChamada, STATUS_IDENTIDADE } from './symbol-identity.mjs';

// PL-05: pl05-1.0 = pl03-1.0 + formas novas (execSync, template/variável montada, clientes HTTP npm, sessão, locals do
// template) e o ramo INFORMATIVO de valor não controlável pelo cliente em SQL/SSRF/path.
export const VERSAO_MODELO_SIGNIFICADO = 'pl05-1.0';

export const CLASSES_SIGNIFICADO = Object.freeze({
  RISCO_DEMONSTRADO: 'RISCO_DEMONSTRADO',
  REVISAO_NECESSARIA: 'REVISAO_NECESSARIA',
  INFORMATIVO: 'INFORMATIVO'
});

export const EFEITOS_NA_DECISAO = Object.freeze({ BLOQUEIA: 'BLOQUEIA', NAO_BLOQUEIA: 'NAO_BLOQUEIA' });

export const ESTADOS_PROPRIEDADE = Object.freeze({
  DEMONSTRADA: 'DEMONSTRADA',
  AUSENTE: 'AUSENTE',
  NAO_DEMONSTRADA: 'NAO_DEMONSTRADA',
  RECUSADA: 'RECUSADA'
});

export const NATUREZAS_ARQUIVO = Object.freeze({
  TESTE: 'TESTE', EXEMPLO: 'EXEMPLO', VENDOR: 'VENDOR', BUILD_SCRIPT: 'BUILD_SCRIPT', DOC_CONFIG: 'DOC_CONFIG', CODIGO: 'CODIGO'
});

const LIMITE_LINHAS_FLUXO = 60;
const LIMITE_SALTOS_FLUXO = 3;

/** Natureza do arquivo por convenção de caminho — EVIDÊNCIA de contexto, nunca decisão. */
export function naturezaArquivoPorCaminho(filePath) {
  const p = String(filePath || '').replace(/\\/g, '/').toLowerCase();
  if (/(^|\/)(vendor|third_party|third-party)\/|\.min\.js$|(^|\/)\.yarn\/releases\//.test(p)) return NATUREZAS_ARQUIVO.VENDOR;
  if (/(^|\/)(test|tests|__tests__|spec|specs|fixtures?|__mocks__|e2e)\/|[._-](test|spec)\.[cm]?[jt]sx?$/.test(p)) return NATUREZAS_ARQUIVO.TESTE;
  if (/(^|\/)(examples?|samples?|demos?)\/|\.example(\.|$)/.test(p)) return NATUREZAS_ARQUIVO.EXEMPLO;
  if (/\.(md|mdx|ya?ml|toml)$|(^|\/)docs?\/|(^|\/)\.env/.test(p)) return NATUREZAS_ARQUIVO.DOC_CONFIG;
  if (/(^|\/)(scripts?|bin|tools?|build|release|ci)\/|(^|\/)(gruntfile|gulpfile)\.|(webpack|rollup|vite)\.config\./.test(p)) return NATUREZAS_ARQUIVO.BUILD_SCRIPT;
  return NATUREZAS_ARQUIVO.CODIGO;
}

const ROTULO_NATUREZA = {
  TESTE: 'arquivo de teste', EXEMPLO: 'arquivo de exemplo', VENDOR: 'código de terceiros incluído no repositório',
  BUILD_SCRIPT: 'script de build/ferramenta', DOC_CONFIG: 'documentação/configuração', CODIGO: 'código do projeto'
};

// Entrada externa por convenção de framework (Express/Koa/Lambda). Demonstra origem de requisição.
const FONTE_REQUISICAO = /\b(?:req|request)\s*\.\s*(?:body|query|params|headers|cookies|files|file|url|originalUrl|path|hostname)\b|\bctx\s*\.\s*(?:request|query|params|headers|cookies)\b|\bevent\s*\.\s*(?:body|queryStringParameters|pathParameters|headers)\b/;
const PALAVRAS_RESERVADAS = new Set(['const', 'let', 'var', 'new', 'return', 'typeof', 'await', 'yield', 'true', 'false', 'null', 'undefined', 'this', 'function', 'async', 'in', 'of', 'instanceof', 'void', 'delete']);

function linhasComoTexto(texto) {
  const inicios = [0];
  for (let k = 0; k < texto.length; k++) if (texto[k] === '\n') inicios.push(k + 1);
  return inicios;
}

/**
 * Localiza, na linha/coluna do match, a chamada de uma das funções/métodos indicados e devolve o índice do "(".
 * Sem coluna válida, só aceita a linha quando há um único candidato.
 */
function localizarChamadaDeRegra(texto, linha, coluna, nomes) {
  const inicios = linhasComoTexto(texto);
  const ini = inicios[linha - 1];
  if (ini === undefined) return null;
  const fim = inicios[linha] ?? texto.length;
  const l = texto.slice(ini, fim);
  const re = new RegExp(`(?:new\\s+)?(?:(?:[\\w$]+\\s*\\.\\s*)*)(?<![\\w$])(?:${nomes.join('|')})\\s*\\(`, 'g');
  const candidatos = [...l.matchAll(re)];
  if (!candidatos.length) return null;
  const col = Number.isInteger(coluna) && coluna > 0 ? coluna - 1 : null;
  let esc = col !== null ? (candidatos.find((m) => m.index === col) || candidatos.find((m) => m.index <= col && col < m.index + m[0].length)) : null;
  if (!esc && candidatos.length === 1) esc = candidatos[0];
  if (!esc) return null;
  return { abre: ini + esc.index + esc[0].length - 1 };
}

/** Divide uma expressão (texto mascarado) nas partes de nível superior separadas por `+`. */
function dividirPorMais(expr) {
  const partes = [];
  let prof = 0; let ini = 0;
  for (let k = 0; k < expr.length; k++) {
    const c = expr[k];
    if ('([{'.includes(c)) prof++;
    else if (')]}'.includes(c)) prof--;
    else if (c === '+' && prof === 0) { partes.push(expr.slice(ini, k)); ini = k + 1; }
  }
  partes.push(expr.slice(ini));
  return partes;
}

/** Identificador com UMA definição `const X = <expressão constante>` no arquivo e nenhuma reatribuição. */
function identificadorConstante(texto, ident, profundidade, opcoes = {}) {
  if (profundidade > 2) return false;
  const id = ident.replace(/\$/g, '\\$');
  const defs = [...texto.matchAll(new RegExp(`\\b(const|let|var)\\s+${id}\\s*(?::[^=;\\n]+)?=(?!=)\\s*`, 'g'))];
  const atribs = [...texto.matchAll(new RegExp(`(?<![\\w$.])${id}\\s*=(?![=>])`, 'g'))];
  if (defs.length !== 1 || defs[0][1] !== 'const' || atribs.length !== 1) return false;
  const ini = defs[0].index + defs[0][0].length;
  const fim = [texto.indexOf('\n', ini), texto.indexOf(';', ini)].filter((x) => x !== -1).reduce((a, b) => Math.min(a, b), texto.length);
  return expressaoConstante(texto, texto.slice(ini, fim), profundidade + 1, opcoes);
}

/** Expressão constante: só literais de string/número, templates cujos ${} são constantes, `+` e identificadores constantes. */
function expressaoConstante(texto, expr, profundidade = 0, opcoes = {}) {
  const partes = dividirPorMais(expr.trim());
  if (!partes.length) return false;
  return partes.every((p) => {
    let t = p.trim();
    while (/^\(.*\)$/s.test(t) && t.length > 2) t = t.slice(1, -1).trim();
    if (/^(["'])\s*\1$/.test(t)) return true; // string literal (conteúdo mascarado)
    if (/^\d+(\.\d+)?$/.test(t)) return true;
    if (opcoes.naoControlavel && NAO_CONTROLAVEL_PELO_CLIENTE.test(t)) return true;
    if (/^`[^`]*`$/s.test(t)) {
      const exprs = [...t.matchAll(/\$\{([^}]*)\}/g)].map((m) => m[1].trim());
      return exprs.every((e) => (opcoes.naoControlavel && NAO_CONTROLAVEL_PELO_CLIENTE.test(e)) || (/^[\w$]+$/.test(e) && identificadorConstante(texto, e, profundidade, opcoes)));
    }
    if (/^[A-Za-z_$][\w$]*$/.test(t)) return identificadorConstante(texto, t, profundidade, opcoes);
    return false;
  });
}

/** Argumento constante (faixa de texto mascarado): nenhuma parte pode vir de fora de uma constante local. */
function argumentoConstante(texto, faixa, opcoes = {}) {
  if (!faixa) return false;
  return expressaoConstante(texto, texto.slice(faixa[0], faixa[1]), 0, opcoes);
}

// PL-05 (desvio D1): valores que o CLIENTE não controla — caminho do runtime e configuração do operador. Só valem nos
// ramos novos de SQL/SSRF/path (opcoes.naoControlavel); o ramo de exec/eval da PL-03 não muda.
// (R2) também process.env['X'] / process.env["X"]: o texto é mascarado, então a chave literal chega como aspas + espaços.
const NAO_CONTROLAVEL_PELO_CLIENTE = /^(?:__dirname|__filename|process\s*\.\s*cwd\s*\(\s*\)|process\s*\.\s*env\s*(?:\.\s*[A-Za-z_$][\w$]*|\[\s*(['"])[^'"\n]*\1\s*\]))$/;

/** Índice do `{` que envolve `pos` (texto mascarado), ou -1 no nível de módulo. */
function chaveEnvolvente(texto, pos) {
  let prof = 0;
  for (let k = pos - 1; k >= 0; k--) {
    if (texto[k] === '}') prof++;
    else if (texto[k] === '{') { if (prof === 0) return k; prof--; }
  }
  return -1;
}

function fechaChave(texto, abre) {
  let prof = 0;
  for (let k = abre; k < texto.length; k++) {
    if (texto[k] === '{') prof++;
    else if (texto[k] === '}') { prof--; if (prof === 0) return k; }
  }
  return texto.length;
}

const PALAVRAS_DE_CONTROLE = new Set(['if', 'for', 'while', 'switch', 'with', 'catch']);

/**
 * A raiz da fonte (req/request/ctx/event) é PARÂMETRO de uma função que envolve o uso e a chamada, sem reatribuição
 * local no meio? (Revisão r1 do fechamento: `const req = { … }` local virava RISCO_DEMONSTRADO.) A convenção de
 * framework só vale para o parâmetro do handler; na dúvida, não é fonte demonstrada.
 */
/**
 * Funções que declaram `nome` como PARÂMETRO e cujo corpo envolve `pos` e a chamada (`abre`).
 * @returns {Array<{ inicio: number, nomeAntes: string|undefined, params: string, ini: number, fim: number }>}
 */
function assinaturasEnvolventes(texto, nome, pos, abre) {
  const reNome = new RegExp(`(?<![\\w$.])${ESC(nome)}(?![\\w$])`);
  const assinaturas = /(?:\b([\w$]+)\s*)?\(([^()]*)\)\s*(=>|\{)|(?<![\w$.])([A-Za-z_$][\w$]*)\s*=>/g;
  const saida = [];
  for (const m of texto.slice(0, pos).matchAll(assinaturas)) {
    let params;
    if (m[4] !== undefined) params = m[4];
    else if (PALAVRAS_DE_CONTROLE.has(m[1])) continue;
    else params = m[2];
    if (!reNome.test(params)) continue;
    const fimAssinatura = m.index + m[0].length;
    let ini;
    let fim;
    if (m[3] === '{') {
      ini = fimAssinatura - 1;
      fim = fechaChave(texto, ini);
    } else {
      const espacos = texto.slice(fimAssinatura).match(/^\s*/)[0].length;
      if (texto[fimAssinatura + espacos] === '{') {
        ini = fimAssinatura + espacos;
        fim = fechaChave(texto, ini);
      } else {
        ini = fimAssinatura;
        fim = fimDaInstrucaoEncadeada(texto, fimAssinatura);
      }
    }
    if (ini < pos && fim > abre) saida.push({ inicio: m.index, nomeAntes: m[1], params, ini, fim });
  }
  return saida;
}

/**
 * Evidência de que a função é HANDLER de requisição (revisão r2 do fechamento: `req` parâmetro de uma função
 * qualquer não é requisição). Convenções: Express/Fastify/hapi `(req, res…)` ou `req: Request`; Koa `(ctx, next)`;
 * Lambda `(event, context)`; função passada a registro de rota (`.get/.post/…/.use(`); handler exportado.
 */
function pareceHandler(texto, a, raiz) {
  const tem = (n) => new RegExp(`(?<![\\w$.])${n}(?![\\w$])`).test(a.params);
  if ((raiz === 'req' || raiz === 'request') && (tem('res') || tem('response') || tem('reply') || /:\s*(?:[\w$]+\.)?Request\b/.test(a.params))) return true;
  if (raiz === 'ctx' && tem('next')) return true;
  if (raiz === 'event' && tem('context')) return true;
  const antes = texto.slice(Math.max(0, a.inicio - 400), a.inicio);
  const instrucao = antes.slice(antes.lastIndexOf(';') + 1);
  // função chamada `handler` só conta EXPORTADA (revisão r3: `function handler(req)` local não é handler)
  if (a.nomeAntes === 'handler' && /\bexport\s+(?:default\s+)?(?:async\s+)?function\s*$/.test(instrucao)) return true;
  if (/\.\s*(?:get|post|put|patch|delete|del|all|use|head|options|route)\s*\([^]*$/.test(instrucao)) return true;
  if (/\bhandler\s*[:=]\s*(?:async\s*)?(?:function\b\s*)?$/.test(instrucao)) return true;
  return false;
}

function raizEhParametro(texto, raiz, pos, abre) {
  const r = ESC(raiz);
  const reatribuicao = new RegExp(`\\b(?:const|let|var)\\s+${r}\\b|(?<![\\w$.])${r}\\s*=(?![=>])`);
  for (const a of assinaturasEnvolventes(texto, raiz, pos, abre)) {
    if (reatribuicao.test(texto.slice(a.ini, pos))) continue;
    if (!pareceHandler(texto, a, raiz)) continue;
    return true;
  }
  return false;
}

/**
 * O identificador, no ponto da chamada, resolve para `const <id> = '<GUID do WebSocket>'`? A declaração visível mais
 * próxima tem de ser essa const, e nenhum parâmetro de função que envolve a chamada pode ter o mesmo nome
 * (revisão r2 do fechamento: `function autenticar(WS_GUID) { … update(WS_GUID) }` ficava INFORMATIVO).
 */
function constanteGuidVisivel(codigo, texto, id, abre) {
  const r = ESC(id);
  const declaracoes = [...texto.slice(0, abre).matchAll(new RegExp(`\\b(const|let|var)\\s+${r}(?![\\w$])`, 'g'))]
    .filter((m) => { const b = chaveEnvolvente(texto, m.index); return b === -1 || fechaChave(texto, b) > abre; });
  const ultima = declaracoes[declaracoes.length - 1];
  if (!ultima || ultima[1] !== 'const') return false;
  if (!new RegExp(`^const\\s+${r}\\s*=\\s*(['"\`])${WS_GUID}\\1`).test(codigo.slice(ultima.index))) return false;
  return assinaturasEnvolventes(texto, id, abre, abre).length === 0;
}

/** Primeira fonte de requisição no trecho cuja raiz é parâmetro que envolve `pos` e a chamada (ou null). */
function fonteDemonstrada(trechoTexto, texto, pos, abre) {
  for (const f of trechoTexto.matchAll(new RegExp(FONTE_REQUISICAO.source, 'g'))) {
    const raiz = f[0].match(/^[\w$]+/)[0];
    if (raizEhParametro(texto, raiz, pos, abre)) return f[0].replace(/\s+/g, '');
  }
  return null;
}

/**
 * Entrada externa (requisição) chega ao trecho? Direta, ou por até 3 saltos de atribuição local dentro das 60
 * linhas anteriores à chamada. Devolve a cadeia observada (para a evidência) ou null.
 *
 * Aproximação de escopo (revisão do fechamento — replay da bancada): de cada identificador só vale a atribuição
 * VISÍVEL mais próxima antes da chamada — a que está num bloco que ainda contém a chamada (ou no nível de módulo).
 * Atribuição em função irmã não conta; parâmetro homônimo declarado entre a atribuição e a chamada sombreia
 * (a origem deixa de ser demonstrada). Na dúvida, nenhuma origem: REVISAO, nunca RISCO inventado.
 */
function origemExterna(texto, faixa, abre) {
  const trecho = texto.slice(faixa[0], faixa[1]);
  const direta = fonteDemonstrada(trecho, texto, faixa[0], abre);
  if (direta) return [direta];
  const inicios = linhasComoTexto(texto);
  const linhaChamada = texto.slice(0, abre).split('\n').length;
  const base = inicios[Math.max(0, linhaChamada - 1 - LIMITE_LINHAS_FLUXO)];
  const regiao = texto.slice(base, abre);
  const visivel = (pos) => {
    const bloco = chaveEnvolvente(texto, pos);
    return bloco === -1 || fechaChave(texto, bloco) > abre;
  };
  const vistos = new Set();
  let fila = [...new Set((trecho.match(/(?<![\w$.])[A-Za-z_$][\w$]*/g) || []).filter((w) => !PALAVRAS_RESERVADAS.has(w)))].map((w) => ({ w, cadeia: [w] }));
  for (let salto = 0; salto < LIMITE_SALTOS_FLUXO && fila.length; salto++) {
    const proxima = [];
    for (const { w, cadeia } of fila) {
      if (vistos.has(w)) continue;
      vistos.add(w);
      const id = w.replace(/\$/g, '\\$');
      const padroes = [
        new RegExp(`\\b(?:const|let|var)\\s+${id}\\s*(?::[^=;\\n]+)?=(?!=)\\s*([^;\\n]+)`, 'g'),
        new RegExp(`(?<![\\w$.])${id}\\s*=(?![=>])\\s*([^;\\n]+)`, 'g'),
        new RegExp(`\\b(?:const|let|var)\\s*\\{[^}]*(?<![\\w$])${id}(?![\\w$])[^}]*\\}\\s*=\\s*([^;\\n]+)`, 'g')
      ];
      const atribuicoes = [];
      for (const re of padroes) {
        for (const m of regiao.matchAll(re)) {
          const pos = base + m.index;
          if (visivel(pos)) atribuicoes.push({ pos, init: m[1] });
        }
      }
      if (!atribuicoes.length) continue;
      atribuicoes.sort((a, b) => b.pos - a.pos);
      // Reatribuição autorreferente (`x = x.trim()`) mantém o valor anterior na cadeia: segue para a atribuição
      // visível anterior até a primeira que não referencia o próprio identificador.
      const autorreferente = new RegExp(`(?<![\\w$.])${id}(?![\\w$])`);
      let k = 0;
      while (k < atribuicoes.length - 1 && autorreferente.test(atribuicoes[k].init)) k++;
      const maisProxima = { pos: atribuicoes[0].pos, init: atribuicoes.slice(0, k + 1).map((a) => a.init).join(' ; ') };
      // parâmetro homônimo declarado depois da atribuição e antes da chamada: sombreia a atribuição
      const entre = texto.slice(maisProxima.pos + 1, abre);
      // listas de parâmetros: `function f(…) {`, `(…) =>`, método `m(…) {`, `x =>`, `catch (x)` — não `if/for/while (…) {`
      const parametro = new RegExp(`(?:\\b([\\w$]+)\\s*)?\\(([^()]*)\\)\\s*(?:=>|\\{)|(?<![\\w$.])${id}\\s*=>|catch\\s*\\(\\s*${id}\\s*\\)`, 'g');
      const CONTROLE = new Set(['if', 'for', 'while', 'switch', 'with']);
      const sombreado = [...entre.matchAll(parametro)].some((p) => p[2] === undefined
        || (!CONTROLE.has(p[1]) && new RegExp(`(?<![\\w$.])${id}(?![\\w$])`).test(p[2])));
      if (sombreado) continue;
      const f = fonteDemonstrada(maisProxima.init, texto, maisProxima.pos, abre);
      if (f) return [...cadeia, f];
      for (const x of maisProxima.init.match(/(?<![\w$.])[A-Za-z_$][\w$]*/g) || []) if (!PALAVRAS_RESERVADAS.has(x) && !vistos.has(x)) proxima.push({ w: x, cadeia: [...cadeia, x] });
    }
    fila = proxima;
  }
  return null;
}

// Catálogo protocolar (observado na PL-03): hash fraco EXIGIDO por protocolo, sem papel de segurança.
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const ESC = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Fim da instrução que começa em `ini` (texto mascarado): `;` de nível zero, `)` que fecha o contexto externo, ou
 * quebra de linha de nível zero não seguida de `.` (encadeamento). */
function fimDaInstrucaoEncadeada(texto, ini) {
  let prof = 0;
  for (let k = ini; k < texto.length; k++) {
    const c = texto[k];
    if ('([{'.includes(c)) prof++;
    else if (')]}'.includes(c)) { if (prof === 0) return k; prof--; }
    else if (c === ';' && prof === 0) return k;
    else if (c === '\n' && prof === 0 && !/^\s*\./.test(texto.slice(k + 1, k + 200))) return k;
  }
  return texto.length;
}

/**
 * Uso protocolar do hash, AMARRADO à própria chamada (revisão r1 do fechamento: proximidade do GUID/cabeçalho não
 * basta — um hash de senha perto do handshake ficava INFORMATIVO).
 *  SHA-1: a instrução encadeada da chamada (`createHash('sha1').update(…)…`) contém o GUID do WebSocket, literal ou
 *         por `const X = '<GUID>'` declarado no mesmo arquivo.
 *  MD5:   o objeto de hash criado na chamada (`h = createHash('md5')`) tem o digest gravado no cabeçalho Content-MD5
 *         (`setHeader('Content-MD5', h.digest(…))` nas 40 linhas seguintes), ou a chamada está num bloco `if (…)` cuja
 *         condição lê o cabeçalho content-md5.
 * Qualquer outro caso: não demonstrado (REVISAO).
 */
function usoProtocolarDeHash(codigo, texto, linha, coluna, algoritmo) {
  const c = localizarChamadaDeRegra(texto, linha, coluna, ['createHash']);
  if (!c) return null;
  if (algoritmo === 'sha1') {
    const instrucao = codigo.slice(c.abre, fimDaInstrucaoEncadeada(texto, c.abre));
    if (instrucao.includes(WS_GUID)) return 'Sec-WebSocket-Accept (RFC 6455): o SHA-1 com o GUID do protocolo é exigido pelo WebSocket';
    for (const id of new Set(instrucao.match(/(?<![\w$.'"`])[A-Za-z_$][\w$]*/g) || [])) {
      if (constanteGuidVisivel(codigo, texto, id, c.abre)) {
        return 'Sec-WebSocket-Accept (RFC 6455): o SHA-1 com o GUID do protocolo é exigido pelo WebSocket';
      }
    }
    return null;
  }
  if (algoritmo === 'md5') {
    const inicioLinha = codigo.lastIndexOf('\n', c.abre) + 1;
    const antes = codigo.slice(inicioLinha, c.abre);
    const variavel = (antes.match(/([\w$]+(?:\.[\w$]+)*)\s*=\s*(?:[\w$]+\s*\.\s*)?createHash\s*$/) || [])[1];
    if (variavel) {
      const seguintes = codigo.slice(c.abre).split(/\r?\n/).slice(0, 40).join('\n');
      if (new RegExp(`setHeader\\s*\\(\\s*(['"\`])content-md5\\1\\s*,\\s*${ESC(variavel)}\\s*\\.\\s*digest\\s*\\(`, 'i').test(seguintes)) {
        return 'cabeçalho HTTP Content-MD5 (RFC 1864): checksum de integridade de transporte';
      }
    }
    const bloco = chaveEnvolvente(texto, c.abre);
    if (bloco > 0) {
      const cabecalho = texto.slice(0, bloco).trimEnd();
      if (cabecalho.endsWith(')')) {
        let prof = 0;
        let k = cabecalho.length - 1;
        for (; k >= 0; k--) { if (cabecalho[k] === ')') prof++; else if (cabecalho[k] === '(' && --prof === 0) break; }
        if (k > 0 && /\bif\s*$/.test(cabecalho.slice(0, k)) && /(['"`])content-md5\1/i.test(codigo.slice(k, cabecalho.length))) {
          return 'cabeçalho HTTP Content-MD5 (RFC 1864): checksum verificado de um corpo recebido';
        }
      }
    }
  }
  return null;
}

/**
 * PL-05 (desvio D3): o destino de uma URL é FIXO quando o prefixo literal (antes do primeiro trecho variável) já tem
 * esquema + host + separador (`https://host/`, `https://host?`, `//host/`) ou é caminho relativo à própria origem
 * (`/api/…`, nunca `//`). Sem o separador depois do host, `https://host${x}` com x = `@outro` troca o host (userinfo):
 * não é fixo. Argumento identificador: usa a ÚLTIMA atribuição a ele antes da chamada (mesmo arquivo).
 * @returns {string|null} descrição do destino fixo, ou null
 */
function destinoFixoDaUrl(codigo, texto, faixa, abre) {
  let ini = faixa[0];
  let fim = faixa[1];
  const bruto = texto.slice(ini, fim).trim();
  if (/^[A-Za-z_$][\w$]*$/.test(bruto)) {
    const atribs = [...texto.slice(0, abre).matchAll(new RegExp(`(?<![\\w$.])${ESC(bruto)}\\s*(?::[^=;\\n]+)?=(?![=>])\\s*`, 'g'))];
    const ultima = atribs[atribs.length - 1];
    if (!ultima) return null;
    ini = ultima.index + ultima[0].length;
    fim = fimDaInstrucaoEncadeada(texto, ini);
  }
  const expr = codigo.slice(ini, fim).trim();
  const aspa = expr[0];
  if (!['"', "'", '`'].includes(aspa)) return null;
  let literal = '';
  for (let k = 1; k < expr.length; k++) {
    if (expr[k] === '\\') { literal += expr[k + 1] ?? ''; k++; continue; }
    if (expr[k] === aspa || (aspa === '`' && expr[k] === '$' && expr[k + 1] === '{')) break;
    literal += expr[k];
  }
  const abs = literal.match(/^((?:https?:)?\/\/[^/?#@\s]+)[/?#]/i);
  if (abs) return abs[1];
  if (/^\/[^/\\]/.test(literal)) return 'mesma origem (caminho relativo)';
  return null;
}

const prop = (nome, estado, evidencia = null) => Object.freeze({ nome, estado, ...(evidencia ? { evidencia: String(evidencia).slice(0, 200) } : {}) });

function montar({ classe, propriedades, razao, explicacao, limitacoes = [], natureza, identidade = null }) {
  const efeito = classe === CLASSES_SIGNIFICADO.INFORMATIVO ? EFEITOS_NA_DECISAO.NAO_BLOQUEIA : EFEITOS_NA_DECISAO.BLOQUEIA;
  const sufixoContexto = natureza !== NATUREZAS_ARQUIVO.CODIGO && classe !== CLASSES_SIGNIFICADO.INFORMATIVO
    ? ` O arquivo parece ser ${ROTULO_NATUREZA[natureza]}; isso é registrado como contexto, mas não afasta o achado.`
    : '';
  return Object.freeze({
    versaoModelo: VERSAO_MODELO_SIGNIFICADO,
    classe,
    efeitoNaDecisao: efeito,
    propriedades: Object.freeze(propriedades),
    contexto: Object.freeze({ naturezaArquivo: natureza, fonte: 'CONVENCAO_DE_CAMINHO', decisivo: false }),
    razao,
    explicacao: `${explicacao}${sufixoContexto}`,
    limitacoes: Object.freeze(limitacoes),
    ...(identidade ? { identidadeStatus: identidade } : {})
  });
}

const LIM_FLUXO = `Fluxo local limitado: até ${LIMITE_SALTOS_FLUXO} saltos de atribuição nas ${LIMITE_LINHAS_FLUXO} linhas anteriores, no mesmo arquivo; entrada externa reconhecida por convenção de framework (req/request/ctx/event).`;

/**
 * Significado de um achado Semgrep das regras zunvio.*.
 * @param {object} p
 * @param {string} p.ruleId
 * @param {string|null} p.codigo - conteúdo do arquivo (null se ilegível)
 * @param {number} p.linha
 * @param {number} [p.coluna]
 * @param {string} p.filePath
 * @param {object|null} [p.identidadeSimbolo] - só para child-process-exec
 */
export function avaliarSignificadoSemgrep({ ruleId, codigo, linha, coluna, filePath, identidadeSimbolo = null }) {
  const natureza = naturezaArquivoPorCaminho(filePath);
  const legivel = typeof codigo === 'string';
  const mascara = legivel ? mascararNaoCodigo(codigo) : null;
  const texto = mascara?.mascarado ?? '';
  const chamada = (nomes) => (legivel ? localizarChamadaDeRegra(texto, linha, coluna, nomes) : null);
  const args = (c) => (c ? argumentosDaChamada(texto, c.abre) : null);
  const naoLocalizada = ['A chamada não foi localizada de forma inequívoca no arquivo; o significado ficou no nível do padrão.'];

  switch (ruleId) {
    case 'zunvio.child-process-exec': {
      const st = identidadeSimbolo?.status;
      if (st === STATUS_IDENTIDADE.RECUSADA) {
        return montar({ classe: 'INFORMATIVO', natureza, identidade: st,
          propriedades: [prop('IDENTIDADE_API', 'RECUSADA', identidadeSimbolo.motivo)],
          razao: 'O símbolo chamado não é child_process.exec (identidade recusada).',
          explicacao: 'Encontramos uma chamada exec(...), mas ela não é child_process.exec. Este item não impede a publicação.' });
      }
      if (st !== STATUS_IDENTIDADE.CONFIRMADA) {
        return montar({ classe: 'REVISAO_NECESSARIA', natureza, identidade: st ?? 'NAO_DETERMINADA',
          propriedades: [prop('IDENTIDADE_API', 'NAO_DEMONSTRADA', identidadeSimbolo?.motivo), prop('ENTRADA_EXTERNA', 'NAO_DEMONSTRADA')],
          razao: 'Não foi possível demonstrar nem recusar que a chamada é child_process.exec.',
          explicacao: 'Encontramos uma chamada exec(...) cuja identidade não conseguimos demonstrar (pode ou não executar comandos do sistema). Revise antes de publicar.',
          limitacoes: ['Identidade de símbolo resolvida por leitura do próprio arquivo, sem análise de escopo.'] });
      }
      const c = chamada(['exec', 'execSync']);
      const a = args(c);
      if (!a || !a.args.length) {
        return montar({ classe: 'REVISAO_NECESSARIA', natureza, identidade: st, limitacoes: naoLocalizada,
          propriedades: [prop('IDENTIDADE_API', 'DEMONSTRADA', identidadeSimbolo.motivo), prop('COMANDO_DINAMICO', 'NAO_DEMONSTRADA'), prop('ENTRADA_EXTERNA', 'NAO_DEMONSTRADA')],
          razao: 'child_process.exec confirmado; o comando não pôde ser analisado.',
          explicacao: 'Esta chamada usa child_process.exec, mas não conseguimos analisar o comando executado. Revise antes de publicar.' });
      }
      if (argumentoConstante(texto, a.args[0])) {
        return montar({ classe: 'INFORMATIVO', natureza, identidade: st,
          propriedades: [prop('IDENTIDADE_API', 'DEMONSTRADA', identidadeSimbolo.motivo), prop('COMANDO_DINAMICO', 'AUSENTE', 'comando literal constante'), prop('ENTRADA_EXTERNA', 'AUSENTE')],
          razao: 'child_process.exec com comando constante: não há entrada que possa alterar o comando.',
          explicacao: 'Esta chamada usa child_process.exec com um comando fixo (constante), sem entrada externa. Este item não impede a publicação.' });
      }
      const origem = origemExterna(texto, a.args[0], c.abre);
      if (origem) {
        return montar({ classe: 'RISCO_DEMONSTRADO', natureza, identidade: st, limitacoes: [LIM_FLUXO],
          propriedades: [prop('IDENTIDADE_API', 'DEMONSTRADA', identidadeSimbolo.motivo), prop('COMANDO_DINAMICO', 'DEMONSTRADA'), prop('ENTRADA_EXTERNA', 'DEMONSTRADA', origem.join(' ← '))],
          razao: 'child_process.exec executa um comando montado com entrada externa da requisição.',
          explicacao: `Esta chamada usa child_process.exec e monta o comando com entrada externa (${origem[origem.length - 1]}). Risco de injeção de comando demonstrado.` });
      }
      return montar({ classe: 'REVISAO_NECESSARIA', natureza, identidade: st, limitacoes: [LIM_FLUXO],
        propriedades: [prop('IDENTIDADE_API', 'DEMONSTRADA', identidadeSimbolo.motivo), prop('COMANDO_DINAMICO', 'DEMONSTRADA'), prop('ENTRADA_EXTERNA', 'NAO_DEMONSTRADA')],
        razao: 'child_process.exec com comando dinâmico; a origem da entrada não foi demonstrada.',
        explicacao: 'Esta chamada usa child_process.exec com um comando montado dinamicamente, mas ainda não conseguimos demonstrar se ele recebe entrada controlável. Revise antes de publicar.' });
    }
    case 'zunvio.eval-detection':
    case 'zunvio.insecure-dynamic-code': {
      const nomes = ruleId === 'zunvio.eval-detection' ? ['eval', 'evaluate'] : ['Function', 'runInNewContext', 'runInThisContext'];
      const c = chamada(nomes);
      const a = args(c);
      if (!a || !a.args.length) {
        return montar({ classe: 'REVISAO_NECESSARIA', natureza, limitacoes: naoLocalizada,
          propriedades: [prop('CODIGO_DINAMICO', 'NAO_DEMONSTRADA'), prop('ENTRADA_EXTERNA', 'NAO_DEMONSTRADA')],
          razao: 'Execução dinâmica de código; o argumento não pôde ser analisado.',
          explicacao: 'Encontramos execução dinâmica de código (eval/Function/vm), mas não conseguimos analisar o código executado. Revise antes de publicar.' });
      }
      // vm.*: só o 1º argumento é código. new Function(...): todos os argumentos formam o código.
      const codigoArgs = /runIn/.test(texto.slice(Math.max(0, c.abre - 20), c.abre)) ? [a.args[0]] : (ruleId === 'zunvio.eval-detection' ? [a.args[0]] : a.args);
      if (codigoArgs.every((f) => argumentoConstante(texto, f))) {
        return montar({ classe: 'INFORMATIVO', natureza,
          propriedades: [prop('CODIGO_DINAMICO', 'AUSENTE', 'código literal constante'), prop('ENTRADA_EXTERNA', 'AUSENTE')],
          razao: 'O código executado é constante: não há entrada que possa alterá-lo.',
          explicacao: 'Encontramos execução dinâmica de código (eval/Function/vm), mas o código executado é fixo (constante), sem entrada externa. Este item não impede a publicação.' });
      }
      const origem = codigoArgs.map((f) => origemExterna(texto, f, c.abre)).find(Boolean);
      if (origem) {
        return montar({ classe: 'RISCO_DEMONSTRADO', natureza, limitacoes: [LIM_FLUXO],
          propriedades: [prop('CODIGO_DINAMICO', 'DEMONSTRADA'), prop('ENTRADA_EXTERNA', 'DEMONSTRADA', origem.join(' ← '))],
          razao: 'Código dinâmico montado com entrada externa da requisição.',
          explicacao: `Encontramos execução dinâmica de código com entrada externa (${origem[origem.length - 1]}). Risco de injeção de código demonstrado.` });
      }
      return montar({ classe: 'REVISAO_NECESSARIA', natureza, limitacoes: [LIM_FLUXO],
        propriedades: [prop('CODIGO_DINAMICO', 'DEMONSTRADA'), prop('ENTRADA_EXTERNA', 'NAO_DEMONSTRADA')],
        razao: 'Código dinâmico; a origem da entrada não foi demonstrada.',
        explicacao: 'Encontramos execução dinâmica de código (eval/Function/vm) com conteúdo variável, mas ainda não conseguimos demonstrar se ele recebe entrada controlável. Revise antes de publicar.' });
    }
    case 'zunvio.ssrf-dynamic-url':
    case 'zunvio.sql-injection-concat':
    case 'zunvio.path-traversal-fs-concat': {
      const cfg = {
        // artigo, particípio e pronome concordam com o alvo (revisão de linguagem na prova da tela)
        'zunvio.ssrf-dynamic-url': { nomes: ['fetch', 'axios', 'got', 'request', 'get', 'post', 'put', 'patch', 'delete', 'head'], alvo: 'URL de requisição de rede', um: 'uma', montado: 'montada', ele: 'ela', risco: 'SSRF' },
        'zunvio.sql-injection-concat': { nomes: ['query', 'execute'], alvo: 'consulta SQL', um: 'uma', montado: 'montada', ele: 'ela', risco: 'injeção de SQL' },
        'zunvio.path-traversal-fs-concat': { nomes: ['readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'appendFile', 'appendFileSync', 'unlink', 'unlinkSync', 'createReadStream', 'createWriteStream', 'sendFile', 'download'], alvo: 'caminho de arquivo', um: 'um', montado: 'montado', ele: 'ele', risco: 'path traversal' }
      }[ruleId];
      const c = chamada(cfg.nomes);
      const a = args(c);
      const origem = a && a.args.length ? origemExterna(texto, a.args[0], c.abre) : null;
      // PL-05 (desvio D3): SSRF exige o cliente controlar o DESTINO. URL cujo prefixo literal já fixa esquema+host+separador
      // (ou caminho relativo à própria origem) tem o destino demonstrado fixo: sem entrada externa ⇒ INFORMATIVO; com
      // entrada externa só no caminho ⇒ REVISAO (nunca RISCO de SSRF).
      const fixo = ruleId === 'zunvio.ssrf-dynamic-url' && a && a.args.length ? destinoFixoDaUrl(codigo, texto, a.args[0], c.abre) : null;
      if (fixo) {
        return montar({ classe: origem ? 'REVISAO_NECESSARIA' : 'INFORMATIVO', natureza, limitacoes: [LIM_FLUXO, 'Destino fixo demonstrado pelo prefixo literal da URL; o caminho e a consulta continuam variáveis.'],
          propriedades: [prop('VALOR_CONCATENADO', 'DEMONSTRADA'), prop('DESTINO_CONTROLAVEL', 'AUSENTE', fixo), prop('ENTRADA_EXTERNA', origem ? 'DEMONSTRADA' : 'NAO_DEMONSTRADA', origem ? origem.join(' ← ') : undefined)],
          razao: origem ? 'URL com destino fixo, mas com caminho montado com entrada externa.' : 'URL com destino fixo (esquema e host literais): o cliente não controla para onde o servidor faz a requisição.',
          explicacao: origem
            ? `Encontramos uma requisição de rede para um destino fixo (${fixo}), mas com parte do caminho vinda do cliente (${origem[origem.length - 1]}). O destino não muda; revise se o caminho montado pode acessar algo indevido no próprio serviço.`
            : `Encontramos uma URL montada dinamicamente, mas o destino é fixo (${fixo}); só o caminho varia. Este item não impede a publicação.` });
      }
      // PL-05: valor montado só com constantes e valores que o cliente não controla (runtime/configuração) ⇒ INFORMATIVO.
      if (!origem && a && a.args.length && argumentoConstante(texto, a.args[0], { naoControlavel: true })) {
        return montar({ classe: 'INFORMATIVO', natureza,
          propriedades: [prop('VALOR_CONCATENADO', 'DEMONSTRADA'), prop('ENTRADA_EXTERNA', 'AUSENTE', 'só literais, constantes locais e valores do runtime/configuração')],
          razao: `${cfg.um === 'um' ? 'Caminho de arquivo' : cfg.alvo[0].toUpperCase() + cfg.alvo.slice(1)} ${cfg.montado} só com valores que o cliente não controla.`,
          explicacao: `Encontramos ${cfg.um} ${cfg.alvo} ${cfg.montado} dinamicamente, mas só com valores fixos ou de configuração do servidor, sem entrada do cliente. Este item não impede a publicação.`,
          limitacoes: ['Valores do runtime (__dirname, __filename, process.cwd()) e de configuração (process.env) são tratados como fora do controle do cliente.'] });
      }
      if (origem) {
        return montar({ classe: 'RISCO_DEMONSTRADO', natureza, limitacoes: [LIM_FLUXO],
          propriedades: [prop('VALOR_CONCATENADO', 'DEMONSTRADA'), prop('ENTRADA_EXTERNA', 'DEMONSTRADA', origem.join(' ← '))],
          razao: `${cfg.um === 'um' ? 'Caminho de arquivo' : cfg.alvo[0].toUpperCase() + cfg.alvo.slice(1)} ${cfg.montado} com entrada externa da requisição.`,
          explicacao: `Encontramos ${cfg.um} ${cfg.alvo} ${cfg.montado} por concatenação com entrada externa (${origem[origem.length - 1]}). Risco de ${cfg.risco} demonstrado.` });
      }
      return montar({ classe: 'REVISAO_NECESSARIA', natureza, limitacoes: a ? [LIM_FLUXO] : naoLocalizada,
        propriedades: [prop('VALOR_CONCATENADO', 'DEMONSTRADA'), prop('ENTRADA_EXTERNA', 'NAO_DEMONSTRADA')],
        razao: `${cfg.um === 'um' ? 'Caminho de arquivo' : cfg.alvo[0].toUpperCase() + cfg.alvo.slice(1)} ${cfg.montado} por concatenação; a origem da entrada não foi demonstrada.`,
        explicacao: `Encontramos ${cfg.um} ${cfg.alvo} ${cfg.montado} por concatenação, mas ainda não conseguimos demonstrar se ${cfg.ele} recebe entrada controlável. Revise antes de publicar.` });
    }
    case 'zunvio.weak-crypto-algorithm': {
      const linhaTxt = legivel ? codigo.split(/\r?\n/)[linha - 1] ?? '' : '';
      const alg = /sha-?1/i.test(linhaTxt) ? 'sha1' : (/md5/i.test(linhaTxt) ? 'md5' : null);
      const protocolo = legivel && alg ? usoProtocolarDeHash(codigo, texto, linha, coluna, alg) : null;
      if (protocolo) {
        return montar({ classe: 'INFORMATIVO', natureza,
          propriedades: [prop('ALGORITMO_FRACO', 'DEMONSTRADA', alg), prop('USO_PROTOCOLAR', 'DEMONSTRADA', protocolo), prop('USO_DE_SEGURANCA', 'AUSENTE')],
          razao: `Uso exigido por protocolo: ${protocolo}.`,
          explicacao: `Encontramos ${alg.toUpperCase()}, mas o uso é exigido pelo protocolo (${protocolo.split(':')[0]}), não uma escolha de segurança. Este item não impede a publicação.`,
          limitacoes: ['Catálogo protocolar restrito aos dois usos observados (WebSocket, Content-MD5).'] });
      }
      return montar({ classe: 'REVISAO_NECESSARIA', natureza,
        propriedades: [prop('ALGORITMO_FRACO', 'DEMONSTRADA', alg ?? undefined), prop('USO_DE_SEGURANCA', 'NAO_DEMONSTRADA')],
        razao: 'Algoritmo de hash/cifra fraco; o propósito do uso não foi demonstrado.',
        explicacao: 'Encontramos um algoritmo criptográfico fraco (MD5/SHA-1 ou cifra depreciada). Não conseguimos determinar se ele protege algo (senha, assinatura) ou só serve de identificador/checksum. Revise antes de publicar.' });
    }
    case 'zunvio.insecure-random':
      return montar({ classe: 'REVISAO_NECESSARIA', natureza,
        propriedades: [prop('GERADOR_NAO_CRIPTOGRAFICO', 'DEMONSTRADA', 'Math.random()'), prop('USO_DE_SEGURANCA', 'NAO_DEMONSTRADA')],
        razao: 'Math.random() não é criptograficamente seguro; o uso do valor não foi determinado.',
        explicacao: 'Encontramos Math.random(), que não é seguro para gerar segredos. Não conseguimos determinar se este valor é usado para segurança (token, senha, identificador secreto). Revise antes de publicar.',
        limitacoes: ['O uso do valor gerado não é analisado nesta versão.'] });
    case 'zunvio.hardcoded-jwt-secret':
      return montar({ classe: 'REVISAO_NECESSARIA', natureza,
        propriedades: [prop('SEGREDO_LITERAL', 'DEMONSTRADA', 'segredo de JWT escrito no código'), prop('USO_EM_PRODUCAO', 'NAO_DEMONSTRADA')],
        razao: 'Segredo de assinatura de JWT embutido no código; o uso em produção não foi demonstrado.',
        explicacao: 'Encontramos um segredo de JWT escrito diretamente no código. Se ele for usado em produção, quem tiver o código pode forjar tokens. Revise antes de publicar.' });
    case 'zunvio.hardcoded-session-secret':
      return montar({ classe: 'REVISAO_NECESSARIA', natureza,
        propriedades: [prop('SEGREDO_LITERAL', 'DEMONSTRADA', 'segredo de sessão/cookie escrito no código'), prop('USO_EM_PRODUCAO', 'NAO_DEMONSTRADA')],
        razao: 'Segredo de assinatura de sessão/cookie embutido no código; o uso em produção não foi demonstrado.',
        explicacao: 'Encontramos o segredo que assina os cookies de sessão escrito diretamente no código. Se ele for usado em produção, quem tiver o código pode forjar sessões. Revise antes de publicar.' });
    case 'zunvio.template-locals-from-request': {
      const c = chamada(['render']);
      const a = args(c);
      const origem = a && a.args.length > 1 ? origemExterna(texto, a.args[1], c.abre) : null;
      if (origem) {
        return montar({ classe: 'RISCO_DEMONSTRADO', natureza, limitacoes: [LIM_FLUXO],
          propriedades: [prop('OBJETO_DA_REQUISICAO', 'DEMONSTRADA', origem.join(' ← ')), prop('ENTRADA_EXTERNA', 'DEMONSTRADA', origem.join(' ← '))],
          razao: 'O objeto inteiro da requisição vira as variáveis do template: o cliente controla opções do motor de template.',
          explicacao: `Encontramos a página montada com todo o conteúdo enviado pelo cliente (${origem[origem.length - 1]}) como variáveis do template. Isso permite que o cliente mude opções do motor de template (por exemplo, qual arquivo usar como layout). Risco demonstrado.` });
      }
      return montar({ classe: 'REVISAO_NECESSARIA', natureza, limitacoes: a ? [LIM_FLUXO] : naoLocalizada,
        propriedades: [prop('OBJETO_DA_REQUISICAO', 'DEMONSTRADA', 'padrão req.body/req.query/req.params'), prop('ENTRADA_EXTERNA', 'NAO_DEMONSTRADA')],
        razao: 'Objeto inteiro de um parâmetro com forma de requisição usado como variáveis do template; a função não foi demonstrada como handler.',
        explicacao: 'Encontramos a página montada com um objeto inteiro com forma de requisição como variáveis do template, mas não conseguimos demonstrar que ele vem do cliente. Revise antes de publicar.' });
    }
    default:
      return montar({ classe: 'REVISAO_NECESSARIA', natureza,
        propriedades: [prop('PADRAO_SINTATICO', 'DEMONSTRADA', ruleId)],
        razao: 'O padrão da regra foi encontrado; o risco não foi analisado por evidência adicional.',
        explicacao: 'Encontramos um padrão de código que pode indicar risco de segurança. Não há evidência adicional para concluir. Revise antes de publicar.' });
  }
}

/** Significado de um achado do Gitleaks (possível credencial). Nunca carrega o valor. */
export function avaliarSignificadoSegredo({ filePath, possivelPlaceholder = false }) {
  const natureza = naturezaArquivoPorCaminho(filePath);
  return montar({ classe: 'REVISAO_NECESSARIA', natureza,
    propriedades: [prop('FORMA_DE_CREDENCIAL', 'DEMONSTRADA'), prop('CREDENCIAL_VALIDA', 'NAO_DEMONSTRADA'), ...(possivelPlaceholder ? [prop('VALOR_SINTETICO', 'NAO_DEMONSTRADA', 'o nome do identificador sugere valor de exemplo')] : [])],
    razao: 'Valor com forma de credencial; validade e uso não foram demonstrados.',
    explicacao: `Encontramos um valor com forma de credencial ou segredo${possivelPlaceholder ? ' (o nome sugere um valor de exemplo, mas isso não foi comprovado)' : ''}. Não verificamos se ele é válido. Uma credencial real continua relevante mesmo em teste ou exemplo. Revise antes de publicar.`,
    limitacoes: ['A validade da credencial não é verificada (nenhum contato externo).'] });
}

/** Conta os achados por significado (para explicar o portão). */
export function contarSignificados(achados) {
  const c = { RISCO_DEMONSTRADO: 0, REVISAO_NECESSARIA: 0, INFORMATIVO: 0, SEM_SIGNIFICADO: 0 };
  for (const a of achados || []) c[a?.significado?.classe ?? 'SEM_SIGNIFICADO']++;
  return c;
}

const CLASSES_VALIDAS = new Set(Object.values(CLASSES_SIGNIFICADO));
const ESTADOS_VALIDOS = new Set(Object.values(ESTADOS_PROPRIEDADE));
const NATUREZAS_VALIDAS = new Set(Object.values(NATUREZAS_ARQUIVO));

/**
 * Coerência de um significado SELADO (validador do Evidence Pack 0.4.0 e verificador de recibo). Um significado
 * que não bloqueia precisa ser INFORMATIVO; o contexto de arquivo nunca pode ser decisivo; identidade não
 * determinada nunca vira INFORMATIVO (fail closed); RISCO_DEMONSTRADO exige ao menos uma propriedade demonstrada.
 * @returns {string[]} problemas (vazio = coerente)
 */
export function problemasDoSignificado(significado, identidadeSimbolo = undefined) {
  const s = significado;
  if (!s || typeof s !== 'object' || Array.isArray(s)) return ['significado ausente ou não é objeto'];
  const p = [];
  if (typeof s.versaoModelo !== 'string' || !s.versaoModelo) p.push('significado.versaoModelo ausente');
  if (!CLASSES_VALIDAS.has(s.classe)) p.push(`significado.classe inválida (${JSON.stringify(s.classe)})`);
  const efeitoEsperado = s.classe === CLASSES_SIGNIFICADO.INFORMATIVO ? EFEITOS_NA_DECISAO.NAO_BLOQUEIA : EFEITOS_NA_DECISAO.BLOQUEIA;
  if (s.efeitoNaDecisao !== efeitoEsperado) p.push(`significado.efeitoNaDecisao (${JSON.stringify(s.efeitoNaDecisao)}) incoerente com a classe ${s.classe}`);
  if (!Array.isArray(s.propriedades)) {
    p.push('significado.propriedades deve ser array');
  } else {
    for (const [i, pr] of s.propriedades.entries()) {
      if (!pr || typeof pr.nome !== 'string' || !ESTADOS_VALIDOS.has(pr.estado)) p.push(`significado.propriedades[${i}] inválida`);
    }
    if (s.classe === CLASSES_SIGNIFICADO.RISCO_DEMONSTRADO && !s.propriedades.some((pr) => pr?.estado === ESTADOS_PROPRIEDADE.DEMONSTRADA)) {
      p.push('RISCO_DEMONSTRADO sem nenhuma propriedade demonstrada');
    }
  }
  if (!s.contexto || !NATUREZAS_VALIDAS.has(s.contexto.naturezaArquivo) || s.contexto.decisivo !== false) {
    p.push('significado.contexto deve registrar naturezaArquivo válida com decisivo=false (contexto de arquivo nunca decide)');
  }
  if (typeof s.razao !== 'string' || !s.razao || typeof s.explicacao !== 'string' || !s.explicacao) p.push('significado sem razao/explicacao');
  if (!Array.isArray(s.limitacoes)) p.push('significado.limitacoes deve ser array');
  // Identidade de símbolo (child-process-exec): o significado repete o status e respeita a semântica homologada.
  if (identidadeSimbolo !== undefined) {
    const st = identidadeSimbolo?.status;
    if (s.identidadeStatus !== st) p.push(`significado.identidadeStatus (${JSON.stringify(s.identidadeStatus)}) diverge de identidadeSimbolo.status (${JSON.stringify(st)})`);
    if (st === STATUS_IDENTIDADE.RECUSADA && s.classe !== CLASSES_SIGNIFICADO.INFORMATIVO) p.push('identidade RECUSADA deve ser INFORMATIVO');
    if (st !== STATUS_IDENTIDADE.RECUSADA && st !== STATUS_IDENTIDADE.CONFIRMADA && s.classe === CLASSES_SIGNIFICADO.INFORMATIVO) {
      p.push('identidade não determinada não pode ser INFORMATIVO (fail closed)');
    }
  }
  return p;
}
