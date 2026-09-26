// PL-03 · Fatia 1 — IDENTIDADE DE SÍMBOLO para a regra zunvio.child-process-exec.
//
// Separa dois fatos que antes eram um só:
//   MATCH                 → o padrão textual `exec(...)` casou (o Semgrep diz isso);
//   IDENTIDADE CONFIRMADA → há evidência estrutural, no próprio arquivo, de que o símbolo chamado é
//                           child_process.exec (ou um wrapper que o expõe com a mesma semântica de shell).
//
// Fail closed epistemicamente: não conseguir provar a identidade NÃO é identidade confirmada.
//   CONFIRMADA      → binding único (ou bindings concordantes) vindo de um módulo compatível e nenhum indício
//                     de sombreamento (parâmetro, função declarada, outra definição) no arquivo;
//   RECUSADA        → o identificador só é definido LOCALMENTE (função/valor local, variável de laço), nenhum
//                     binding o liga ao módulo E o arquivo não referencia nenhum módulo compatível (a definição
//                     local não pode ser um wrapper de child_process deste arquivo);
//   NAO_DETERMINADA → todo o resto: sem binding, forma não suportada, alias/renomeação, outro módulo,
//                     parâmetro/função declarada, bindings divergentes (sombreamento), definição local num
//                     arquivo que referencia child_process (possível wrapper), chamada não localizada.
//
// Escopo DELIBERADAMENTE restrito às formas do corpus histórico da Bancada Pública v1 (50 achados A–C);
// o que foi acrescentado além delas serve só para NÃO afirmar identidade (detectar sombreamento).
// Análise léxica por arquivo, sem escopo: comentários, strings, templates e regex literais são mascarados
// antes de procurar bindings (um `import` dentro de string nunca conta).

export const STATUS_IDENTIDADE = Object.freeze({
  CONFIRMADA: 'CONFIRMADA',
  RECUSADA: 'RECUSADA',
  NAO_DETERMINADA: 'NAO_DETERMINADA'
});

export const FORMAS_IDENTIDADE = Object.freeze({
  IMPORT_NOMEADO: 'IMPORT_NOMEADO',
  IMPORT_NAMESPACE_RECEPTOR: 'IMPORT_NAMESPACE_RECEPTOR',
  REQUIRE_DESESTRUTURADO: 'REQUIRE_DESESTRUTURADO',
  REQUIRE_MEMBRO: 'REQUIRE_MEMBRO',
  REQUIRE_MODULO_RECEPTOR: 'REQUIRE_MODULO_RECEPTOR',
  DEFINICAO_LOCAL: 'DEFINICAO_LOCAL',
  VARIAVEL_DE_LACO: 'VARIAVEL_DE_LACO',
  PARAMETRO: 'PARAMETRO',
  FUNCAO_DECLARADA: 'FUNCAO_DECLARADA',
  FORMA_NAO_SUPORTADA: 'FORMA_NAO_SUPORTADA',
  SEM_BINDING: 'SEM_BINDING',
  AMBIGUA: 'AMBIGUA',
  POSSIVEL_WRAPPER: 'POSSIVEL_WRAPPER',
  WRAPPER_DE_EXEC: 'WRAPPER_DE_EXEC',
  WRAPPER_SEM_SHELL: 'WRAPPER_SEM_SHELL',
  CHAMADA_NAO_LOCALIZADA: 'CHAMADA_NAO_LOCALIZADA',
  ARQUIVO_ILEGIVEL: 'ARQUIVO_ILEGIVEL'
});

export const API_CHILD_PROCESS_EXEC = 'child_process.exec';
// `child-process-promise` expõe `exec` como wrapper de child_process.exec (shell) — aparece no corpus.
const MODULOS_COMPATIVEIS = new Set(['child_process', 'node:child_process', 'child-process-promise']);
const PALAVRAS_ANTES_DE_REGEX = new Set(['return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'throw', 'case', 'do', 'else', 'yield', 'await']);
const PALAVRAS_NAO_FUNCAO = new Set(['if', 'for', 'while', 'switch', 'with', 'return', 'function', 'typeof', 'await', 'yield', 'new', 'catch', 'super', 'import']);

/**
 * Lexer mínimo e preservador de posição. Devolve o texto com comentários, CONTEÚDO de strings, texto de
 * templates e corpo de regex literais trocados por espaço (delimitadores e quebras de linha mantidos) e o mapa
 * início-da-string → valor original (para ler especificadores de módulo sem deixar strings virarem código).
 * @param {string} codigo
 * @returns {{ mascarado: string, literais: Map<number, string> }}
 */
export function mascararNaoCodigo(codigo) {
  const s = String(codigo ?? '');
  const out = s.split('');
  const literais = new Map();
  const apagar = (i) => { if (out[i] !== '\n' && out[i] !== '\r') out[i] = ' '; };
  let i = 0;
  const pilha = []; // profundidade de chaves de cada ${ } aberto dentro de template
  // Cada '(' aberto lembra se é a condição de if/while/for/with: depois desse ')' começa um comando, então uma
  // barra ali abre regex literal; depois de qualquer outro ')' (valor), a barra é divisão.
  const pilhaParenteses = [];
  let ultimoSignificativo = ''; // último caractere de CÓDIGO não-branco
  let ultimaPalavra = '';
  let palavraAnterior = ''; // palavra imediatamente antes de ultimaPalavra (para `for await (`)
  let ultimaPalavraEhPropriedade = false; // `obj.if` não é o comando if
  const consumirTemplate = () => { // i aponta para o caractere após a crase (ou após o } de fechamento de ${})
    while (i < s.length) {
      if (s[i] === '\\') { apagar(i); apagar(i + 1); i += 2; continue; }
      if (s[i] === '`') { i++; return 'fim'; }
      if (s[i] === '$' && s[i + 1] === '{') { pilha.push(0); i += 2; return 'expr'; }
      apagar(i); i++;
    }
    return 'fim';
  };
  while (i < s.length) {
    const c = s[i];
    const d = s[i + 1];
    if (c === '/' && d === '/') { while (i < s.length && s[i] !== '\n') { apagar(i); i++; } continue; }
    if (c === '/' && d === '*') { apagar(i); apagar(i + 1); i += 2; while (i < s.length && !(s[i] === '*' && s[i + 1] === '/')) { apagar(i); i++; } if (i < s.length) { apagar(i); apagar(i + 1); i += 2; } continue; }
    if (c === '"' || c === "'") {
      const inicio = i; let valor = ''; i++;
      while (i < s.length && s[i] !== c && s[i] !== '\n') { if (s[i] === '\\') { valor += s[i + 1] ?? ''; apagar(i); apagar(i + 1); i += 2; continue; } valor += s[i]; apagar(i); i++; }
      literais.set(inicio, valor);
      i++; ultimoSignificativo = c; ultimaPalavra = ''; continue;
    }
    if (c === '`') {
      const inicio = i; i++;
      if (consumirTemplate() === 'fim') {
        // Template sem ${}: é um literal simples (ex.: require(`child_process`)); o valor original fica no mapa.
        literais.set(inicio, s.slice(inicio + 1, i - 1));
        ultimoSignificativo = '`'; ultimaPalavra = '';
      }
      continue;
    }
    if (pilha.length && c === '{') { pilha[pilha.length - 1]++; i++; ultimoSignificativo = c; ultimaPalavra = ''; continue; }
    if (pilha.length && c === '}') {
      if (pilha[pilha.length - 1] === 0) { pilha.pop(); i++; if (consumirTemplate() === 'fim') { ultimoSignificativo = '`'; ultimaPalavra = ''; } continue; }
      pilha[pilha.length - 1]--; i++; ultimoSignificativo = c; ultimaPalavra = ''; continue;
    }
    if (c === '/') {
      // Depois de um operador (inclusive `/` de divisão) vem operando: uma barra ali abre regex literal.
      // Palavra-chave depois de `.` é propriedade (obj.return), não o operador: não abre regex.
      const ehRegex = ultimoSignificativo === '' || '(,=:[!&|?{};+-*%<>~^/'.includes(ultimoSignificativo) || (!ultimaPalavraEhPropriedade && PALAVRAS_ANTES_DE_REGEX.has(ultimaPalavra));
      if (ehRegex) {
        // Só é regex se fechar na MESMA linha; senão era divisão e nada é mascarado (evita esconder código real,
        // p.ex. um require na mesma linha, o que poderia levar a RECUSADA indevida).
        let k = i + 1; let classe = false; let fecha = -1;
        while (k < s.length && s[k] !== '\n') {
          if (s[k] === '\\') { k += 2; continue; }
          if (s[k] === '[') classe = true; else if (s[k] === ']') classe = false; else if (s[k] === '/' && !classe) { fecha = k; break; }
          k++;
        }
        if (fecha !== -1) {
          for (let m = i + 1; m < fecha; m++) apagar(m);
          i = fecha + 1; while (i < s.length && /[a-z]/i.test(s[i])) i++;
          // Uma regex literal é um VALOR: a barra seguinte é divisão, não outra regex.
          ultimoSignificativo = ')'; ultimaPalavra = ''; palavraAnterior = ''; continue;
        }
      }
    }
    if ((c === '+' || c === '-') && d === c) {
      // ++/-- pós-fixo (depois de identificador, ) ou ]) fecha um VALOR: a barra seguinte é divisão.
      const posfixo = /[\w$)\]]/.test(ultimoSignificativo);
      i += 2; ultimoSignificativo = posfixo ? ')' : c; ultimaPalavra = ''; palavraAnterior = ''; continue;
    }
    if (c === '(') {
      const controle = !ultimaPalavraEhPropriedade && (['if', 'while', 'for', 'with'].includes(ultimaPalavra) || (ultimaPalavra === 'await' && palavraAnterior === 'for'));
      pilhaParenteses.push(controle); ultimoSignificativo = '('; ultimaPalavra = ''; palavraAnterior = ''; i++; continue;
    }
    if (c === ')') { ultimoSignificativo = pilhaParenteses.pop() ? ';' : ')'; ultimaPalavra = ''; palavraAnterior = ''; i++; continue; }
    if (/[\w$]/.test(c)) {
      let j = i; while (j < s.length && /[\w$]/.test(s[j])) j++;
      ultimaPalavraEhPropriedade = ultimoSignificativo === '.';
      palavraAnterior = ultimaPalavra; ultimaPalavra = s.slice(i, j); ultimoSignificativo = s[j - 1]; i = j; continue;
    }
    if (!/\s/.test(c)) { ultimoSignificativo = c; ultimaPalavra = ''; palavraAnterior = ''; }
    i++;
  }
  return { mascarado: out.join(''), literais };
}

/** Compatibilidade: remove comentários (e agora também oculta strings/templates/regex) preservando posições. */
export function removerComentarios(codigo) {
  return mascararNaoCodigo(codigo).mascarado;
}

const linhaDoIndice = (texto, indice) => texto.slice(0, indice).split('\n').length;
const literalEm = (literais, texto, indice) => (texto[indice] === '"' || texto[indice] === "'" || texto[indice] === '`' ? literais.get(indice) ?? null : null);

function fecharParenteses(texto, abre) {
  let prof = 0;
  for (let k = abre; k < texto.length; k++) {
    if (texto[k] === '(') prof++;
    else if (texto[k] === ')') { prof--; if (prof === 0) return k; }
  }
  return -1;
}

/**
 * Lista, no arquivo inteiro, os bindings de um identificador — só em CÓDIGO (texto mascarado).
 * @returns {Array<{ linha: number, forma: string, modulo: string|null, nomeImportado: string|null }>}
 */
function coletarBindings(texto, literais, ident) {
  const id = ident.replace(/\$/g, '\\$');
  const bindings = [];
  // `indice` é interno (posição no arquivo, para ler o corpo de wrappers); não vai para a evidência.
  const add = (indice, forma, modulo = null, nomeImportado = null) => bindings.push({ linha: linhaDoIndice(texto, indice), forma, modulo, nomeImportado, indice });

  // import … from 'M'   (ignora `import type` e especificadores `type x`)
  for (const m of texto.matchAll(/\bimport\s+(?!type\b)([^;'"`]*?)\bfrom\s*(['"])/g)) {
    const clausula = m[1];
    const modulo = literalEm(literais, texto, m.index + m[0].length - 1);
    const ns = clausula.match(/\*\s*as\s+([\w$]+)/);
    if (ns && ns[1] === ident) add(m.index, FORMAS_IDENTIDADE.IMPORT_NAMESPACE_RECEPTOR, modulo, '*');
    const chaves = clausula.match(/\{([^}]*)\}/);
    if (chaves) {
      for (const esp of chaves[1].split(',').map((x) => x.trim()).filter(Boolean)) {
        if (/^type\s/.test(esp)) continue; // só tipo: não cria binding de valor
        const r = esp.match(/^([\w$]+)(?:\s+as\s+([\w$]+))?$/);
        if (!r) continue;
        const local = r[2] || r[1];
        if (local === ident) add(m.index, r[2] ? FORMAS_IDENTIDADE.FORMA_NAO_SUPORTADA : FORMAS_IDENTIDADE.IMPORT_NOMEADO, modulo, r[1]);
      }
    }
    const padrao = clausula.replace(/\{[^}]*\}/, '').replace(/\*\s*as\s+[\w$]+/, '').replace(/,/g, ' ').trim();
    if (padrao && padrao === ident) add(m.index, FORMAS_IDENTIDADE.FORMA_NAO_SUPORTADA, modulo, 'default');
  }
  // const|let|var { a, b: c } = require('M')
  for (const m of texto.matchAll(/\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\(\s*(['"])/g)) {
    const modulo = literalEm(literais, texto, m.index + m[0].length - 1);
    for (const esp of m[1].split(',').map((x) => x.trim()).filter(Boolean)) {
      const r = esp.match(/^([\w$]+)(?:\s*:\s*([\w$]+))?$/);
      if (!r) continue;
      const local = r[2] || r[1];
      if (local === ident) add(m.index, r[2] ? FORMAS_IDENTIDADE.FORMA_NAO_SUPORTADA : FORMAS_IDENTIDADE.REQUIRE_DESESTRUTURADO, modulo, r[1]);
    }
  }
  // const|let|var X = require('M').membro   |   const|let|var X = require('M')
  for (const m of texto.matchAll(new RegExp(`\\b(?:const|let|var)\\s+${id}\\s*=\\s*require\\s*\\(\\s*(['"])`, 'g'))) {
    const aspa = m.index + m[0].length - 1;
    const modulo = literalEm(literais, texto, aspa);
    const resto = texto.slice(aspa).match(/^(['"])[^'"\n]*\1\s*\)\s*(\.\s*([\w$]+))?/);
    if (resto?.[3]) add(m.index, FORMAS_IDENTIDADE.REQUIRE_MEMBRO, modulo, resto[3]);
    else add(m.index, FORMAS_IDENTIDADE.REQUIRE_MODULO_RECEPTOR, modulo, '*');
  }
  // const|let|var X = <função local | resultado de chamada que não é require/import>
  for (const m of texto.matchAll(new RegExp(`\\b(?:const|let|var)\\s+${id}\\s*(?::[^=;\\n]+)?=(?!=)\\s*([^;\\n]{0,80})`, 'g'))) {
    const init = m[1].trim();
    if (/^require\s*\(/.test(init)) continue; // tratado acima
    const funcao = /^(async\s+)?(function\b|\([^)]*\)\s*(:[^=]+)?=>|[\w$]+\s*=>)/.test(init)
      || (/^(async\s+)?\(/.test(init) && /=>/.test(texto.slice(m.index, m.index + m[0].length + 200)));
    const chamada = /^[\w$]+(\s*\.\s*[\w$]+)*\s*\(/.test(init) && !/^(await\s+)?import\s*\(/.test(init);
    add(m.index, funcao || chamada ? FORMAS_IDENTIDADE.DEFINICAO_LOCAL : FORMAS_IDENTIDADE.FORMA_NAO_SUPORTADA, null, null);
  }
  // for (const|let|var X of|in …)
  for (const m of texto.matchAll(new RegExp(`\\bfor\\s*\\(\\s*(?:const|let|var)\\s+${id}\\s+(?:of|in)\\b`, 'g'))) {
    add(m.index, FORMAS_IDENTIDADE.VARIAVEL_DE_LACO, null, null);
  }
  // function X(…) declarada — sombreamento possível (não afirma nada sozinha)
  for (const m of texto.matchAll(new RegExp(`\\bfunction\\s*\\*?\\s*${id}\\s*\\(`, 'g'))) {
    add(m.index, FORMAS_IDENTIDADE.FUNCAO_DECLARADA, null, null);
  }
  // parâmetros chamados X (function, método, arrow, catch) — sombreamento possível. Só em posição de NOME de
  // parâmetro (início, após vírgula/abre-chave/abre-colchete/rest; seguido de : , = ) } ] ou fim) — nunca como
  // referência de tipo (`p: X.Tipo`) ou membro (`a.X`).
  const ehParam = new RegExp(`(^|[,({\\[]|\\.\\.\\.)\\s*${id}\\s*\\??\\s*(?=[:,=)}\\]]|$)`);
  for (let k = texto.indexOf('('); k !== -1; k = texto.indexOf('(', k + 1)) {
    const fecha = fecharParenteses(texto, k);
    if (fecha === -1) break;
    const lista = texto.slice(k + 1, fecha);
    if (!ehParam.test(lista)) continue;
    const antes = texto.slice(Math.max(0, k - 60), k);
    const depois = texto.slice(fecha + 1, fecha + 120);
    const arrow = /^\s*(:\s*[^=;{}]{0,100})?\s*=>/.test(depois);
    const palavra = antes.match(/([\w$]+)\s*$/)?.[1];
    const funcaoOuMetodo = /\bfunction\s*\*?\s*[\w$]*\s*$/.test(antes)
      || (palavra && !PALAVRAS_NAO_FUNCAO.has(palavra) && /^\s*(:\s*[^={;]{0,100})?\s*\{/.test(depois))
      || /\bcatch\s*$/.test(antes);
    if (arrow || funcaoOuMetodo) add(k, FORMAS_IDENTIDADE.PARAMETRO, null, null);
  }
  for (const m of texto.matchAll(new RegExp(`(^|[^.\\w$])${id}\\s*=>`, 'g'))) add(m.index, FORMAS_IDENTIDADE.PARAMETRO, null, null);
  return bindings;
}

/**
 * Localiza a chamada casada na linha/coluna do match: `exec(` ou `R.exec(`, só em CÓDIGO.
 * Sem coluna válida, só aceita a linha quando há exatamente UMA chamada candidata.
 * @returns {{ simbolo: string, receptor: string|null } | null}
 */
function localizarChamada(texto, linha, coluna) {
  const linhas = texto.split('\n');
  const l = linhas[linha - 1];
  if (l === undefined) return null;
  // PL-05: execSync entra na mesma regra (mesmo shell); o nome chamado segue na evidência.
  const candidatos = [...l.matchAll(/(?:([\w$]+)\s*\.\s*)?(?<![\w$])(exec|execSync)\s*\(/g)];
  if (!candidatos.length) return null;
  const col = Number.isInteger(coluna) && coluna > 0 ? coluna - 1 : null;
  let escolhido = null;
  if (col !== null) escolhido = candidatos.find((m) => m.index === col) || candidatos.find((m) => m.index <= col && col < m.index + m[0].length) || null;
  if (!escolhido && candidatos.length === 1) escolhido = candidatos[0];
  if (!escolhido) return null;
  const receptor = escolhido[1] ?? null;
  const nome = escolhido[2];
  const inicioLinha = linhas.slice(0, linha - 1).reduce((n, x) => n + x.length + 1, 0);
  // `abre`: posição do "(" da chamada no arquivo (para ler os argumentos do ponto de chamada).
  return { simbolo: receptor ? `${receptor}.${nome}` : nome, nome, receptor, abre: inicioLinha + escolhido.index + escolhido[0].length - 1 };
}

// ---- PL-03 (fechamento): leitura LIMITADA do corpo de wrappers locais ------------------------------------------
// Limite explícito: só o mesmo arquivo, só a definição do próprio `exec` (um nível), no máximo LIMITE_CORPO_WRAPPER
// caracteres. Nenhuma travessia entre arquivos ou para outras funções locais: qualquer chamada não resolvida
// devolve INDETERMINADO (a identidade fica NAO_DETERMINADA, fail-closed).
const LIMITE_CORPO_WRAPPER = 8000;
const FUNCOES_COM_SHELL = new Set(['exec', 'execSync']);
const FUNCOES_SEM_SHELL = new Set(['execFile', 'execFileSync', 'spawn', 'spawnSync']);
const METODOS_DE_EXECUCAO = new Set([...FUNCOES_COM_SHELL, ...FUNCOES_SEM_SHELL, 'fork', 'run', 'system', 'shell', 'command']);
const GLOBAIS_INOFENSIVOS = new Set(['String', 'Number', 'Boolean', 'Array', 'Object', 'JSON', 'Math', 'Date', 'Error', 'TypeError', 'RangeError', 'Promise', 'Buffer', 'Symbol', 'Map', 'Set', 'BigInt', 'parseInt', 'parseFloat', 'isNaN', 'encodeURIComponent', 'decodeURIComponent', 'setTimeout', 'clearTimeout', 'setImmediate']);
const PALAVRAS_NAO_CHAMADA = new Set(['if', 'for', 'while', 'switch', 'catch', 'function', 'return', 'typeof', 'await', 'yield', 'import', 'super', 'new', 'delete', 'void', 'in', 'of', 'instanceof']);

function fecharChaves(texto, abre) {
  let prof = 0;
  for (let k = abre; k < texto.length && k - abre <= LIMITE_CORPO_WRAPPER; k++) {
    if (texto[k] === '{') prof++;
    else if (texto[k] === '}') { prof--; if (prof === 0) return k; }
  }
  return -1;
}

function fimDaInstrucao(texto, ini) {
  let prof = 0;
  for (let k = ini; k < texto.length && k - ini <= LIMITE_CORPO_WRAPPER; k++) {
    const c = texto[k];
    if ('([{'.includes(c)) prof++;
    else if (')]}'.includes(c)) { prof--; if (prof < 0) return k; }
    else if (c === ';' && prof === 0) return k;
    else if (c === '\n' && prof === 0 && !/([=+\-*/,(&|?:]|=>)\s*$/.test(texto.slice(ini, k))) return k;
  }
  return -1;
}

/** Faixas [ini, fim) dos argumentos de nível superior de uma chamada cujo "(" está em `abre` (texto mascarado). */
export function argumentosDaChamada(texto, abre) {
  const fecha = fecharParenteses(texto, abre);
  if (fecha === -1) return null;
  const args = [];
  let prof = 0; let ini = abre + 1;
  for (let k = abre + 1; k < fecha; k++) {
    const c = texto[k];
    if ('([{'.includes(c)) prof++;
    else if (')]}'.includes(c)) prof--;
    else if (c === ',' && prof === 0) { args.push([ini, k]); ini = k + 1; }
  }
  if (texto.slice(ini, fecha).trim()) args.push([ini, fecha]);
  return { fecha, args };
}

/**
 * Parâmetros de uma lista (texto mascarado entre `ini` e `fim`), separados só nas vírgulas de NÍVEL SUPERIOR, com a
 * faixa do valor padrão quando houver (`opts = { shell: true }`). Revisão r1 do fechamento: o split por toda vírgula
 * deslocava os índices e o padrão era ignorado — chamada sem opções virava "sem shell".
 * @returns {Array<{ nome: string, padrao: [number, number] | null }>}
 */
function parametrosDe(texto, ini, fim) {
  const pedacos = [];
  let prof = 0;
  let inicio = ini;
  for (let k = ini; k <= fim; k++) {
    const c = k < fim ? texto[k] : ',';
    if ('([{<'.includes(c) && k < fim) prof++;
    else if (')]}>'.includes(c) && k < fim && !(c === '>' && texto[k - 1] === '=')) prof--;
    else if (c === ',' && prof <= 0) { pedacos.push([inicio, k]); inicio = k + 1; }
  }
  return pedacos
    .filter(([a, b]) => texto.slice(a, b).trim())
    .map(([a, b]) => {
      const bruto = texto.slice(a, b);
      const nome = (bruto.trim().replace(/^\.\.\./, '').match(/^([\w$]+)/) || [])[1] ?? '?';
      let prof2 = 0;
      let padrao = null;
      for (let k = a; k < b; k++) {
        const c = texto[k];
        if ('([{<'.includes(c)) prof2++;
        else if (')]}>'.includes(c) && !(c === '>' && texto[k - 1] === '=')) prof2--;
        else if (c === '=' && prof2 === 0 && texto[k + 1] !== '>' && texto[k + 1] !== '=' && !'=!<>'.includes(texto[k - 1])) {
          padrao = [k + 1, b];
          break;
        }
      }
      return { nome, padrao };
    });
}

/** Corpo e parâmetros da definição local do `exec` (ou null se fora do limite / forma sem corpo legível). */
function definicaoDoWrapper(texto, binding, ident) {
  const id = ident.replace(/\$/g, '\\$');
  if (binding.forma === FORMAS_IDENTIDADE.FUNCAO_DECLARADA) {
    const abre = texto.indexOf('(', binding.indice);
    const fechaP = fecharParenteses(texto, abre);
    const chave = fechaP === -1 ? -1 : texto.indexOf('{', fechaP);
    const fechaC = chave === -1 ? -1 : fecharChaves(texto, chave);
    if (fechaC === -1) return null;
    return { ini: chave, fim: fechaC + 1, params: parametrosDe(texto, abre + 1, fechaP) };
  }
  if (binding.forma !== FORMAS_IDENTIDADE.DEFINICAO_LOCAL) return null;
  const m = new RegExp(`\\b(?:const|let|var)\\s+${id}\\s*(?::[^=;\\n]+)?=(?!=)\\s*`, 'y');
  m.lastIndex = binding.indice;
  const cab = m.exec(texto);
  if (!cab) return null;
  let p = binding.indice + cab[0].length;
  const resto = texto.slice(p);
  const asy = resto.match(/^async\s+/);
  if (asy) p += asy[0].length;
  const r = texto.slice(p);
  let params = [];
  if (/^function\b/.test(r) || r.startsWith('(') || /^[\w$]+\s*=>/.test(r)) {
    let aposParams;
    if (/^[\w$]+\s*=>/.test(r)) { params = [{ nome: r.match(/^([\w$]+)/)[1], padrao: null }]; aposParams = p + r.indexOf('=>'); }
    else {
      const abre = texto.indexOf('(', p);
      const fechaP = fecharParenteses(texto, abre);
      if (fechaP === -1) return null;
      params = parametrosDe(texto, abre + 1, fechaP);
      aposParams = fechaP + 1;
    }
    const seta = texto.slice(aposParams).match(/^\s*(?::[^={;]{0,100})?\s*(=>)?\s*/);
    const inicioCorpo = aposParams + seta[0].length;
    if (texto[inicioCorpo] === '{') {
      const fechaC = fecharChaves(texto, inicioCorpo);
      return fechaC === -1 ? null : { ini: inicioCorpo, fim: fechaC + 1, params };
    }
    const fimExp = fimDaInstrucao(texto, inicioCorpo);
    return fimExp === -1 ? null : { ini: inicioCorpo, fim: fimExp, params };
  }
  const fim = fimDaInstrucao(texto, p); // resultado de chamada (ex.: promisify(execFile), fábrica(...))
  return fim === -1 ? null : { ini: p, fim, params };
}

/** Uma expressão de opções (texto mascarado) contém a chave `shell`? null = não dá para saber. */
function opcoesTemShell(texto, faixa, corpo, params, argsSite) {
  if (!faixa) return false; // opções ausentes: sem shell
  const expr = texto.slice(faixa[0], faixa[1]).trim();
  if (expr.startsWith('{')) {
    // Só as entradas de PRIMEIRO nível importam (`env: { ...x }` aninhado não muda `shell`).
    const entradas = [];
    let prof = 0; let ini = 1;
    for (let k = 0; k < expr.length; k++) {
      const c = expr[k];
      if ('([{'.includes(c)) prof++;
      else if (')]}'.includes(c)) { prof--; if (prof === 0) { entradas.push(expr.slice(ini, k)); break; } }
      else if (c === ',' && prof === 1) { entradas.push(expr.slice(ini, k)); ini = k + 1; }
    }
    const itens = entradas.map((e) => e.trim()).filter(Boolean);
    if (itens.some((e) => e.startsWith('...'))) return null; // spread de primeiro nível: conteúdo não visível
    // `shell: false` ⇒ sem shell; `shell: true` ⇒ com shell; qualquer outro valor (variável, abreviado `{ shell }`,
    // string) ⇒ não demonstrado.
    const entradaShell = itens.find((e) => /^shell\s*(:|$)/.test(e));
    if (!entradaShell) return false;
    const valor = entradaShell.replace(/^shell\s*:?/, '').trim();
    if (valor === 'false') return false;
    if (valor === 'true') return true;
    return null;
  }
  const ident = expr.match(/^[\w$]+$/)?.[0];
  if (!ident) return null;
  const local = texto.slice(corpo.ini, corpo.fim).match(new RegExp(`\\b(?:const|let|var)\\s+${ident.replace(/\$/g, '\\$')}\\s*=\\s*\\{`));
  if (local) {
    const abre = corpo.ini + local.index + local[0].length - 1;
    const fecha = fecharChaves(texto, abre);
    if (fecha === -1) return null;
    return opcoesTemShell(texto, [abre, fecha + 1], corpo, params, argsSite);
  }
  const k = params.findIndex((prm) => prm.nome === ident);
  if (k === -1) return null;
  if (!argsSite) return null; // argumentos do ponto de chamada ilegíveis: não dá para saber
  const doSite = argsSite.args[k] ?? null;
  if (doSite) return opcoesTemShell(texto, doSite, corpo, [], null);
  // argumento omitido: vale o padrão do parâmetro (se houver); sem padrão, as opções são undefined (sem shell)
  if (params[k].padrao) return opcoesTemShell(texto, params[k].padrao, corpo, [], null);
  return false;
}

function faixaDeOpcoes(texto, args) {
  if (!args) return null;
  if (args.args.length >= 3) return args.args[2];
  if (args.args.length === 2 && texto.slice(args.args[1][0], args.args[1][1]).trim().startsWith('{')) return args.args[1];
  return null;
}

/**
 * Lê o corpo do wrapper local e diz a que ele delega.
 * @returns {{ tipo: 'COM_SHELL'|'SEM_SHELL'|'SEM_CHILD_PROCESS'|'INDETERMINADO', detalhe: string, modulo?: string }}
 */
function analisarWrapper(texto, literais, def, chamada) {
  const corpo = texto.slice(def.ini, def.fim);
  const argsSite = chamada.abre != null ? argumentosDaChamada(texto, chamada.abre) : null;
  const resolverCompat = (nome, receptor) => {
    const bs = coletarBindings(texto, literais, receptor || nome);
    if (!bs.length) return null;
    // Dentro do corpo do wrapper, alias nomeado (`{ exec: cpExec }`, `import { exec as run }`) é resolvido pelo
    // nome importado; import default continua não suportado.
    const aliasNomeado = (b) => b.forma === FORMAS_IDENTIDADE.FORMA_NAO_SUPORTADA && b.nomeImportado && b.nomeImportado !== 'default';
    const ok = bs.every((b) => MODULOS_COMPATIVEIS.has(b.modulo) && (receptor
      ? [FORMAS_IDENTIDADE.IMPORT_NAMESPACE_RECEPTOR, FORMAS_IDENTIDADE.REQUIRE_MODULO_RECEPTOR].includes(b.forma)
      : [FORMAS_IDENTIDADE.IMPORT_NOMEADO, FORMAS_IDENTIDADE.REQUIRE_DESESTRUTURADO, FORMAS_IDENTIDADE.REQUIRE_MEMBRO].includes(b.forma) || aliasNomeado(b)));
    if (!ok) return null;
    return { funcao: receptor ? nome : bs[0].nomeImportado, modulo: bs[0].modulo };
  };
  const chamadasCompat = [];
  // promisify(X) / util.promisify(X): o wrapper É X, com as opções vindas do ponto de chamada.
  const prom = corpo.match(/(?<![\w$])(?:[\w$]+\s*\.\s*)?promisify\s*\(\s*(?:([\w$]+)\s*\.\s*)?([\w$]+)\s*\)/);
  if (prom) {
    const alvo = resolverCompat(prom[2], prom[1] ?? null);
    if (!alvo) return { tipo: 'INDETERMINADO', detalhe: `promisify de '${prom[2]}' não ligado a child_process` };
    chamadasCompat.push({ ...alvo, opcoes: faixaDeOpcoes(texto, argsSite), viaSite: true });
  }
  // chamadas de método com nome de execução: só valem se o receptor for o módulo compatível
  for (const m of corpo.matchAll(/(?:([\w$]+)|[)\]])\s*\.\s*([\w$]+)\s*\(/g)) {
    if (!METODOS_DE_EXECUCAO.has(m[2])) continue;
    const alvo = m[1] ? resolverCompat(m[2], m[1]) : null;
    if (!alvo) return { tipo: 'INDETERMINADO', detalhe: `chamada '.${m[2]}(' com receptor não resolvido` };
    chamadasCompat.push({ ...alvo, abre: def.ini + m.index + m[0].length - 1 });
  }
  // chamadas diretas (sem receptor)
  for (const m of corpo.matchAll(/(?<![\w$.])(new\s+)?([\w$]+)\s*\(/g)) {
    const nome = m[2];
    if (m[1] || PALAVRAS_NAO_CHAMADA.has(nome) || GLOBAIS_INOFENSIVOS.has(nome)) continue;
    if (prom && nome === 'promisify') continue;
    if (nome === 'require') continue;
    const alvo = resolverCompat(nome, null);
    if (!alvo) return { tipo: 'INDETERMINADO', detalhe: `chamada a '${nome}(' não resolvida dentro do wrapper` };
    chamadasCompat.push({ ...alvo, abre: def.ini + m.index + m[0].length - 1 });
  }
  if (!chamadasCompat.length) return { tipo: 'SEM_CHILD_PROCESS', detalhe: 'o corpo do wrapper não chama nenhuma função de child_process' };
  const comShell = chamadasCompat.find((c) => FUNCOES_COM_SHELL.has(c.funcao));
  if (comShell) return { tipo: 'COM_SHELL', detalhe: `o wrapper delega a ${comShell.funcao} de '${comShell.modulo}' (shell)`, modulo: comShell.modulo };
  for (const c of chamadasCompat) {
    if (!FUNCOES_SEM_SHELL.has(c.funcao)) return { tipo: 'INDETERMINADO', detalhe: `o wrapper chama ${c.funcao} de child_process` };
    const faixa = c.viaSite ? c.opcoes : faixaDeOpcoes(texto, argumentosDaChamada(texto, c.abre));
    const shell = opcoesTemShell(texto, faixa, def, c.viaSite ? [] : def.params, argsSite);
    // shell: true demonstrado ⇒ o wrapper executa via shell (equivalente a exec); desconhecido ⇒ indeterminado.
    if (shell === true) return { tipo: 'COM_SHELL', detalhe: `o wrapper delega a ${c.funcao} de '${c.modulo}' com a opção shell`, modulo: c.modulo };
    if (shell !== false) return { tipo: 'INDETERMINADO', detalhe: `não foi possível provar a ausência de shell nas opções de ${c.funcao}` };
  }
  const fns = [...new Set(chamadasCompat.map((c) => c.funcao))].join(', ');
  return { tipo: 'SEM_SHELL', detalhe: `o wrapper delega a ${fns} de '${chamadasCompat[0].modulo}' sem a opção shell`, modulo: chamadasCompat[0].modulo };
}

function descreverBinding(b) {
  return `${b.forma}${b.modulo ? ` de '${b.modulo}'` : ''}${b.nomeImportado && b.nomeImportado !== '*' ? ` (nome importado: ${b.nomeImportado})` : ''} na linha ${b.linha}`;
}

/** O arquivo referencia (em código) algum módulo compatível? Então uma definição local pode ser wrapper dele. */
function referenciaModuloCompativel(texto, literais) {
  // `import type … from 'M'` não existe em tempo de execução: não torna ninguém wrapper de M.
  const soTipo = new Set([...texto.matchAll(/\bimport\s+type\b[^;'"`]*?\bfrom\s*(['"])/g)].map((m) => m.index + m[0].length - 1));
  // Aceita também template sem ${} (`child_process`): na dúvida, referência conta (fail-closed).
  for (const m of texto.matchAll(/\b(?:from|require|import)\s*\(?\s*(['"`])/g)) {
    const aspa = m.index + m[0].length - 1;
    if (soTipo.has(aspa)) continue;
    if (MODULOS_COMPATIVEIS.has(literalEm(literais, texto, aspa))) return true;
  }
  return false;
}

/**
 * Resolve a identidade do símbolo chamado num match da regra zunvio.child-process-exec.
 * @param {object} params
 * @param {string|null} params.codigo - Conteúdo do arquivo (null quando ilegível).
 * @param {number} params.linha - Linha do match (1-based).
 * @param {number} [params.coluna] - Coluna do match (1-based), quando o scanner informa.
 * @returns {Readonly<object>} evidência estruturada da identidade.
 */
export function resolverIdentidadeChildProcessExec({ codigo, linha, coluna }) {
  let base = { regra: 'zunvio.child-process-exec', apiPretendida: API_CHILD_PROCESS_EXEC };
  const resultado = (status, forma, extra) => Object.freeze({ ...base, status, forma, simbolo: null, receptor: null, origem: null, linhaOrigem: null, bindings: [], sombreamento: false, ...extra });

  if (typeof codigo !== 'string') {
    return resultado(STATUS_IDENTIDADE.NAO_DETERMINADA, FORMAS_IDENTIDADE.ARQUIVO_ILEGIVEL, { motivo: 'Arquivo do achado não pôde ser lido; identidade não demonstrada.' });
  }
  const { mascarado: texto, literais } = mascararNaoCodigo(codigo);
  const chamada = localizarChamada(texto, linha, coluna);
  if (!chamada) {
    return resultado(STATUS_IDENTIDADE.NAO_DETERMINADA, FORMAS_IDENTIDADE.CHAMADA_NAO_LOCALIZADA, { motivo: `Chamada exec(...)/execSync(...) não localizada de forma inequívoca na linha ${linha}; identidade não demonstrada.` });
  }
  // PL-05: a API pretendida acompanha o nome chamado (child_process.exec | child_process.execSync).
  const api = `child_process.${chamada.nome}`;
  base = { ...base, apiPretendida: api };
  const alvo = chamada.receptor || chamada.nome;
  const bindings = coletarBindings(texto, literais, alvo);
  const lista = bindings.map(({ indice, ...b }) => Object.freeze({ ...b }));
  const comum = { simbolo: chamada.simbolo, receptor: chamada.receptor, bindings: lista };

  if (!bindings.length) {
    return resultado(STATUS_IDENTIDADE.NAO_DETERMINADA, FORMAS_IDENTIDADE.SEM_BINDING, { ...comum, motivo: `Nenhum binding de '${alvo}' encontrado no arquivo nas formas suportadas; identidade não demonstrada.` });
  }

  const classificar = (b) => {
    if ([FORMAS_IDENTIDADE.FORMA_NAO_SUPORTADA, FORMAS_IDENTIDADE.PARAMETRO].includes(b.forma)) return 'INDETERMINADO';
    // PL-03 (fechamento): função declarada é definição local (junto de import continua AMBIGUA: classes divergem).
    if ([FORMAS_IDENTIDADE.DEFINICAO_LOCAL, FORMAS_IDENTIDADE.VARIAVEL_DE_LACO, FORMAS_IDENTIDADE.FUNCAO_DECLARADA].includes(b.forma)) return chamada.receptor ? 'INDETERMINADO' : 'LOCAL';
    if (!MODULOS_COMPATIVEIS.has(b.modulo)) return 'INDETERMINADO'; // outro módulo pode reexportar child_process.exec
    if (chamada.receptor) {
      return b.forma === FORMAS_IDENTIDADE.IMPORT_NAMESPACE_RECEPTOR || b.forma === FORMAS_IDENTIDADE.REQUIRE_MODULO_RECEPTOR ? 'API' : 'INDETERMINADO';
    }
    return (b.forma === FORMAS_IDENTIDADE.IMPORT_NOMEADO || b.forma === FORMAS_IDENTIDADE.REQUIRE_DESESTRUTURADO || b.forma === FORMAS_IDENTIDADE.REQUIRE_MEMBRO) && b.nomeImportado === chamada.nome ? 'API' : 'INDETERMINADO';
  };
  const classes = new Set(bindings.map(classificar));

  if (classes.size > 1) {
    return resultado(STATUS_IDENTIDADE.NAO_DETERMINADA, FORMAS_IDENTIDADE.AMBIGUA, { ...comum, sombreamento: true, motivo: `Bindings divergentes de '${alvo}' no mesmo arquivo (${bindings.map(descreverBinding).join('; ')}); sem análise de escopo, a identidade não é demonstrada.` });
  }
  const [classe] = classes;
  const primeiro = bindings[0];
  if (classe === 'API') {
    return resultado(STATUS_IDENTIDADE.CONFIRMADA, primeiro.forma, { ...comum, origem: primeiro.modulo, linhaOrigem: primeiro.linha, motivo: `'${chamada.simbolo}' está ligado a '${primeiro.modulo}' (${descreverBinding(primeiro)}): identidade de ${api} confirmada.` });
  }
  if (classe === 'LOCAL') {
    if (referenciaModuloCompativel(texto, literais)) {
      // PL-03 (fechamento): lê o corpo da definição (um nível, mesmo arquivo, limite explícito) para saber a que
      // o wrapper delega. Só com UMA definição legível; qualquer dúvida mantém NAO_DETERMINADA/POSSIVEL_WRAPPER.
      const def = bindings.length === 1 ? definicaoDoWrapper(texto, primeiro, alvo) : null;
      const w = def ? analisarWrapper(texto, literais, def, chamada) : { tipo: 'INDETERMINADO', detalhe: bindings.length === 1 ? 'corpo da definição fora do limite de leitura' : 'mais de uma definição local' };
      const wrapper = { tipo: w.tipo, detalhe: w.detalhe, limite: `mesmo arquivo, um nível, até ${LIMITE_CORPO_WRAPPER} caracteres` };
      if (w.tipo === 'COM_SHELL') {
        return resultado(STATUS_IDENTIDADE.CONFIRMADA, FORMAS_IDENTIDADE.WRAPPER_DE_EXEC, { ...comum, origem: w.modulo, linhaOrigem: primeiro.linha, wrapper, motivo: `'${alvo}' é um wrapper local (${descreverBinding(primeiro)}) e ${w.detalhe}: a chamada executa comando por shell como ${api}.` });
      }
      if (w.tipo === 'SEM_SHELL' || w.tipo === 'SEM_CHILD_PROCESS') {
        return resultado(STATUS_IDENTIDADE.RECUSADA, w.tipo === 'SEM_SHELL' ? FORMAS_IDENTIDADE.WRAPPER_SEM_SHELL : primeiro.forma, { ...comum, origem: 'LOCAL', linhaOrigem: primeiro.linha, wrapper, motivo: `'${alvo}' é um wrapper local (${descreverBinding(primeiro)}) e ${w.detalhe}: não é ${api}.` });
      }
      return resultado(STATUS_IDENTIDADE.NAO_DETERMINADA, FORMAS_IDENTIDADE.POSSIVEL_WRAPPER, { ...comum, origem: 'LOCAL', linhaOrigem: primeiro.linha, wrapper, motivo: `'${alvo}' é definido localmente (${bindings.map(descreverBinding).join('; ')}) num arquivo que referencia child_process, e ${w.detalhe}: a definição pode ser um wrapper de shell; identidade não demonstrada nem recusada.` });
    }
    return resultado(STATUS_IDENTIDADE.RECUSADA, primeiro.forma, { ...comum, origem: 'LOCAL', linhaOrigem: primeiro.linha, motivo: `'${alvo}' é definido localmente no arquivo (${bindings.map(descreverBinding).join('; ')}), nenhum binding o liga a child_process e o arquivo não referencia nenhum módulo compatível: não é ${api}.` });
  }
  return resultado(STATUS_IDENTIDADE.NAO_DETERMINADA, primeiro.forma, { ...comum, origem: primeiro.modulo, linhaOrigem: primeiro.linha, motivo: `Binding de '${alvo}' em forma não suportada nesta fatia, de módulo não compatível ou de sombreamento possível (${descreverBinding(primeiro)}); identidade não demonstrada.` });
}
