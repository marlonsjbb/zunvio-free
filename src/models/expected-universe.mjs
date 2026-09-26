// PL-02 — UNIVERSO ESPERADO × ANÁLISE EFETIVA.
//
//   UNIVERSO ESPERADO → ELEGIBILIDADE → ENVIADO AO SCANNER → ANALISADO → NÃO ANALISADO + MOTIVO
//
// "O scanner não relatou erro" ≠ "tudo o que deveria ser analisado foi analisado" (Bancada Pública v1, B4: 12
// arquivos .mts/.cts e 1 .cjs de 3,78 MB ficaram fora da análise sem nenhuma declaração). Este módulo compara o
// inventário do PRÓPRIO ZUNVIO com o que o scanner efetivamente analisou e transforma a diferença em evidência.
//
// Regras:
//  - a expectativa é do ZUNVIO (cobertura declarada no rulepack), não a tabela interna do scanner;
//  - nem todo arquivo vai para todo scanner: elegibilidade por cobertura declarada;
//  - motivo só quando DEMONSTRÁVEL pelo lado do ZUNVIO (tamanho medido, extensão, erro declarado); sem isso,
//    UNKNOWN_CAUSE — nunca COMPLETE;
//  - escala: nenhuma lista gigante vai para o pack (contagens + teto + digest reproduzível).

import { createHash } from 'node:crypto';
import { extname } from 'node:path';
import { TIPO_EXCLUSAO } from '../scan-inventory.mjs';

export const MODELO_UNIVERSO = 'pl02-1.0';

/** Extensões que o ZUNVIO ESPERA por linguagem declarada no rulepack (expectativa do produto). */
export const EXTENSOES_POR_LINGUAGEM = Object.freeze({
  javascript: Object.freeze(['.cjs', '.js', '.jsx', '.mjs']),
  typescript: Object.freeze(['.cts', '.mts', '.ts', '.tsx'])
});

/**
 * Extensões que o Semgrep 1.176.0 (versão fixada em engine-bootstrap.mjs) efetivamente analisa para
 * javascript/typescript. Levantado por sonda com o binário real (PL-02, 25/09/2026) e protegido por teste com o
 * binário real: `.mts`/`.cts` NÃO são analisados e o Semgrep não declara nada. Mudou a versão do Semgrep? Refazer
 * a sonda — o teste falha alto.
 */
export const SEMGREP_EXTENSOES_RECONHECIDAS = Object.freeze(['.cjs', '.js', '.jsx', '.mjs', '.ts', '.tsx']);

export const MOTIVO_UNIVERSO = Object.freeze({
  UNSUPPORTED_EXTENSION: 'UNSUPPORTED_EXTENSION',
  SIZE_LIMIT_EXCEEDED: 'SIZE_LIMIT_EXCEEDED',
  OPERATIONAL_LIMIT: 'OPERATIONAL_LIMIT',
  UNKNOWN_CAUSE: 'UNKNOWN_CAUSE',
  SCANNER_REPORTS_NO_COVERAGE_SIGNAL: 'SCANNER_REPORTS_NO_COVERAGE_SIGNAL',
  // Revisão r4: o inventário não conseguiu ler (lstat/listagem) um caminho que pode conter arquivo esperado.
  READ_ERROR: 'READ_ERROR'
});

/** Motivos que um universo selado pode trazer (conjunto fechado; o SaaS usa o mesmo). */
export const MOTIVOS_DO_UNIVERSO = Object.freeze(new Set([
  'TIMEOUT', 'FILE_SKIPPED', 'PARTIAL_PARSING', 'PARSE_ERROR', 'FILE_ERROR', 'RULE_ERROR',
  'UNSUPPORTED_EXTENSION', 'SIZE_LIMIT_EXCEEDED', 'OPERATIONAL_LIMIT', 'UNKNOWN_CAUSE', 'READ_ERROR'
]));
const TIPOS_DE_EXCLUSAO_POLITICA = new Set(['DIRETORIO_POLITICA', 'LINK_SIMBOLICO', 'OUTRA']);
const CRITERIOS_COM_UNIVERSO_MEDIDO = new Set(['SUCCESS_EXPECTED_UNIVERSE_ANALYZED', 'SUCCESS_WITH_UNANALYZED_EXPECTED_FILES', 'SUCCESS_WITH_FILE_OR_RULE_ERRORS']);

export const ESTADO_ARQUIVO = Object.freeze({
  ANALISADO: 'ANALISADO',
  PARCIAL: 'PARCIAL',
  NAO_ANALISADO: 'NAO_ANALISADO'
});

/** Teto de arquivos listados no pack (igual ao `maxItems` do contrato de ingestão); o resto vai em digest. */
export const TETO_ARQUIVOS_AFETADOS = 200;

const sha256 = (texto) => createHash('sha256').update(texto).digest('hex');
const ordenar = (lista) => [...lista].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

/** Digest reproduzível de uma lista de linhas (ordenada, uma por linha). */
export function digestDeLista(linhas) {
  return sha256(ordenar(linhas).join('\n') + '\n');
}

/** Extensão em minúsculas (".d.mts" → ".mts"); arquivo sem extensão → "". */
export function extensaoDe(caminho) {
  return extname(String(caminho || '')).toLowerCase();
}

const ALIAS_LINGUAGEM = Object.freeze({ js: 'javascript', ts: 'typescript', javascript: 'javascript', typescript: 'typescript' });

/**
 * Linguagens declaradas → as que este modelo cobre. Uma linguagem declarada FORA do modelo torna o universo
 * inavaliável (null): medir só uma parte e chamar de "universo analisado" seria afirmar o que não foi comprovado.
 */
export function linguagensDoModelo(linguagens) {
  const modeladas = new Set();
  for (const l of linguagens || []) {
    const canonica = ALIAS_LINGUAGEM[String(l).toLowerCase()];
    if (!canonica) return null;
    modeladas.add(canonica);
  }
  return ordenar(modeladas);
}

/** Extensões esperadas para as linguagens declaradas (só linguagens que o ZUNVIO conhece). */
export function extensoesEsperadas(linguagens) {
  const conjunto = new Set();
  for (const l of linguagens || []) for (const e of EXTENSOES_POR_LINGUAGEM[l] || []) conjunto.add(e);
  return ordenar(conjunto);
}

function porTipoDeExclusao(exclusoes) {
  const contagem = {};
  for (const e of exclusoes || []) {
    const tipo = e?.tipo || 'OUTRA';
    contagem[tipo] = (contagem[tipo] || 0) + 1;
  }
  return contagem;
}

/** Fronteira declarada do universo: o que o inventário não enviou por POLÍTICA e o que não conseguiu ler. */
function fronteira(inventario) {
  const exclusoes = inventario?.exclusoes || [];
  const politica = exclusoes.filter((e) => e?.tipo !== TIPO_EXCLUSAO.LIMITE_TAMANHO_ARQUIVO);
  return {
    filesSent: (inventario?.arquivosRelativos || []).length,
    policyExclusions: politica.length,
    policyExclusionsByKind: porTipoDeExclusao(politica),
    // PL-01: inclui o que ficou além do limite operacional do inventário (quantidade de arquivos ou bytes totais).
    operationalLimitExclusions: exclusoes.length - politica.length + (inventario?.limiteOperacional?.arquivos || 0),
    readErrors: (inventario?.errosLeitura || []).length
  };
}

/**
 * Motivos do Semgrep por arquivo (a partir de `errors`), com a mesma classificação da Fatia 1.
 * @param {Array} erros - json.errors
 * @param {(bruto: string) => string} caminhoRelativo
 * @param {(erro: object) => string} motivoDoErro - motivoDoErroSemgrep (models/completeness.mjs)
 */
function errosPorArquivo(erros, caminhoRelativo, motivoDoErro) {
  const mapa = new Map();
  for (const erro of erros || []) {
    if (typeof erro?.path !== 'string' || !erro.path) continue;
    const caminho = caminhoRelativo(erro.path);
    const atual = mapa.get(caminho) || { timeouts: 0, motivos: new Set() };
    const motivo = motivoDoErro(erro);
    if (motivo === 'TIMEOUT') atual.timeouts++;
    atual.motivos.add(motivo);
    mapa.set(caminho, atual);
  }
  return mapa;
}

/**
 * Universo esperado do Semgrep × análise efetiva.
 * @param {object} p
 * @param {object} p.inventario - criarInventarioScanner(): arquivosRelativos, tamanhos, shebangNode, exclusoes, errosLeitura
 * @param {object} p.json - saída JSON do Semgrep (precisa de paths.scanned e errors)
 * @param {(bruto: string) => string} p.caminhoRelativo - caminho do Semgrep → caminho relativo ao inventário
 * @param {string[]} p.linguagens - linguagens declaradas no rulepack
 * @param {{ maxTargetBytes: number, timeoutsBeforeFileSkipped: number }} p.limites - limites efetivos do Semgrep
 * @param {(erro: object) => string} p.motivoDoErro
 * @returns {{ universe: object, arquivos: Array<{ path: string, state: string, reasons: string[], timeouts: number }> } | null}
 *   null quando não há inventário ou sinais para comparar (o chamador mantém a Fatia 1).
 */
export function avaliarUniversoSemgrep({ inventario, json, caminhoRelativo, linguagens, limites, motivoDoErro }) {
  if (!inventario || !Array.isArray(inventario.arquivosRelativos)) return null;
  // PL-01: acima do limite e sem nem a contagem fechar, o universo esperado não é determinável — nada de universo.
  if (inventario.limiteOperacional?.universoDeterminado === false) return null;
  if (!json || !Array.isArray(json.paths?.scanned) || !Array.isArray(json.errors)) return null;
  const modeladas = linguagensDoModelo(linguagens);
  if (!modeladas) return null;
  const extensoes = extensoesEsperadas(modeladas);
  if (!extensoes.length) return null;
  const esperadaExt = new Set(extensoes);
  const shebang = new Set(inventario.shebangNode || []);
  const elegivel = (caminho) => {
    const ext = extensaoDe(caminho);
    return ext === '' ? shebang.has(caminho) : esperadaExt.has(ext);
  };
  const reconhecidas = new Set(SEMGREP_EXTENSOES_RECONHECIDAS);
  const scanned = new Set(json.paths.scanned.map((p) => caminhoRelativo(p)));
  const erros = errosPorArquivo(json.errors, caminhoRelativo, motivoDoErro);
  const tamanhos = inventario.tamanhos || {};
  const limiarTimeout = limites?.timeoutsBeforeFileSkipped ?? 3;
  const maxBytes = limites?.maxTargetBytes ?? 1_000_000;

  const arquivos = [];
  const esperados = new Set();
  let analisados = 0;
  const classificar = (caminho, estado, motivos, timeouts = 0) => {
    if (estado === ESTADO_ARQUIVO.ANALISADO) { analisados++; return; }
    arquivos.push({ path: caminho, state: estado, reasons: ordenar(new Set(motivos)), timeouts });
  };

  for (const caminho of inventario.arquivosRelativos) {
    if (!elegivel(caminho)) continue;
    esperados.add(caminho);
    const e = erros.get(caminho);
    if (scanned.has(caminho)) {
      if (!e) { classificar(caminho, ESTADO_ARQUIVO.ANALISADO, []); continue; }
      const motivos = [...e.motivos];
      if (e.timeouts >= limiarTimeout) {
        // EXP-LC-03: o arquivo pulado por timeout CONTINUA em paths.scanned; só errors revela o pulo.
        classificar(caminho, ESTADO_ARQUIVO.NAO_ANALISADO, [...motivos, 'FILE_SKIPPED'], e.timeouts);
      } else if (e.motivos.has('PARSE_ERROR')) {
        // Fatia 1 (caso controlado com o binário real): erro de sintaxe/léxico descarta o arquivo inteiro.
        classificar(caminho, ESTADO_ARQUIVO.NAO_ANALISADO, motivos, e.timeouts);
      } else if (e.motivos.has('FILE_ERROR')) {
        // Efeito não demonstrado: leitura conservadora (não se afirma que foi analisado).
        classificar(caminho, ESTADO_ARQUIVO.NAO_ANALISADO, motivos, e.timeouts);
      } else {
        // PartialParsing ou 1–2 timeouts: analisado, mas não por inteiro.
        classificar(caminho, ESTADO_ARQUIVO.PARCIAL, motivos, e.timeouts);
      }
      continue;
    }
    // Fora de paths.scanned: o motivo declarado pelo Semgrep vale primeiro; sem ele, só o demonstrável pelo ZUNVIO.
    const bytes = tamanhos[caminho];
    if (e) {
      classificar(caminho, ESTADO_ARQUIVO.NAO_ANALISADO, e.timeouts >= limiarTimeout ? [...e.motivos, 'FILE_SKIPPED'] : [...e.motivos], e.timeouts);
    } else if (Number.isInteger(bytes) && bytes > maxBytes) {
      classificar(caminho, ESTADO_ARQUIVO.NAO_ANALISADO, [MOTIVO_UNIVERSO.SIZE_LIMIT_EXCEEDED]);
    } else if (extensaoDe(caminho) !== '' && !reconhecidas.has(extensaoDe(caminho))) {
      classificar(caminho, ESTADO_ARQUIVO.NAO_ANALISADO, [MOTIVO_UNIVERSO.UNSUPPORTED_EXTENSION]);
    } else {
      classificar(caminho, ESTADO_ARQUIVO.NAO_ANALISADO, [MOTIVO_UNIVERSO.UNKNOWN_CAUSE]);
    }
  }
  // PL-01: arquivo esperado que ficou além do limite operacional do inventário (não enviado) — lacuna declarada.
  for (const al of inventario.alemDoLimite || []) {
    const caminho = typeof al?.caminho === 'string' ? al.caminho : null;
    if (!caminho || esperados.has(caminho) || !elegivel(caminho)) continue;
    esperados.add(caminho);
    classificar(caminho, ESTADO_ARQUIVO.NAO_ANALISADO, [MOTIVO_UNIVERSO.OPERATIONAL_LIMIT]);
  }
  // Revisão r4: caminho que o inventário não conseguiu ler. Se pode conter arquivo esperado (extensão elegível, ou
  // sem extensão — pasta de conteúdo desconhecido ou script), é lacuna com motivo READ_ERROR: nunca COMPLETE.
  for (const er of inventario.errosLeitura || []) {
    const caminho = typeof er?.caminho === 'string' ? er.caminho : null;
    if (!caminho || esperados.has(caminho)) continue;
    const ext = extensaoDe(caminho);
    if (ext !== '' && !esperadaExt.has(ext)) continue;
    esperados.add(caminho);
    classificar(caminho, ESTADO_ARQUIVO.NAO_ANALISADO, [MOTIVO_UNIVERSO.READ_ERROR]);
  }
  // Arquivo esperado que o ZUNVIO NÃO enviou por limite operacional próprio (acima do limite individual).
  for (const ex of inventario.exclusoes || []) {
    if (ex?.tipo !== TIPO_EXCLUSAO.LIMITE_TAMANHO_ARQUIVO || !elegivel(ex.caminho) || esperados.has(ex.caminho)) continue;
    esperados.add(ex.caminho);
    classificar(ex.caminho, ESTADO_ARQUIVO.NAO_ANALISADO, [MOTIVO_UNIVERSO.OPERATIONAL_LIMIT]);
  }

  arquivos.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const naoAnalisados = arquivos.filter((a) => a.state === ESTADO_ARQUIVO.NAO_ANALISADO);
  const parciais = arquivos.filter((a) => a.state === ESTADO_ARQUIVO.PARCIAL);
  const byReason = {};
  for (const a of arquivos) for (const m of a.reasons) byReason[m] = (byReason[m] || 0) + 1;
  const foraDoEsperado = [...scanned].filter((p) => !esperados.has(p)).length;

  const universe = {
    model: MODELO_UNIVERSO,
    coverage: {
      languages: modeladas,
      expectedExtensions: extensoes,
      includesNodeShebangWithoutExtension: true,
      source: 'RULEPACK_LANGUAGES'
    },
    boundary: fronteira(inventario),
    expected: esperados.size,
    analyzed: analisados,
    partiallyAnalyzed: parciais.length,
    notAnalyzed: naoAnalisados.length,
    scannedOutsideExpected: foraDoEsperado,
    byReason: Object.fromEntries(ordenar(Object.keys(byReason)).map((k) => [k, byReason[k]])),
    notAnalyzedDigest: digestDeLista(naoAnalisados.map((a) => `${a.path}\t${a.reasons.join(',')}`)),
    scannedDigest: digestDeLista([...scanned])
  };
  return { universe, arquivos };
}

/**
 * Universo esperado do Gitleaks. O Gitleaks 8.18.4 não emite nenhum sinal de cobertura por arquivo nem de bytes no
 * modo de diretório (sonda PL-02): o universo esperado é registrado, mas NADA é afirmado sobre o que foi analisado.
 * A completude continua UNKNOWN (sem modelo); a razão fica explícita.
 */
export function universoGitleaks(inventario) {
  if (!inventario || !Array.isArray(inventario.arquivosRelativos)) return null;
  const tamanhos = inventario.tamanhos || {};
  const bytes = inventario.arquivosRelativos.reduce((s, p) => s + (Number.isInteger(tamanhos[p]) ? tamanhos[p] : 0), 0);
  return {
    model: MODELO_UNIVERSO,
    coverage: { languages: [], expectedExtensions: [], includesNodeShebangWithoutExtension: false, source: 'ALL_FILES_SENT' },
    boundary: fronteira(inventario),
    expected: inventario.arquivosRelativos.length,
    expectedBytes: bytes,
    analyzed: null,
    partiallyAnalyzed: null,
    notAnalyzed: null,
    scannedOutsideExpected: null,
    byReason: {},
    evidence: MOTIVO_UNIVERSO.SCANNER_REPORTS_NO_COVERAGE_SIGNAL
  };
}

const HEX64 = /^[0-9a-f]{64}$/;
const naoNegativo = (n) => Number.isInteger(n) && n >= 0;

/**
 * Coerência de um universo SELADO (validador do Evidence Pack 0.5.0 e verificador de recibo).
 * @param {object} universe
 * @param {{ status: string, criterion: string, affectedFileCount: number }} completude
 * @returns {string[]} problemas (vazio = coerente)
 */
export function problemasDoUniverso(universe, completude) {
  const u = universe;
  if (!u || typeof u !== 'object' || Array.isArray(u)) return ['universe ausente ou não é objeto'];
  const p = [];
  if (typeof u.model !== 'string' || !u.model) p.push('universe.model ausente');
  if (!naoNegativo(u.expected)) p.push('universe.expected deve ser inteiro ≥ 0');
  if (u.expectedBytes !== undefined && !naoNegativo(u.expectedBytes)) p.push('universe.expectedBytes deve ser inteiro ≥ 0');
  if (!u.boundary || !naoNegativo(u.boundary.filesSent)) p.push('universe.boundary.filesSent deve ser inteiro ≥ 0');
  // Revisão r7: cobertura e fronteira com a mesma coerência do adaptador do SaaS.
  const cov = u.coverage;
  if (!cov || typeof cov !== 'object'
    || !Array.isArray(cov.languages) || cov.languages.some((l) => !(l in EXTENSOES_POR_LINGUAGEM))
    || !Array.isArray(cov.expectedExtensions) || cov.expectedExtensions.some((e) => typeof e !== 'string' || !/^\.[a-z0-9]{1,8}$/.test(e))
    || typeof cov.includesNodeShebangWithoutExtension !== 'boolean'
    || !['RULEPACK_LANGUAGES', 'ALL_FILES_SENT'].includes(cov.source)) {
    p.push('universe.coverage fora do modelo');
  }
  if (!u.boundary || ['policyExclusions', 'operationalLimitExclusions', 'readErrors'].some((k) => !naoNegativo(u.boundary[k]))) {
    p.push('universe.boundary com contagem fora do modelo');
  }
  // Revisões r4/r5: tipos de exclusão por política em conjunto fechado, com ou sem sinal de cobertura.
  const porTipo = u.boundary?.policyExclusionsByKind;
  if (!porTipo || typeof porTipo !== 'object' || Object.entries(porTipo).some(([k, n]) => !TIPOS_DE_EXCLUSAO_POLITICA.has(k) || !naoNegativo(n) || n === 0)) {
    p.push('universe.boundary.policyExclusionsByKind com tipo ou contagem fora do modelo');
  }
  const semSinal = u.evidence === MOTIVO_UNIVERSO.SCANNER_REPORTS_NO_COVERAGE_SIGNAL;
  // Revisão r6: evidence só existe com o único valor do modelo.
  if (u.evidence !== undefined && !semSinal) p.push('universe.evidence fora do modelo');
  if (semSinal) {
    // Sem sinal do scanner: nada pode ser afirmado sobre o analisado, e a completude não pode ser COMPLETE.
    if (u.analyzed !== null || u.notAnalyzed !== null || u.partiallyAnalyzed !== null || u.scannedOutsideExpected !== null) p.push('universo sem sinal de cobertura não pode declarar contagens de análise');
    // Revisão r1 (M3): sem sinal, nenhum motivo de não análise pode ser afirmado.
    if (!u.byReason || typeof u.byReason !== 'object' || Object.keys(u.byReason).length > 0) p.push('universo sem sinal de cobertura não pode declarar motivos');
    // Revisão r2: sem sinal não há lista de analisados nem de não analisados para selar.
    if (u.notAnalyzedDigest !== undefined || u.scannedDigest !== undefined) p.push('universo sem sinal de cobertura não pode declarar digests de análise');
    if (completude?.status === 'COMPLETE') p.push('universo sem sinal de cobertura não pode sustentar COMPLETE');
    return p;
  }
  for (const campo of ['analyzed', 'partiallyAnalyzed', 'notAnalyzed', 'scannedOutsideExpected']) {
    if (!naoNegativo(u[campo])) p.push(`universe.${campo} deve ser inteiro ≥ 0`);
  }
  if (p.length) return p;
  if (u.analyzed + u.partiallyAnalyzed + u.notAnalyzed !== u.expected) {
    p.push(`universe: expected (${u.expected}) ≠ analyzed + partiallyAnalyzed + notAnalyzed (${u.analyzed + u.partiallyAnalyzed + u.notAnalyzed})`);
  }
  const lacunas = u.partiallyAnalyzed + u.notAnalyzed;
  const motivos = u.byReason && typeof u.byReason === 'object' ? Object.values(u.byReason) : null;
  // Revisão r4: motivos em conjunto fechado, como no adaptador do SaaS.
  if (motivos && Object.keys(u.byReason).some((k) => !MOTIVOS_DO_UNIVERSO.has(k))) p.push('universe.byReason com motivo fora do modelo');
  if (!motivos || motivos.some((n) => !naoNegativo(n) || n === 0)) p.push('universe.byReason deve ter contagens inteiras > 0');
  else if (lacunas > 0 && motivos.length === 0) p.push('universe com lacunas sem motivo');
  else if (lacunas === 0 && motivos.length > 0) p.push('universe sem lacunas não pode ter motivos');
  if (!HEX64.test(u.notAnalyzedDigest || '') || !HEX64.test(u.scannedDigest || '')) p.push('universe: digests devem ser SHA-256');
  if (completude) {
    // Revisão r6: universo com sinal só existe sob os critérios que o motor produz com ele; sob "sem modelo" ou
    // "sem sinais" a lacuna medida sumiria da superfície.
    if (!CRITERIOS_COM_UNIVERSO_MEDIDO.has(completude.criterion)) p.push(`universo medido sob critério incompatível (${completude.criterion})`);
    if (completude.status === 'COMPLETE' && lacunas > 0) p.push('completude COMPLETE com arquivos esperados não analisados por inteiro');
    if (completude.criterion === 'SUCCESS_WITH_UNANALYZED_EXPECTED_FILES' && lacunas === 0) p.push('critério de arquivos não analisados sem nenhuma lacuna no universo');
    if (completude.criterion === 'SUCCESS_EXPECTED_UNIVERSE_ANALYZED' && lacunas > 0) p.push('critério de universo analisado com lacunas');
    if (Number.isInteger(completude.affectedFileCount) && completude.affectedFileCount < lacunas) p.push('affectedFileCount menor que as lacunas do universo');
  }
  return p;
}
