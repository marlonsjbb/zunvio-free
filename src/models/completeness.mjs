// Fatia 1 (ZUNVIO v1.1) — Scanner Completeness.
//
// Modelo mínimo de COMPLETUDE por scanner: responde "a análise deste scanner foi
// comprovadamente completa?". Conceito distinto de `completion` (sensor-identity.mjs),
// que só diz se o sensor terminou com ou sem achados.
//
// Origem (Product Learnings LC-01/LC-03, EXP-LC-03 de 25/09/2026): o Semgrep registra
// em `errors` (nível warn) timeout por regra/arquivo e parsing parcial; após o limite
// de timeouts por arquivo, o arquivo é pulado. O ZUNVIO descartava esse sinal e
// apresentava a execução como sucesso sem limitação. Este módulo só OBSERVA e
// CLASSIFICA: não altera timeout, regras, paralelismo nem o conjunto de arquivos.
//
// Critérios determinísticos (documentados em docs/architecture/f1-scanner-completeness.md):
//   DEGRADED — o scanner não entregou resultado utilizável: status ≠ SUCCESS
//              (ERROR, TIMEOUT, UNAVAILABLE) ou saída não interpretável.
//   UNKNOWN  — sucesso, mas os sinais necessários para provar completude não vieram
//              (ex.: JSON sem `errors` ou sem `paths.scanned`), ou o scanner ainda não
//              tem modelo de completude (NOT_EVALUATED).
//   PARTIAL  — sucesso, sinais presentes e pelo menos um erro de arquivo/regra
//              (timeout, parsing parcial, arquivo pulado, erro de arquivo ou de regra).
//   COMPLETE — sucesso, `errors` presente e vazio e `paths.scanned` presente.
// Nunca COMPLETE só porque o processo terminou com exit code 0.
//
// PL-02 (universo esperado): com o inventário do ZUNVIO disponível, COMPLETE exige também que TODO arquivo
// esperado pela cobertura declarada tenha sido analisado (models/expected-universe.mjs). Sem erro declarado, mas
// com arquivo esperado fora da análise, a completude é PARTIAL (SUCCESS_WITH_UNANALYZED_EXPECTED_FILES).

import { avaliarUniversoSemgrep, digestDeLista, TETO_ARQUIVOS_AFETADOS } from './expected-universe.mjs';

export const COMPLETENESS_STATUS = Object.freeze({
  COMPLETE: 'COMPLETE',
  PARTIAL: 'PARTIAL',
  DEGRADED: 'DEGRADED',
  UNKNOWN: 'UNKNOWN'
});

export const COMPLETENESS_REASON = Object.freeze({
  TIMEOUT: 'TIMEOUT',
  FILE_SKIPPED: 'FILE_SKIPPED',
  PARTIAL_PARSING: 'PARTIAL_PARSING',
  PARSE_ERROR: 'PARSE_ERROR',
  FILE_ERROR: 'FILE_ERROR',
  RULE_ERROR: 'RULE_ERROR',
  SCANNER_FAILURE: 'SCANNER_FAILURE',
  SIGNALS_MISSING: 'SIGNALS_MISSING',
  NOT_EVALUATED: 'NOT_EVALUATED',
  // PL-02 (universo esperado)
  UNSUPPORTED_EXTENSION: 'UNSUPPORTED_EXTENSION',
  SIZE_LIMIT_EXCEEDED: 'SIZE_LIMIT_EXCEEDED',
  OPERATIONAL_LIMIT: 'OPERATIONAL_LIMIT',
  // PL-01: o projeto passa do limite operacional e nem a contagem do universo esperado fechou.
  LIMIT_EXCEEDED: 'LIMIT_EXCEEDED',
  UNKNOWN_CAUSE: 'UNKNOWN_CAUSE',
  SCANNER_REPORTS_NO_COVERAGE_SIGNAL: 'SCANNER_REPORTS_NO_COVERAGE_SIGNAL',
  // LC-06 (histórico Git): por que a cobertura do histórico não foi demonstrada.
  SHALLOW_HISTORY: 'SHALLOW_HISTORY',
  HISTORY_NOT_DETERMINED: 'HISTORY_NOT_DETERMINED',
  HISTORY_COVERAGE_MISMATCH: 'HISTORY_COVERAGE_MISMATCH'
});

export const COMPLETENESS_CRITERION = Object.freeze({
  SCANNER_FAILED: 'SCANNER_STATUS_NOT_SUCCESS',
  OUTPUT_UNREADABLE: 'SCANNER_OUTPUT_UNREADABLE',
  SIGNALS_MISSING: 'SUCCESS_WITHOUT_COMPLETENESS_SIGNALS',
  NOT_EVALUATED: 'SCANNER_WITHOUT_COMPLETENESS_MODEL',
  ERRORS_PRESENT: 'SUCCESS_WITH_FILE_OR_RULE_ERRORS',
  NO_ERRORS: 'SUCCESS_ERRORS_EMPTY_AND_PATHS_PRESENT',
  // PL-02: com o universo esperado disponível
  UNIVERSE_ANALYZED: 'SUCCESS_EXPECTED_UNIVERSE_ANALYZED',
  UNIVERSE_GAPS: 'SUCCESS_WITH_UNANALYZED_EXPECTED_FILES',
  // LC-06: histórico Git esperado (calculado pelo Git) = histórico varrido (declarado pelo Gitleaks), sem shallow.
  HISTORY_SCANNED: 'SUCCESS_EXPECTED_HISTORY_SCANNED'
});

// Limites em vigor: o ZUNVIO NÃO passa --timeout/--timeout-threshold/--max-target-bytes
// ao Semgrep (src/scanners/semgrep.mjs), então valem os padrões documentados pelo
// próprio binário (`semgrep scan --help`, versão 1.176.0 fixada em engine-bootstrap.mjs):
// 5 s por regra por arquivo; 3 timeouts por arquivo antes de pulá-lo; 1.000.000 bytes.
export const SEMGREP_EFFECTIVE_LIMITS = Object.freeze({
  perRuleTimeoutSeconds: 5,
  timeoutsBeforeFileSkipped: 3,
  maxTargetBytes: 1000000,
  source: 'SEMGREP_DEFAULTS_NOT_OVERRIDDEN_BY_ZUNVIO'
});

const ORDEM_GRAVIDADE = ['COMPLETE', 'UNKNOWN', 'PARTIAL', 'DEGRADED'];

function tipoErroSemgrep(erro) {
  const bruto = Array.isArray(erro?.type) ? erro.type[0] : erro?.type;
  return typeof bruto === 'string' && bruto.length > 0 ? bruto : 'Unknown';
}

/**
 * Motivo canônico a partir do tipo de erro do Semgrep. Tipos desconhecidos com
 * arquivo viram FILE_ERROR; sem arquivo, RULE_ERROR. Nunca some com um erro.
 */
export function motivoDoErroSemgrep(erro) {
  const tipo = tipoErroSemgrep(erro).toLowerCase();
  if (tipo === 'timeout') return COMPLETENESS_REASON.TIMEOUT;
  if (tipo === 'partialparsing') return COMPLETENESS_REASON.PARTIAL_PARSING;
  const temArquivo = typeof erro?.path === 'string' && erro.path.length > 0;
  // "Syntax error"/"Lexical error": o Semgrep não conseguiu ler o arquivo e o
  // descarta inteiro (confirmado no caso controlado da Fatia 1 com o binário real).
  if (temArquivo && /^(other )?(syntax|lexical) error$/.test(tipo)) return COMPLETENESS_REASON.PARSE_ERROR;
  if (/rule|config|schema|pattern/.test(tipo) && !temArquivo) return COMPLETENESS_REASON.RULE_ERROR;
  return temArquivo ? COMPLETENESS_REASON.FILE_ERROR : COMPLETENESS_REASON.RULE_ERROR;
}

function ordenarUnicos(lista) {
  return [...new Set(lista)].sort();
}

function resultadoDegradado(criterion, reasons, errorsByType = {}) {
  return Object.freeze({
    status: COMPLETENESS_STATUS.DEGRADED,
    criterion,
    reasons: ordenarUnicos(reasons),
    affectedFiles: [],
    affectedFileCount: 0,
    ruleErrors: [],
    errorsByType,
    filesScanned: null,
    effectiveLimits: SEMGREP_EFFECTIVE_LIMITS,
    source: 'semgrep-json'
  });
}

/**
 * Completude do Semgrep a partir do resultado bruto do processo.
 * @param {object} params
 * @param {'SUCCESS'|'ERROR'|'TIMEOUT'|'UNAVAILABLE'} params.status - Status já decidido pelo scanner.
 * @param {object|null} params.json - JSON interpretado da saída (null se não interpretável).
 * @param {(caminhoBruto: string) => string} params.caminhoRelativo - Converte caminho do Semgrep em caminho relativo ao alvo.
 * @param {(ruleIdBruto: string) => string} params.normalizarRegra - Normaliza o check_id/rule_id.
 */
export function avaliarCompletudeSemgrep({ status, json, caminhoRelativo, normalizarRegra, inventario = null, linguagens = null }) {
  if (status !== 'SUCCESS') {
    return resultadoDegradado(COMPLETENESS_CRITERION.SCANNER_FAILED, [COMPLETENESS_REASON.SCANNER_FAILURE]);
  }
  if (!json || typeof json !== 'object') {
    return resultadoDegradado(COMPLETENESS_CRITERION.OUTPUT_UNREADABLE, [COMPLETENESS_REASON.SCANNER_FAILURE]);
  }
  const temErros = Array.isArray(json.errors);
  const temScanned = Array.isArray(json.paths?.scanned);
  if (!temErros || !temScanned) {
    return Object.freeze({
      status: COMPLETENESS_STATUS.UNKNOWN,
      criterion: COMPLETENESS_CRITERION.SIGNALS_MISSING,
      reasons: [COMPLETENESS_REASON.SIGNALS_MISSING],
      affectedFiles: [],
      affectedFileCount: 0,
      ruleErrors: [],
      errorsByType: {},
      filesScanned: temScanned ? json.paths.scanned.length : null,
      effectiveLimits: SEMGREP_EFFECTIVE_LIMITS,
      source: 'semgrep-json'
    });
  }

  const porArquivo = new Map();
  const ruleErrors = [];
  const errorsByType = {};
  for (const erro of json.errors) {
    const tipo = tipoErroSemgrep(erro);
    errorsByType[tipo] = (errorsByType[tipo] || 0) + 1;
    const motivo = motivoDoErroSemgrep(erro);
    const regra = typeof erro?.rule_id === 'string' && erro.rule_id ? normalizarRegra(erro.rule_id) : null;
    if (typeof erro?.path === 'string' && erro.path.length > 0) {
      const caminho = caminhoRelativo(erro.path);
      const atual = porArquivo.get(caminho) || { path: caminho, reasons: [], rules: [], counts: {} };
      atual.reasons.push(motivo);
      if (regra) atual.rules.push(regra);
      atual.counts[motivo] = (atual.counts[motivo] || 0) + 1;
      porArquivo.set(caminho, atual);
    } else {
      ruleErrors.push({ reason: motivo, rule: regra, type: tipo });
    }
  }

  const affectedFiles = [...porArquivo.values()]
    .map((a) => {
      const reasons = [...a.reasons];
      // Arquivo pulado: o Semgrep documenta que, ao atingir o limite de timeouts
      // por arquivo, o arquivo é pulado. Só é afirmado quando o limite foi atingido.
      if ((a.counts[COMPLETENESS_REASON.TIMEOUT] || 0) >= SEMGREP_EFFECTIVE_LIMITS.timeoutsBeforeFileSkipped) {
        reasons.push(COMPLETENESS_REASON.FILE_SKIPPED);
      }
      return Object.freeze({
        path: a.path,
        reasons: ordenarUnicos(reasons),
        rules: ordenarUnicos(a.rules),
        timeouts: a.counts[COMPLETENESS_REASON.TIMEOUT] || 0
      });
    })
    .sort((x, y) => x.path.localeCompare(y.path));

  // PL-02: universo esperado × análise efetiva (só com o inventário do ZUNVIO e as linguagens do rulepack).
  const universo = inventario && linguagens
    ? avaliarUniversoSemgrep({ inventario, json, caminhoRelativo, linguagens, limites: SEMGREP_EFFECTIVE_LIMITS, motivoDoErro: motivoDoErroSemgrep })
    : null;
  if (universo) {
    const porCaminho = new Map(affectedFiles.map((a) => [a.path, { ...a, reasons: [...a.reasons], rules: [...a.rules] }]));
    for (const u of universo.arquivos) {
      const atual = porCaminho.get(u.path) || { path: u.path, reasons: [], rules: [], timeouts: 0 };
      atual.reasons = ordenarUnicos([...atual.reasons, ...u.reasons]);
      atual.timeouts = Math.max(atual.timeouts || 0, u.timeouts || 0);
      porCaminho.set(u.path, atual);
    }
    const todos = [...porCaminho.values()]
      .map((a) => Object.freeze({ path: a.path, reasons: ordenarUnicos(a.reasons), rules: ordenarUnicos(a.rules), timeouts: a.timeouts || 0 }))
      .sort((x, y) => x.path.localeCompare(y.path));
    const lacunas = universo.universe.partiallyAnalyzed + universo.universe.notAnalyzed;
    const comErros = json.errors.length > 0;
    const status = comErros || lacunas > 0 ? COMPLETENESS_STATUS.PARTIAL : COMPLETENESS_STATUS.COMPLETE;
    const criterion = comErros
      ? COMPLETENESS_CRITERION.ERRORS_PRESENT
      : lacunas > 0 ? COMPLETENESS_CRITERION.UNIVERSE_GAPS : COMPLETENESS_CRITERION.UNIVERSE_ANALYZED;
    return Object.freeze({
      status,
      criterion,
      reasons: ordenarUnicos([...todos.flatMap((a) => a.reasons), ...ruleErrors.map((r) => r.reason)]),
      affectedFiles: todos.slice(0, TETO_ARQUIVOS_AFETADOS),
      affectedFileCount: todos.length,
      affectedFilesTruncated: todos.length > TETO_ARQUIVOS_AFETADOS,
      affectedFilesDigest: digestDeLista(todos.map((a) => `${a.path}\t${a.reasons.join(',')}`)),
      ruleErrors: ruleErrors.sort((a, b) => `${a.reason}${a.rule}`.localeCompare(`${b.reason}${b.rule}`)),
      errorsByType,
      filesScanned: json.paths.scanned.length,
      effectiveLimits: SEMGREP_EFFECTIVE_LIMITS,
      source: 'semgrep-json+zunvio-inventory',
      universe: Object.freeze(universo.universe)
    });
  }

  const reasons = ordenarUnicos([
    ...affectedFiles.flatMap((a) => a.reasons),
    ...ruleErrors.map((r) => r.reason)
  ]);
  const temProblema = json.errors.length > 0;
  // PL-02 (revisão r1, B2): com o inventário do ZUNVIO disponível mas sem universo calculável (cobertura declarada
  // ilegível ou fora do modelo), a ausência de erro NÃO comprova nada: UNKNOWN, nunca COMPLETE pelo autorrelato.
  // PL-01: universo indeterminado por limite operacional ⇒ o motivo é LIMIT_EXCEEDED, explícito.
  const universoIndeterminado = inventario?.limiteOperacional?.universoDeterminado === false;
  if (inventario && !temProblema) {
    return Object.freeze({
      status: COMPLETENESS_STATUS.UNKNOWN,
      criterion: COMPLETENESS_CRITERION.SIGNALS_MISSING,
      reasons: [universoIndeterminado ? COMPLETENESS_REASON.LIMIT_EXCEEDED : COMPLETENESS_REASON.SIGNALS_MISSING],
      affectedFiles: [],
      affectedFileCount: 0,
      ruleErrors: [],
      errorsByType,
      filesScanned: json.paths.scanned.length,
      effectiveLimits: SEMGREP_EFFECTIVE_LIMITS,
      source: 'semgrep-json'
    });
  }
  if (universoIndeterminado && !reasons.includes(COMPLETENESS_REASON.LIMIT_EXCEEDED)) reasons.push(COMPLETENESS_REASON.LIMIT_EXCEEDED);
  return Object.freeze({
    status: temProblema ? COMPLETENESS_STATUS.PARTIAL : COMPLETENESS_STATUS.COMPLETE,
    criterion: temProblema ? COMPLETENESS_CRITERION.ERRORS_PRESENT : COMPLETENESS_CRITERION.NO_ERRORS,
    reasons,
    affectedFiles,
    affectedFileCount: affectedFiles.length,
    ruleErrors: ruleErrors.sort((a, b) => `${a.reason}${a.rule}`.localeCompare(`${b.reason}${b.rule}`)),
    errorsByType,
    filesScanned: json.paths.scanned.length,
    effectiveLimits: SEMGREP_EFFECTIVE_LIMITS,
    source: 'semgrep-json'
  });
}

/**
 * Completude de um scanner que ainda não tem modelo (ex.: Gitleaks). PL-02: quando o universo esperado é conhecido
 * mas o scanner não emite sinal de cobertura, o universo é registrado com a razão explícita — e a completude
 * continua UNKNOWN (nada é inventado).
 */
export function completudeNaoAvaliada(scannerStatus, universo = null) {
  if (scannerStatus && scannerStatus !== 'SUCCESS') {
    return resultadoDegradadoGenerico(COMPLETENESS_CRITERION.SCANNER_FAILED, [COMPLETENESS_REASON.SCANNER_FAILURE]);
  }
  return Object.freeze({
    status: COMPLETENESS_STATUS.UNKNOWN,
    criterion: COMPLETENESS_CRITERION.NOT_EVALUATED,
    reasons: universo
      ? [COMPLETENESS_REASON.NOT_EVALUATED, COMPLETENESS_REASON.SCANNER_REPORTS_NO_COVERAGE_SIGNAL]
      : [COMPLETENESS_REASON.NOT_EVALUATED],
    ...(universo ? { universe: Object.freeze(universo) } : {}),
    affectedFiles: [],
    affectedFileCount: 0,
    ruleErrors: [],
    errorsByType: {},
    filesScanned: null,
    effectiveLimits: null,
    source: 'none'
  });
}

function resultadoDegradadoGenerico(criterion, reasons) {
  return Object.freeze({
    status: COMPLETENESS_STATUS.DEGRADED,
    criterion,
    reasons,
    affectedFiles: [],
    affectedFileCount: 0,
    ruleErrors: [],
    errorsByType: {},
    filesScanned: null,
    effectiveLimits: null,
    source: 'scanner-status'
  });
}

/** Estado que cada critério determina (tabela do modelo; qualquer outro par é incoerente). */
export const ESTADO_DO_CRITERIO = Object.freeze({
  [COMPLETENESS_CRITERION.SCANNER_FAILED]: COMPLETENESS_STATUS.DEGRADED,
  [COMPLETENESS_CRITERION.OUTPUT_UNREADABLE]: COMPLETENESS_STATUS.DEGRADED,
  [COMPLETENESS_CRITERION.SIGNALS_MISSING]: COMPLETENESS_STATUS.UNKNOWN,
  [COMPLETENESS_CRITERION.NOT_EVALUATED]: COMPLETENESS_STATUS.UNKNOWN,
  [COMPLETENESS_CRITERION.ERRORS_PRESENT]: COMPLETENESS_STATUS.PARTIAL,
  [COMPLETENESS_CRITERION.NO_ERRORS]: COMPLETENESS_STATUS.COMPLETE,
  [COMPLETENESS_CRITERION.UNIVERSE_ANALYZED]: COMPLETENESS_STATUS.COMPLETE,
  [COMPLETENESS_CRITERION.UNIVERSE_GAPS]: COMPLETENESS_STATUS.PARTIAL,
  [COMPLETENESS_CRITERION.HISTORY_SCANNED]: COMPLETENESS_STATUS.COMPLETE
});

/**
 * Problemas de coerência de uma completude declarada (vazio = coerente). Revisão
 * independente da Fatia 1 (r1, achado 1): o critério não pode ser um rótulo livre,
 * porque "sem modelo" desligaria a proteção de um scanner PARTIAL. Isto garante
 * COERÊNCIA, não autenticidade: quem recalcula o canonicalHash pode declarar outro
 * estado coerente; autenticidade vem da notarização/ingestão, não do validador.
 */
export function problemasDeCoerencia(scanner, completude) {
  if (!completude || typeof completude !== 'object') return [`completude do scanner ${scanner} ausente`];
  const esperado = ESTADO_DO_CRITERIO[completude.criterion];
  if (!esperado) return [`critério de completude do scanner ${scanner} fora do modelo: ${JSON.stringify(completude.criterion)}`];
  if (esperado !== completude.status) return [`critério ${completude.criterion} do scanner ${scanner} exige estado ${esperado}, declarado ${completude.status}`];
  return [];
}

/**
 * O scanner tem modelo de completude? Só o par exato UNKNOWN + NOT_EVALUATED significa
 * "sem modelo"; qualquer outra combinação — inclusive incoerente — conta como observada,
 * para que a proteção da Fatia 1 nunca seja desligada por um rótulo.
 */
export function temModeloDeCompletude(completude) {
  return Boolean(completude)
    && !(completude.criterion === COMPLETENESS_CRITERION.NOT_EVALUATED && completude.status === COMPLETENESS_STATUS.UNKNOWN);
}

/** Frase do risco residual para análise incompleta (gerada pelo Evidence Pack; conferida pelo validador). */
export const MARCA_RISCO_INCOMPLETO = 'análise incompleta';
export const MARCA_RISCO_INTEGRAL = '100% de integridade';

/**
 * Regra fundamental (Fatia 1): ausência de finding não é evidência de ausência numa
 * região cuja análise não foi comprovadamente completa. Verdadeiro quando o scanner
 * tem modelo de completude e NÃO provou completude.
 */
export function ausenciaNaoComprova(completude) {
  return temModeloDeCompletude(completude) && completude.status !== COMPLETENESS_STATUS.COMPLETE;
}

/** Estado agregado da análise: o pior entre os scanners (DEGRADED > PARTIAL > UNKNOWN > COMPLETE). */
export function agregarCompletude(porScanner) {
  const estados = Object.values(porScanner).map((c) => c?.status || COMPLETENESS_STATUS.UNKNOWN);
  const pior = estados.reduce((acc, e) => (ORDEM_GRAVIDADE.indexOf(e) > ORDEM_GRAVIDADE.indexOf(acc) ? e : acc), COMPLETENESS_STATUS.COMPLETE);
  return Object.freeze({
    status: estados.length ? pior : COMPLETENESS_STATUS.UNKNOWN,
    byScanner: Object.fromEntries(Object.entries(porScanner).map(([id, c]) => [id, c?.status || COMPLETENESS_STATUS.UNKNOWN]))
  });
}

const DESCRICAO_MOTIVO = Object.freeze({
  TIMEOUT: 'a análise de uma ou mais regras demorou mais que o limite do scanner',
  FILE_SKIPPED: 'o scanner pulou o arquivo depois de atingir o limite de timeouts por arquivo',
  PARTIAL_PARSING: 'o scanner só conseguiu ler parte do código',
  PARSE_ERROR: 'o scanner não conseguiu ler o código do arquivo, que ficou fora da análise',
  FILE_ERROR: 'o scanner registrou erro ao analisar o arquivo',
  RULE_ERROR: 'o scanner registrou erro ao aplicar uma regra',
  SCANNER_FAILURE: 'o scanner não concluiu a execução',
  SIGNALS_MISSING: 'o scanner não informou os sinais necessários para comprovar a completude',
  UNSUPPORTED_EXTENSION: 'o scanner não reconhece a extensão do arquivo e não o analisou (sem declarar)',
  SIZE_LIMIT_EXCEEDED: 'o arquivo passa do limite de tamanho do scanner e não foi analisado',
  OPERATIONAL_LIMIT: 'o arquivo passa do limite de tamanho do próprio ZUNVIO e não foi enviado ao scanner',
  UNKNOWN_CAUSE: 'o arquivo esperado não foi analisado e o motivo não pôde ser demonstrado',
  READ_ERROR: 'o ZUNVIO não conseguiu ler o caminho, que pode conter arquivo esperado',
  LIMIT_EXCEEDED: 'o projeto passa do limite operacional do ZUNVIO e não foi possível determinar todo o universo esperado',
  NOT_EVALUATED: 'o scanner não tem modelo de completude',
  SCANNER_REPORTS_NO_COVERAGE_SIGNAL: 'o scanner não informa quais arquivos analisou',
  SHALLOW_HISTORY: 'o repositório é um clone raso (shallow): parte do histórico Git não está no alvo',
  HISTORY_NOT_DETERMINED: 'o histórico Git esperado não pôde ser determinado (alvo sem repositório Git, repositório sem commits ou subdiretório de um repositório)',
  HISTORY_COVERAGE_MISMATCH: 'os commits que o Gitleaks declara ter varrido não batem com os commits esperados pelo Git'
});

// LC-06: o mesmo motivo pode significar coisas diferentes por sensor; aqui, o sentido para o scanner de segredos.
const DESCRICAO_MOTIVO_POR_SCANNER = Object.freeze({
  'zunvio-segredos': Object.freeze({
    UNSUPPORTED_EXTENSION: 'conteúdo compactado (zip, docx, xlsx, gzip, pdf e contêineres equivalentes) não é inspecionável lendo os bytes do arquivo',
    OPERATIONAL_LIMIT: 'o arquivo passa do limite operacional do inventário do ZUNVIO e não foi lido'
  })
});
const descricaoMotivo = (scanner, m) => DESCRICAO_MOTIVO_POR_SCANNER[scanner]?.[m] ?? DESCRICAO_MOTIVO[m];

/**
 * Limitações estruturadas derivadas da completude. Só para limitação comprovada
 * (PARTIAL, DEGRADED) ou para scanner com modelo que não informou os sinais
 * (UNKNOWN por SIGNALS_MISSING). Scanner sem modelo (NOT_EVALUATED) não gera
 * limitação: nada foi observado. Textos humanos nunca embutem caminho de arquivo
 * nem mensagem externa (caminhos ficam só em `where.files`).
 */
export function limitacoesDaCompletude(porScanner) {
  const limitacoes = [];
  for (const [scanner, c] of Object.entries(porScanner)) {
    if (!c || c.status === COMPLETENESS_STATUS.COMPLETE) continue;
    if (!temModeloDeCompletude(c)) {
      // PL-04 (decisão do fundador): o agregado UNKNOWN nunca fica silencioso. Sensor sem sinal de cobertura com o
      // universo enviado conhecido gera limitação explícita — sem afirmar nada sobre o que foi analisado.
      if (c.universe && Number.isInteger(c.universe.expected)) {
        limitacoes.push(Object.freeze({
          code: 'COMPLETENESS_UNKNOWN',
          scanner,
          whatWasNotVerified: `Não foi possível comprovar quais dos ${c.universe.expected} arquivo(s) enviados o scanner ${scanner} analisou.`,
          where: { fileCount: 0, files: [], rules: [] },
          why: { reasons: c.reasons, detail: c.reasons.map((m) => descricaoMotivo(scanner, m)).filter(Boolean).join('; ') },
          impact: 'Nenhum achado reportado por este scanner não comprova ausência de problemas: a cobertura dele não pôde ser demonstrada.',
          source: c.source ?? 'none'
        }));
      }
      continue;
    }
    if (c.history && c.status !== COMPLETENESS_STATUS.DEGRADED) {
      // LC-06: cobertura do histórico Git não demonstrada — dito como histórico, não como arquivos.
      const h = c.history;
      limitacoes.push(Object.freeze({
        code: 'COMPLETENESS_UNKNOWN',
        scanner,
        whatWasNotVerified: `Não foi possível comprovar que todo o histórico Git esperado foi varrido pelo scanner ${scanner}${Number.isInteger(h.commitsExpected) && Number.isInteger(h.commitsScanned) ? ` (${h.commitsScanned} de ${h.commitsExpected} commit(s) esperados)` : ''}.`,
        where: { fileCount: 0, files: [], rules: [] },
        why: { reasons: c.reasons, detail: c.reasons.map((m) => descricaoMotivo(scanner, m)).filter(Boolean).join('; ') },
        impact: 'Nenhum achado no histórico não comprova ausência de segredos nele: a cobertura do histórico não foi demonstrada.',
        source: c.source
      }));
      continue;
    }
    const n = c.affectedFileCount;
    const code = c.status === COMPLETENESS_STATUS.DEGRADED
      ? 'SCANNER_DEGRADED'
      : c.status === COMPLETENESS_STATUS.PARTIAL ? 'ANALYSIS_PARTIAL' : 'COMPLETENESS_UNKNOWN';
    const u = c.universe;
    const oQue = c.status === COMPLETENESS_STATUS.DEGRADED
      ? `O scanner ${scanner} não entregou um resultado utilizável; nada do que ele cobre foi verificado nesta análise.`
      : c.status === COMPLETENESS_STATUS.PARTIAL
        ? (u && Number.isInteger(u.expected) && Number.isInteger(u.notAnalyzed) && u.notAnalyzed + u.partiallyAnalyzed > 0
            // PL-02: a lacuna é medida contra o universo esperado pelo ZUNVIO, não só contra o que o scanner declarou.
            ? `Dos ${u.expected} arquivo(s) esperados pelo scanner ${scanner}, ${[
              u.notAnalyzed > 0 ? `${u.notAnalyzed} ${u.notAnalyzed === 1 ? 'não foi analisado' : 'não foram analisados'}` : null,
              u.partiallyAnalyzed > 0 ? `${u.partiallyAnalyzed} ${u.partiallyAnalyzed === 1 ? 'foi analisado' : 'foram analisados'} só em parte` : null
            ].filter(Boolean).join(' e ')}.`
            : n > 0
              ? `${n} arquivo(s) não foram verificados por completo pelo scanner ${scanner}.`
              : `Parte das regras do scanner ${scanner} não foi aplicada por completo.`)
        : `Não foi possível comprovar que o scanner ${scanner} verificou todo o código.`;
    limitacoes.push(Object.freeze({
      code,
      scanner,
      whatWasNotVerified: oQue,
      // PL-02 (escala): a lista de arquivos segue o teto do pack; fileCount é o total.
      where: { fileCount: n, files: c.affectedFiles.slice(0, TETO_ARQUIVOS_AFETADOS).map((a) => a.path), rules: ordenarUnicos(c.affectedFiles.flatMap((a) => a.rules).concat(c.ruleErrors.map((r) => r.rule).filter(Boolean))) },
      why: { reasons: c.reasons, detail: c.reasons.map((m) => descricaoMotivo(scanner, m)).filter(Boolean).join('; ') },
      impact: 'Os achados encontrados continuam válidos. Onde a análise não foi completa, a ausência de achados não é evidência de ausência de problemas.',
      source: c.source
    }));
  }
  return limitacoes;
}

// ---------------------------------------------------------------------------------------------------------------
// LC-06 — cobertura verificável de segredos.

export const MODELO_HISTORICO = 'lc06-1.0';

/**
 * Completude do sensor de segredos no WORKING TREE (scanner próprio) a partir do universo que ele mediu.
 * COMPLETE só com o universo elegível inteiro analisado; qualquer lacuna ⇒ PARTIAL; universo não determinável
 * (limite operacional sem contagem fechada) ⇒ UNKNOWN com LIMIT_EXCEEDED. Falha ⇒ DEGRADED.
 * @param {{ status: string, cobertura: { universe: object|null, lacunas: object[] } | null }} resultado
 */
export function completudeDaArvoreSegredos(resultado, teto = 200, digest) {
  if (!resultado || resultado.status !== 'SUCCESS' || !resultado.cobertura) {
    return resultadoDegradadoGenerico(COMPLETENESS_CRITERION.SCANNER_FAILED, [COMPLETENESS_REASON.SCANNER_FAILURE]);
  }
  const { universe, lacunas } = resultado.cobertura;
  const base = { ruleErrors: [], errorsByType: {}, effectiveLimits: null, source: 'zunvio-inventory' };
  if (!universe) {
    return Object.freeze({
      status: COMPLETENESS_STATUS.UNKNOWN,
      criterion: COMPLETENESS_CRITERION.SIGNALS_MISSING,
      reasons: [COMPLETENESS_REASON.LIMIT_EXCEEDED],
      affectedFiles: [],
      affectedFileCount: 0,
      filesScanned: null,
      ...base
    });
  }
  const arquivos = lacunas.map((a) => Object.freeze({ path: a.path, reasons: [...a.reasons].sort(), rules: [], timeouts: 0 }));
  const temLacuna = arquivos.length > 0;
  return Object.freeze({
    status: temLacuna ? COMPLETENESS_STATUS.PARTIAL : COMPLETENESS_STATUS.COMPLETE,
    criterion: temLacuna ? COMPLETENESS_CRITERION.UNIVERSE_GAPS : COMPLETENESS_CRITERION.UNIVERSE_ANALYZED,
    reasons: ordenarUnicos(arquivos.flatMap((a) => a.reasons)),
    affectedFiles: arquivos.slice(0, teto),
    affectedFileCount: arquivos.length,
    affectedFilesTruncated: arquivos.length > teto,
    affectedFilesDigest: digest(arquivos.map((a) => `${a.path}\t${a.reasons.join(',')}`)),
    filesScanned: universe.analyzed,
    ...base,
    universe: Object.freeze(universe)
  });
}

/**
 * Completude do sensor de segredos no HISTÓRICO Git (Gitleaks), a partir da comparação feita pelo ZUNVIO entre o
 * histórico esperado (Git) e o varrido (Gitleaks). Nunca inferida só da declaração do Gitleaks.
 * @param {{ status: string, cobertura: object }} resultado - executarHistoricoGitleaks()
 * @param {string} opcoesLog - as opções de log com que esperado e varrido foram medidos
 */
export function completudeDoHistorico(resultado, opcoesLog) {
  const c = resultado?.cobertura || {};
  const history = Object.freeze({
    model: MODELO_HISTORICO,
    scope: 'HEAD_REACHABLE',
    logOptions: opcoesLog,
    applicable: c.applicable !== false,
    shallow: c.shallow ?? null,
    headCommit: c.headCommit ?? null,
    commitsTotal: c.commitsTotal ?? null,
    commitsExpected: c.commitsExpected ?? null,
    commitsScanned: c.commitsScanned ?? null,
    ...(c.expectedDigest ? { expectedDigest: c.expectedDigest } : {})
  });
  const base = { affectedFiles: [], affectedFileCount: 0, ruleErrors: [], errorsByType: {}, filesScanned: null, effectiveLimits: null, source: 'git+gitleaks-history', history };
  if (resultado?.status !== 'SUCCESS' && resultado?.status !== 'NOT_RUN') {
    return Object.freeze({ status: COMPLETENESS_STATUS.DEGRADED, criterion: COMPLETENESS_CRITERION.SCANNER_FAILED, reasons: [COMPLETENESS_REASON.SCANNER_FAILURE], ...base });
  }
  if (c.status === 'COMPLETE') {
    return Object.freeze({ status: COMPLETENESS_STATUS.COMPLETE, criterion: COMPLETENESS_CRITERION.HISTORY_SCANNED, reasons: [], ...base });
  }
  return Object.freeze({
    status: COMPLETENESS_STATUS.UNKNOWN,
    criterion: COMPLETENESS_CRITERION.SIGNALS_MISSING,
    reasons: [c.reason || COMPLETENESS_REASON.HISTORY_NOT_DETERMINED],
    ...base
  });
}

const MOTIVOS_HISTORICO = new Set(['SHALLOW_HISTORY', 'HISTORY_NOT_DETERMINED', 'HISTORY_COVERAGE_MISMATCH']);
const naoNeg = (n) => Number.isInteger(n) && n >= 0;

/**
 * Coerência de uma completude de histórico SELADA (validador do pack 0.7.0 e verificador de recibo). Vazio = coerente.
 * COMPLETE (histórico varrido) exige: aplicável, não shallow, HEAD registrado e commits varridos = esperados.
 */
export function problemasDoHistorico(c) {
  const h = c?.history;
  if (!h || typeof h !== 'object') return ['history ausente'];
  const p = [];
  if (h.model !== MODELO_HISTORICO || h.scope !== 'HEAD_REACHABLE' || typeof h.logOptions !== 'string' || typeof h.applicable !== 'boolean') p.push('history fora do modelo');
  for (const k of ['commitsTotal', 'commitsExpected', 'commitsScanned']) if (h[k] !== null && !naoNeg(h[k])) p.push(`history.${k} deve ser inteiro ≥ 0 ou null`);
  if (h.headCommit !== null && !/^[0-9a-f]{40}$/.test(h.headCommit)) p.push('history.headCommit deve ser SHA de 40 caracteres ou null');
  if (h.shallow !== null && typeof h.shallow !== 'boolean') p.push('history.shallow deve ser booleano ou null');
  if (c.criterion === COMPLETENESS_CRITERION.HISTORY_SCANNED) {
    if (c.status !== COMPLETENESS_STATUS.COMPLETE) p.push('histórico varrido exige COMPLETE');
    if (h.applicable !== true || h.shallow !== false || !h.headCommit) p.push('histórico COMPLETE exige repositório aplicável, não shallow e HEAD registrado');
    if (!naoNeg(h.commitsExpected) || h.commitsScanned !== h.commitsExpected) p.push('histórico COMPLETE exige commits varridos = commits esperados');
  }
  if (c.status === COMPLETENESS_STATUS.COMPLETE && c.criterion !== COMPLETENESS_CRITERION.HISTORY_SCANNED) p.push('histórico COMPLETE só pelo critério do histórico varrido');
  if (c.status === COMPLETENESS_STATUS.UNKNOWN && (!Array.isArray(c.reasons) || c.reasons.length !== 1 || !MOTIVOS_HISTORICO.has(c.reasons[0]))) p.push('histórico UNKNOWN exige exatamente um motivo do histórico');
  if (h.shallow === true && c.status === COMPLETENESS_STATUS.COMPLETE) p.push('histórico shallow não pode ser COMPLETE');
  return p;
}
