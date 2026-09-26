import { createHash } from 'node:crypto';
import { redigirTexto, redigirObjeto } from '../utils/redactor.mjs';

const SEVERIDADES_VALIDAS = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
const ORDEM_SEVERIDADE = { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4, INFO: 5 };

export const CATEGORIAS_ACHADO = Object.freeze({
  CODIGO_PROPRIO: 'CODIGO_PROPRIO',
  TERCEIROS_DEPENDENCIAS: 'TERCEIROS_DEPENDENCIAS',
  TESTES_FIXTURES: 'TESTES_FIXTURES',
  ARTEFATOS_GERADOS: 'ARTEFATOS_GERADOS'
});

export const ESTADO_DETECCAO = Object.freeze({ DETECTADO: 'DETECTADO' });
export const STATUS_VALIDACAO_ACHADO = Object.freeze({
  NECESSITA_REVISAO: 'NECESSITA_REVISAO',
  CONFIRMADO: 'CONFIRMADO'
});

export function classificarCategoriaCaminho(filePath) {
  const segmentos = String(filePath || '')
    .replace(/\\/g, '/')
    .split('/')
    .filter(Boolean)
    .map((segmento) => segmento.toLowerCase());

  if (segmentos.includes('node_modules')) return CATEGORIAS_ACHADO.TERCEIROS_DEPENDENCIAS;
  // MASS-399 AJ-01B: o nome do diretório (dist/build/coverage), isoladamente,
  // não é mais tratado como prova de artefato gerado (decisão de política
  // #12420 — reproduzido em AJ-01 que isso permitia esconder segredo/eval()
  // reais de propósito). ARTEFATOS_GERADOS permanece no enum e no relatório
  // por compatibilidade de schema, mas nada nesta função a atribui mais;
  // um achado nesses caminhos agora cai em CODIGO_PROPRIO e bloqueia como
  // qualquer achado em src/.
  if (segmentos.some((segmento) => ['test', 'tests', '__tests__', 'fixtures'].includes(segmento))) {
    return CATEGORIAS_ACHADO.TESTES_FIXTURES;
  }
  return CATEGORIAS_ACHADO.CODIGO_PROPRIO;
}

export function achadoBloqueiaCodigoProprio(achado) {
  return achado?.categoria !== CATEGORIAS_ACHADO.TERCEIROS_DEPENDENCIAS
    && achado?.categoria !== CATEGORIAS_ACHADO.ARTEFATOS_GERADOS
    // PL-03: o efeito na decisão é o do SIGNIFICADO selado no achado. INFORMATIVO (inclui identidade de símbolo
    // RECUSADA) não bloqueia; RISCO_DEMONSTRADO e REVISAO_NECESSARIA bloqueiam. Sem significado, vale a regra
    // anterior (compatibilidade).
    && achado?.significado?.efeitoNaDecisao !== 'NAO_BLOQUEIA'
    && achado?.identidadeSimbolo?.status !== 'RECUSADA'
    // E2E mínimo: revisão humana ACEITA (só possível em REVISAO_NECESSARIA) deixa de bloquear; o achado e a revisão
    // continuam no Evidence Pack. Nunca vale para RISCO_DEMONSTRADO.
    && !(achado?.revisaoHumana?.estado === 'ACEITA' && achado?.significado?.classe === 'REVISAO_NECESSARIA');
}

function compararTexto(a, b) {
  const textoA = String(a ?? '');
  const textoB = String(b ?? '');
  if (textoA < textoB) return -1;
  if (textoA > textoB) return 1;
  return 0;
}

/** Ordena achados por uma chave total, independente da ordem emitida pelos motores. */
export function compararAchadosNormalizados(a, b) {
  const diferencaSeveridade = (ORDEM_SEVERIDADE[a?.severity] ?? 99) - (ORDEM_SEVERIDADE[b?.severity] ?? 99);
  if (diferencaSeveridade !== 0) return diferencaSeveridade;

  return compararTexto(a?.filePath, b?.filePath)
    || (Number(a?.startLine) || 0) - (Number(b?.startLine) || 0)
    || (Number(a?.endLine) || 0) - (Number(b?.endLine) || 0)
    || compararTexto(a?.scanner, b?.scanner)
    || compararTexto(a?.ruleId, b?.ruleId)
    || compararTexto(a?.fingerprint, b?.fingerprint)
    || compararTexto(a?.id, b?.id);
}

/**
 * Cria um objeto de achado de segurança normalizado e imutável.
 * @param {object} params
 * @param {'gitleaks' | 'semgrep'} params.scanner - Nome do scanner que gerou o achado.
 * @param {string} params.ruleId - Identificador da regra ou vulnerabilidade.
 * @param {'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'} params.severity - Grau de severidade normalizado.
 * @param {string} params.message - Mensagem descritiva do achado (será redigida).
 * @param {string} params.filePath - Caminho relativo do arquivo afetado.
 * @param {number} [params.startLine=1] - Linha inicial do achado.
 * @param {number} [params.endLine=1] - Linha final do achado.
 * @param {boolean} [params.possivelPlaceholder=false] - Indica que o identificador declarador documenta um valor sintético.
 * @param {object} [params.rawDetails={}] - Metadados adicionais sanitizados.
 * @param {object|null} [params.significado=null] - PL-03: significado do achado (models/finding-meaning.mjs) —
 *   classe, efeito na decisão, propriedades demonstradas/não demonstradas, contexto, razão. Selado sob o hash.
 * @param {object|null} [params.identidadeSimbolo=null] - PL-03 · Fatia 1: evidência estruturada da identidade do
 *   símbolo chamado (hoje só para zunvio.child-process-exec; ver models/symbol-identity.mjs). Ausente nas demais regras.
 * @param {string|null} [params.identidadeExtra=null] - Discriminador opcional de
 *   identidade além de (scanner, regra, arquivo, faixa de linhas). O Gitleaks usa
 *   isto para carregar commit e faixa de colunas, de modo que uma credencial
 *   rotacionada no mesmo lugar (commits distintos) ou dois segredos distintos na
 *   mesma linha não colapsem para o mesmo `id`/`fingerprint` (PER-207). Deve ser
 *   determinístico e nunca conter o segredo em claro. Ausente para o Semgrep.
 * @returns {Readonly<{ id: string, scanner: string, ruleId: string, severity: string, message: string, filePath: string, startLine: number, endLine: number, fingerprint: string, rawDetails: Readonly<object> }>}
 */
export function criarAchadoNormalizado({
  scanner,
  ruleId,
  severity,
  message,
  filePath,
  startLine = 1,
  endLine = 1,
  rawDetails = {},
  identidadeExtra = null,
  possivelPlaceholder = false,
  identidadeSimbolo = null,
  significado = null
}) {
  const scannerNorm = String(scanner || '').trim().toLowerCase();
  const ruleIdNorm = String(ruleId || 'UNKNOWN_RULE').trim();
  const sevUpper = String(severity || 'INFO').trim().toUpperCase();
  const severityNorm = SEVERIDADES_VALIDAS.has(sevUpper) ? sevUpper : 'INFO';
  const filePathNorm = String(filePath || '').replace(/\\/g, '/');
  const categoria = classificarCategoriaCaminho(filePathNorm);
  const startLineNorm = Number.isInteger(startLine) && startLine > 0 ? startLine : 1;
  const endLineNorm = Number.isInteger(endLine) && endLine >= startLineNorm ? endLine : startLineNorm;

  const mensagemRedigida = redigirTexto(String(message || ''));
  const rawDetailsRedigido = redigirObjeto(rawDetails || {});

  const identidadeBase = `${scannerNorm}:${ruleIdNorm}:${filePathNorm}:${startLineNorm}:${endLineNorm}`;
  const identidadeExtraNorm =
    identidadeExtra !== null && identidadeExtra !== undefined && String(identidadeExtra) !== ''
      ? String(identidadeExtra)
      : '';
  const fonteFingerprint = identidadeExtraNorm ? `${identidadeBase}:${identidadeExtraNorm}` : identidadeBase;

  const fingerprint = createHash('sha256').update(fonteFingerprint).digest('hex').slice(0, 16);

  const id = `ZVS-${scannerNorm.slice(0, 3).toUpperCase()}-${fingerprint}`;

  return Object.freeze({
    id,
    scanner: scannerNorm,
    ruleId: ruleIdNorm,
    severity: severityNorm,
    message: mensagemRedigida,
    filePath: filePathNorm,
    categoria,
    estadoDeteccao: ESTADO_DETECCAO.DETECTADO,
    statusValidacao: STATUS_VALIDACAO_ACHADO.NECESSITA_REVISAO,
    startLine: startLineNorm,
    endLine: endLineNorm,
    fingerprint,
    ...(possivelPlaceholder === true ? { possivelPlaceholder: true } : {}),
    ...(identidadeSimbolo ? { identidadeSimbolo: Object.freeze(redigirObjeto(identidadeSimbolo)) } : {}),
    ...(significado ? { significado: Object.freeze(redigirObjeto(significado)) } : {}),
    rawDetails: Object.freeze(rawDetailsRedigido)
  });
}

/**
 * Projeta um achado normalizado para a forma canônica selada em
 * `canonicalContent.findings`. É a MESMA projeção usada na construção do
 * Evidence Pack e no cálculo do `findingsDigest` por sensor, de modo que um
 * verificador possa recomputar o digest a partir dos achados selados (B4).
 * @param {object} achado - Achado normalizado (com id/fingerprint/rawDetails).
 * @returns {{ scanner: string, ruleId: string, severity: string, filePath: string, startLine: number, endLine: number, message: string, possivelPlaceholder?: true }}
 */
export function projetarAchadoCanonico(achado) {
  return {
    scanner: achado.scanner,
    ruleId: achado.ruleId,
    severity: achado.severity,
    filePath: achado.filePath,
    categoria: achado.categoria || classificarCategoriaCaminho(achado.filePath),
    estadoDeteccao: ESTADO_DETECCAO.DETECTADO,
    statusValidacao: achado.statusValidacao || STATUS_VALIDACAO_ACHADO.NECESSITA_REVISAO,
    startLine: achado.startLine,
    endLine: achado.endLine,
    message: achado.message,
    ...(achado.possivelPlaceholder === true ? { possivelPlaceholder: true } : {}),
    // PL-03 · Fatia 1: a identidade do símbolo fica selada sob o hash junto com o achado.
    ...(achado.identidadeSimbolo ? { identidadeSimbolo: achado.identidadeSimbolo } : {}),
    // PL-03 (fechamento): o significado (classe, propriedades, contexto, razão, efeito na decisão) influencia o
    // portão, então também fica selado sob o hash.
    ...(achado.significado ? { significado: achado.significado } : {}),
    // E2E mínimo (EP 0.8.0): revisão humana ACEITA fica selada no achado com a chave estável e o contexto que a
    // sustentam (o verificador confere a coerência). Achado sem revisão aceita não muda de forma.
    ...(achado.revisaoHumana ? { chaveRevisao: achado.chaveRevisao, contextoRevisao: achado.contextoRevisao, revisaoHumana: achado.revisaoHumana } : {})
  };
}
