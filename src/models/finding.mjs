import { createHash } from 'node:crypto';
import { redigirTexto, redigirObjeto } from '../utils/redactor.mjs';

const SEVERIDADES_VALIDAS = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);

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
 * @param {object} [params.rawDetails={}] - Metadados adicionais sanitizados.
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
  identidadeExtra = null
}) {
  const scannerNorm = String(scanner || '').trim().toLowerCase();
  const ruleIdNorm = String(ruleId || 'UNKNOWN_RULE').trim();
  const sevUpper = String(severity || 'INFO').trim().toUpperCase();
  const severityNorm = SEVERIDADES_VALIDAS.has(sevUpper) ? sevUpper : 'INFO';
  const filePathNorm = String(filePath || '').replace(/\\/g, '/');
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
    startLine: startLineNorm,
    endLine: endLineNorm,
    fingerprint,
    rawDetails: Object.freeze(rawDetailsRedigido)
  });
}

/**
 * Projeta um achado normalizado para a forma canônica selada em
 * `canonicalContent.findings`. É a MESMA projeção usada na construção do
 * Evidence Pack e no cálculo do `findingsDigest` por sensor, de modo que um
 * verificador possa recomputar o digest a partir dos achados selados (B4).
 * @param {object} achado - Achado normalizado (com id/fingerprint/rawDetails).
 * @returns {{ scanner: string, ruleId: string, severity: string, filePath: string, startLine: number, endLine: number, message: string }}
 */
export function projetarAchadoCanonico(achado) {
  return {
    scanner: achado.scanner,
    ruleId: achado.ruleId,
    severity: achado.severity,
    filePath: achado.filePath,
    startLine: achado.startLine,
    endLine: achado.endLine,
    message: achado.message
  };
}
