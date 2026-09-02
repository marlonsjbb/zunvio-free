import { createHash } from 'node:crypto';
import { calcularHashCanonico } from '../utils/canonical-json.mjs';

// Estados canônicos de completude de um sensor, distintos entre si:
// - CLEAN: o sensor concluiu e não encontrou achados.
// - WITH_FINDINGS: o sensor concluiu e encontrou achados.
// - NOT_STARTED: o sensor não iniciou (binário indisponível).
// - FAILED: o sensor iniciou mas falhou (erro/timeout/estouro de buffer).
export const COMPLETUDE = Object.freeze({
  CLEAN: 'CLEAN',
  WITH_FINDINGS: 'WITH_FINDINGS',
  NOT_STARTED: 'NOT_STARTED',
  FAILED: 'FAILED'
});

/**
 * Classifica a completude do sensor a partir do status do runner e do total de
 * achados. "Zero achados" só é CLEAN quando o status é SUCCESS; qualquer outro
 * status nunca é inferido como "rodou limpo".
 */
export function classificarCompletude(status, totalAchados = 0) {
  if (status === 'SUCCESS') {
    return totalAchados > 0 ? COMPLETUDE.WITH_FINDINGS : COMPLETUDE.CLEAN;
  }
  if (status === 'UNAVAILABLE') return COMPLETUDE.NOT_STARTED;
  return COMPLETUDE.FAILED;
}

/**
 * Extrai a versão semver (x.y.z, sem sufixo de pré-release) da saída textual do
 * binário. Retorna null quando a saída não contém um semver reconhecível.
 */
export function extrairVersaoSemver(texto) {
  if (typeof texto !== 'string') return null;
  const m = /(\d+\.\d+\.\d+)/.exec(texto);
  return m ? m[1] : null;
}

/** SHA-256 (hex, 64 chars) determinístico de um texto UTF-8. */
export function hashTexto(texto) {
  return createHash('sha256').update(String(texto), 'utf8').digest('hex');
}

/** Digest canônico (SHA-256 sobre JSON canônico) de um valor serializável. */
export function calcularDigestCanonico(valor) {
  return calcularHashCanonico(valor);
}
