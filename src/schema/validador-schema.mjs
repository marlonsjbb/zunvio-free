import schemaEvidencePack from './evidence-pack-v0.schema.json' with { type: 'json' };
import { calcularHashCanonico, serializarJsonCanonico } from '../utils/canonical-json.mjs';
import { validarMapaClaimEvidence } from '../decision/claim-evidence-map.mjs';

const ESTADOS_PUBLICOS = new Set(['ATENDE', 'NAO_ATENDE', 'NAO_COMPROVADO', 'NAO_APLICAVEL']);
const SUBCAUSAS_NAO_COMPROVADO = new Set([
  'SEM_EVIDENCIA_DO_CLIENTE',
  'FORA_DE_COBERTURA_DO_MOTOR',
  'MOTOR_FALHOU'
]);

/**
 * Validador estrutural determinístico do Evidence Pack v0.
 * @param {object} evidencePack
 * @param {{ finalidade?: 'DECISAO' | 'SELO' | 'APROVACAO' | 'COMPARACAO_DECISORIA' | 'HISTORICO' }} [opcoes]
 * @returns {{ valido: boolean, erros: string[] }}
 */
export function validarEvidencePackV0(evidencePack, { finalidade = 'DECISAO' } = {}) {
  const erros = [];

  if (!evidencePack || typeof evidencePack !== 'object') {
    return { valido: false, erros: ['Evidence pack deve ser um objeto não nulo'] };
  }

  // 1. Campos de primeiro nível obrigatórios
  const camposObrigatorios = [
    'versao',
    'target',
    'canonicalHash',
    'canonicalContent',
    'volatileMetadata',
    'integrityProof',
    'decision',
    'coverageAndResidualRisk'
  ];

  for (const campo of camposObrigatorios) {
    if (evidencePack[campo] === undefined || evidencePack[campo] === null) {
      erros.push(`Campo obrigatório ausente: '${campo}'`);
    }
  }

  // 2. Validação da versão
  if (!['0.1.0', '0.2.0'].includes(evidencePack.versao)) {
    erros.push(`Versão inválida: '${evidencePack.versao}'. Esperadas: '0.1.0' ou '0.2.0'`);
  }
  if (evidencePack.versao === '0.1.0' && finalidade !== 'HISTORICO') {
    erros.push(`Evidence Pack 0.1.0 é aceito somente como evidência histórica; seu uso decisório falha fechado porque decision não integra o canonicalHash`);
  }

  // 3. Validação do canonicalHash
  if (typeof evidencePack.canonicalHash !== 'string' || !/^[a-f0-9]{64}$/.test(evidencePack.canonicalHash)) {
    erros.push(`canonicalHash inválido: esperado SHA-256 de 64 caracteres hexadecimais`);
  }

  // 4. Validação de canonicalContent
  const cc = evidencePack.canonicalContent;
  if (evidencePack.versao === '0.2.0' && cc?.decision === undefined) {
    erros.push(`Evidence Pack 0.2.0 exige canonicalContent.decision protegido pelo canonicalHash`);
  }
  if (cc && typeof cc === 'object') {
    if (typeof cc.filesAnalyzed !== 'number' || cc.filesAnalyzed < 0) {
      erros.push(`canonicalContent.filesAnalyzed deve ser inteiro >= 0`);
    }
    if (typeof cc.inventoryDigest !== 'string' || !/^[a-f0-9]{64}$/.test(cc.inventoryDigest)) {
      erros.push(`canonicalContent.inventoryDigest deve ser SHA-256 de 64 caracteres`);
    }
    if (!Array.isArray(cc.findings)) {
      erros.push(`canonicalContent.findings deve ser um array`);
    }
    if (!Array.isArray(cc.exclusions)) {
      erros.push(`canonicalContent.exclusions deve ser um array`);
    }
    if (!Array.isArray(cc.limitations)) {
      erros.push(`canonicalContent.limitations deve ser um array`);
    }
    if (
      typeof evidencePack.canonicalHash === 'string' &&
      calcularHashCanonico(cc) !== evidencePack.canonicalHash
    ) {
      erros.push(`canonicalHash não corresponde ao canonicalContent`);
    }
  }

  // 4.1. Claim-to-Evidence Map v1 é aditivo, mas, quando presente, deve ser
  // formalmente válido, idêntico nos dois níveis e protegido pelo canonicalHash.
  if (evidencePack.claimEvidenceMap !== undefined) {
    const validacaoMapa = validarMapaClaimEvidence(evidencePack.claimEvidenceMap);
    for (const erro of validacaoMapa.erros) erros.push(`claimEvidenceMap: ${erro}`);
    if (cc?.claimEvidenceMap === undefined) {
      erros.push('claimEvidenceMap deve integrar canonicalContent.');
    } else if (
      serializarJsonCanonico(cc.claimEvidenceMap)
      !== serializarJsonCanonico(evidencePack.claimEvidenceMap)
    ) {
      erros.push('claimEvidenceMap diverge de canonicalContent.claimEvidenceMap.');
    }
  } else if (cc?.claimEvidenceMap !== undefined) {
    erros.push('canonicalContent.claimEvidenceMap exige claimEvidenceMap no primeiro nível.');
  }

  // 5. Validação de volatileMetadata
  const vm = evidencePack.volatileMetadata;
  if (vm && typeof vm === 'object') {
    if (typeof vm.timestamp !== 'string') {
      erros.push(`volatileMetadata.timestamp deve ser string ISO`);
    }
    if (typeof vm.durationMs !== 'number' || vm.durationMs < 0) {
      erros.push(`volatileMetadata.durationMs deve ser número >= 0`);
    }
  }

  // 6. Validação de integrityProof
  const ip = evidencePack.integrityProof;
  if (ip && typeof ip === 'object') {
    if (typeof ip.immutable !== 'boolean') {
      erros.push(`integrityProof.immutable deve ser boolean`);
    }
    if (typeof ip.initialDigest !== 'string' || typeof ip.finalDigest !== 'string') {
      erros.push(`integrityProof digests inicial e final devem ser strings`);
    }
  }

  // 7. Validação de decision
  const dec = evidencePack.decision;
  if (dec && typeof dec === 'object') {
    if (typeof dec.score !== 'number' || dec.score < 0 || dec.score > 100) {
      erros.push(`decision.score deve ser número entre 0 e 100`);
    }
    if (typeof dec.coverage !== 'number' || dec.coverage < 0 || dec.coverage > 100) {
      erros.push(`decision.coverage deve ser número entre 0 e 100`);
    }
    if (!['ACCEPT', 'REJECT', 'UNPROVEN'].includes(dec.outcome)) {
      erros.push(`decision.outcome deve ser 'ACCEPT', 'REJECT' ou 'UNPROVEN'`);
    }
    if (
      evidencePack.versao === '0.2.0' &&
      (typeof dec.maxPossibleScore !== 'number' || dec.maxPossibleScore < 0 || dec.maxPossibleScore > 100)
    ) {
      erros.push(`decision.maxPossibleScore deve ser número entre 0 e 100`);
    }
    if (evidencePack.versao === '0.2.0' && !Array.isArray(dec.gates)) {
      erros.push(`decision.gates deve ser array no Evidence Pack 0.2.0`);
    } else if (!dec.gates || (typeof dec.gates !== 'object' && !Array.isArray(dec.gates))) {
      erros.push(`decision.gates deve ser objeto ou array`);
    }
    if (Array.isArray(dec.gates)) {
      for (const [indice, gate] of dec.gates.entries()) {
        if (!gate || typeof gate !== 'object') {
          erros.push(`decision.gates[${indice}] deve ser objeto`);
          continue;
        }
        if (!ESTADOS_PUBLICOS.has(gate.estado)) {
          erros.push(`decision.gates[${indice}].estado deve usar um dos quatro estados públicos`);
        }
        if (
          gate.estado === 'NAO_COMPROVADO' &&
          !SUBCAUSAS_NAO_COMPROVADO.has(gate.subcausa)
        ) {
          erros.push(`decision.gates[${indice}] NÃO COMPROVADO exige subcausa interna válida`);
        }
        if (gate.estado !== 'NAO_COMPROVADO' && Object.hasOwn(gate, 'subcausa')) {
          erros.push(`decision.gates[${indice}].subcausa só pode existir em NÃO COMPROVADO`);
        }
      }
    }
    if (
      cc?.decision !== undefined &&
      serializarJsonCanonico(cc.decision) !== serializarJsonCanonico(dec)
    ) {
      erros.push(`decision diverge de canonicalContent.decision`);
    }
  }

  // 8. Validação de coverageAndResidualRisk
  const cr = evidencePack.coverageAndResidualRisk;
  if (cr && typeof cr === 'object') {
    if (!Array.isArray(cr.excludedPaths)) {
      erros.push(`coverageAndResidualRisk.excludedPaths deve ser array`);
    }
    if (!Array.isArray(cr.unexecutedChecks)) {
      erros.push(`coverageAndResidualRisk.unexecutedChecks deve ser array`);
    }
    if (typeof cr.residualRiskStatement !== 'string' || !cr.residualRiskStatement.trim()) {
      erros.push(`coverageAndResidualRisk.residualRiskStatement deve ser string não-vazia`);
    }
  }

  return {
    valido: erros.length === 0,
    erros
  };
}
