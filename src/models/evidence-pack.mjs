import { calcularHashCanonico } from '../utils/canonical-json.mjs';
import { validarEvidencePackV0 } from '../schema/validador-schema.mjs';
import { projetarAchadoCanonico } from './finding.mjs';
import { DECISAO_PUBLICACAO, CODIGO_DECISAO, OUTCOME_CANONICO } from '../decision/evaluator.mjs';

/**
 * Constrói e valida o Evidence Pack v0 estruturado e determinístico.
 * @param {object} params
 * @param {string} params.target - Caminho canônico do projeto.
 * @param {number} params.duracaoTotalMs - Duração da análise em ms.
 * @param {object} params.integridade - Resultado de imutabilidade e digest.
 * @param {object} params.scanners - Sumário e status dos scanners.
 * @param {Array} params.achados - Lista normalizada e ordenada de achados.
 * @param {object} params.avaliacao - Avaliação com score, cobertura e gates.
 * @param {object} params.badges - Badges gerados.
 * @param {object|null} [params.claimEvidenceMap=null] - Mapa Claim-to-Evidence v1.
 * @param {object} [params.delta] - Detalhes do Git diff e blast radius.
 * @param {Array} [params.exclusoes=[]] - Exclusões rastreadas.
 * @param {Array} [params.errosLeitura=[]] - Erros de leitura encontrados.
 * @param {boolean} [params.limitesExcedidos=false] - Se limites foram excedidos.
 * @param {string|null} [params.motivoLimite=null] - Motivo do limite excedido.
 * @param {object} [params.resumoSeveridade] - Contagem por severidade.
 * @returns {object} Evidence Pack v0 validado e congelado.
 */
export function construirEvidencePackV0({
  target,
  duracaoTotalMs,
  integridade,
  scanners,
  achados = [],
  avaliacao,
  badges,
  claimEvidenceMap = null,
  delta = {},
  exclusoes = [],
  errosLeitura = [],
  limitesExcedidos = false,
  motivoLimite = null,
  resumoSeveridade = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
}) {
  const scoreNum = typeof avaliacao.score === 'number' ? avaliacao.score : (avaliacao.score?.observado ?? 0);
  const coverageNum = typeof avaliacao.cobertura === 'number' ? avaliacao.cobertura : (avaliacao.score?.cobertura ?? 0);
  const maxScoreNum = typeof avaliacao.maxScorePossivel === 'number' ? avaliacao.maxScorePossivel : (avaliacao.score?.maximoPossivel ?? 100);
  let outcomeCode = OUTCOME_CANONICO.UNPROVEN;
  const rawDecisao = avaliacao.decisao?.decisaoPublicacao || avaliacao.decisao?.codigo || avaliacao.decisao;
  if (
    rawDecisao === DECISAO_PUBLICACAO.PUBLICAR ||
    rawDecisao === CODIGO_DECISAO.ACEITAR ||
    rawDecisao === OUTCOME_CANONICO.ACCEPT
  ) {
    outcomeCode = OUTCOME_CANONICO.ACCEPT;
  } else if (
    rawDecisao === DECISAO_PUBLICACAO.NAO_PUBLICAR ||
    rawDecisao === CODIGO_DECISAO.NAO_ACEITAR ||
    rawDecisao === OUTCOME_CANONICO.REJECT
  ) {
    outcomeCode = OUTCOME_CANONICO.REJECT;
  } else if (
    rawDecisao === DECISAO_PUBLICACAO.INCONCLUSIVO ||
    rawDecisao === CODIGO_DECISAO.INCONCLUSIVO ||
    rawDecisao === OUTCOME_CANONICO.UNPROVEN
  ) {
    // MASS-307: estado INCONCLUSIVO é selado como UNPROVEN no canonicalHash.
    outcomeCode = OUTCOME_CANONICO.UNPROVEN;
  }
  const decision = {
    score: scoreNum,
    coverage: coverageNum,
    outcome: outcomeCode,
    maxPossibleScore: maxScoreNum,
    gates: avaliacao.portoes
  };

  // 1. Monta o Conteúdo Canônico (estritamente livre de campos voláteis como timestamp/duração)
  const canonicalContent = {
    filesAnalyzed: integridade.contagemArquivos || 0,
    inventoryDigest: integridade.digestInicial,
    scannersSummary: {
      gitleaks: {
        id: scanners.gitleaks?.identidade?.id || 'gitleaks',
        status: scanners.gitleaks?.status || 'UNAVAILABLE',
        findingsCount: scanners.gitleaks?.totalAchados || 0,
        version: scanners.gitleaks?.identidade?.versao ?? null,
        configHash: scanners.gitleaks?.identidade?.configHash ?? null,
        findingsDigest: scanners.gitleaks?.identidade?.findingsDigest ?? null,
        completion: scanners.gitleaks?.identidade?.completion ?? null
      },
      semgrep: {
        id: scanners.semgrep?.identidade?.id || 'semgrep',
        status: scanners.semgrep?.status || 'UNAVAILABLE',
        findingsCount: scanners.semgrep?.totalAchados || 0,
        version: scanners.semgrep?.identidade?.versao ?? null,
        configHash: scanners.semgrep?.identidade?.configHash ?? null,
        findingsDigest: scanners.semgrep?.identidade?.findingsDigest ?? null,
        completion: scanners.semgrep?.identidade?.completion ?? null
      }
    },
    findingsCount: achados.length,
    findings: achados.map(projetarAchadoCanonico),
    exclusions: exclusoes.map((e) => ({
      path: e.caminho,
      reason: e.motivo
    })),
    limitations: [
      ...(limitesExcedidos && motivoLimite ? [motivoLimite] : []),
      ...errosLeitura.map((er) => `Erro de I/O em ${er.caminho}: ${er.erro}`)
    ],
    decision,
    ...(claimEvidenceMap ? { claimEvidenceMap } : {})
  };

  // 2. Calcula o Hash Canônico do conteúdo determinístico
  const canonicalHash = calcularHashCanonico(canonicalContent);

  // 3. Metadados Voláteis
  const timestampIso = new Date().toISOString();
  const volatileMetadata = {
    timestamp: timestampIso,
    durationMs: duracaoTotalMs,
    systemPlatform: `${process.platform}-${process.arch}`
  };

  // 4. Prova de Integridade
  const integrityProof = {
    initialDigest: integridade.digestInicial,
    finalDigest: integridade.digestFinal,
    immutable: integridade.inalterado,
    differences: integridade.diferencas || []
  };

  // 5. Declaração de Cobertura e Risco Residual
  const unexecutedChecks = [];
  if (!scanners.gitleaks?.disponivel) unexecutedChecks.push('gitleaks-secret-detection');
  if (!scanners.semgrep?.disponivel) unexecutedChecks.push('semgrep-sast-detection');
  if (!delta.ativo) unexecutedChecks.push('git-delta-blast-radius');

  const residualRiskStatement =
    unexecutedChecks.length > 0 || exclusoes.length > 0 || !integridade.inalterado
      ? `Risco residual existente: verificações omitidas (${unexecutedChecks.join(', ') || 'nenhuma'}), ${exclusoes.length} itens excluídos e ${achados.length} achados reportados.`
      : `Análise estática local executada com 100% de integridade. O risco residual restringe-se a vulnerabilidades de runtime e dependências de terceiros não analisadas neste lote.`;

  const coverageAndResidualRisk = {
    excludedPaths: exclusoes.map((e) => e.caminho),
    unexecutedChecks,
    residualRiskStatement
  };

  const pack = {
    versao: '0.2.0',
    target,
    canonicalHash,
    canonicalContent,
    volatileMetadata,
    integrityProof,
    decision,
    ...(claimEvidenceMap ? { claimEvidenceMap } : {}),
    badges,
    coverageAndResidualRisk,
    delta: {
      ativo: Boolean(delta.ativo),
      ehRepositorioGit: Boolean(delta.ehRepositorioGit),
      baseRef: delta.baseRef || null,
      headRef: delta.headRef || null,
      arquivosAlterados: delta.arquivosAlterados || 0,
      blastRadius: delta.blastRadius || null,
      resumoAchadosDelta: delta.resumoAchadosDelta || null,
      arquivos: delta.arquivos || [],
      erro: delta.erro || null
    },
    scanners,
    totalAchados: achados.length,
    resumoSeveridade,
    achados,
    // Propriedades de compatibilidade para relatórios CLI existentes
    timestamp: timestampIso,
    duracaoTotalMs,
    arquivosAnalisados: integridade.contagemArquivos || 0,
    integridade: {
      inalterado: integridade.inalterado,
      digestInicial: integridade.digestInicial,
      digestFinal: integridade.digestFinal,
      diferencas: integridade.diferencas || []
    },
    avaliacao
  };

  const validacao = validarEvidencePackV0(pack);
  if (!validacao.valido) {
    throw new Error(`Evidence Pack gerado não está em conformidade com o schema v0: ${validacao.erros.join('; ')}`);
  }

  return Object.freeze(pack);
}
