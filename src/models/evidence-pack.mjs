import { calcularHashCanonico } from '../utils/canonical-json.mjs';
import { validarEvidencePackV0 } from '../schema/validador-schema.mjs';
import { projetarAchadoCanonico } from './finding.mjs';
import { DECISAO_PUBLICACAO, CODIGO_DECISAO, OUTCOME_CANONICO } from '../decision/evaluator.mjs';
import { agregarCompletude, completudeNaoAvaliada, limitacoesDaCompletude } from './completeness.mjs';

// Fatia 1 (Scanner Completeness): versão explícita do contrato. 0.3.0 acrescenta
// completude por scanner (canônica), `limitations` estruturadas e metadados de
// reconstrução da execução. Leitores de 0.2.0 continuam aceitos pelo validador.
// PL-03 (fechamento): 0.4.0 = 0.3.0 + `significado` selado em cada achado do Gitleaks/Semgrep (classe, efeito na
// decisão, propriedades demonstradas/não demonstradas, contexto, razão). Packs 0.3.0 continuam aceitos.
// PL-02 (universo esperado): 0.5.0 = 0.4.0 + `completeness.universe` por scanner (universo esperado × análise
// efetiva, motivos, digests) e `affectedFiles` com teto + `affectedFilesTruncated`/`affectedFilesDigest`.
// Packs 0.2.0–0.4.0 continuam aceitos.
// PL-01 + PL-04 (confiança ≤ evidência): 0.6.0 = 0.5.0 com os sinais de confiança derivados da completude — sensor
// sem sinal de cobertura não sustenta ATENDE (portão NAO_COMPROVADO / FORA_DE_COBERTURA_DO_MOTOR) e gera limitação
// COMPLETENESS_UNKNOWN; acima do limite operacional a integridade é NAO_COMPROVADO e o resto do projeto vira lacuna
// declarada. Mesmo formato do 0.5.0; as regras novas valem a partir do 0.6.0 (packs 0.5.0 seguem as da época).
// LC-06 (cobertura verificável de segredos): 0.7.0 = 0.6.0 + sensor de segredos em duas partes com cobertura própria —
// `scannersSummary['zunvio-segredos']` (working tree: scanner próprio, universo esperado × analisado, detalhe de política
// e de formatos não inspecionados) e `scannersSummary.gitleaks` só para o histórico Git, com `completeness.history`
// (commits esperados pelo Git × varridos pelo Gitleaks, shallow). Baseline do projeto selada por contagem. O portão
// Segredos só é ATENDE com as duas coberturas completas e zero achado (nem suprimido). Packs 0.2–0.6 seguem aceitos.
export const VERSAO_EVIDENCE_PACK = '0.7.0';
// Sem as duas partes do sensor de segredos (chamador que monta o pack com os scanners do formato anterior), o pack
// É do formato 0.6.0 — a versão declara o que o conteúdo carrega. O orquestrador sempre produz 0.7.0.
const VERSAO_SEM_SEGREDOS_PROPRIO = '0.6.0';
// E2E mínimo (revisão humana registrável, decisão do fundador de 26/09/2026): 0.8.0 = 0.7.0 + `humanReviews` (toda revisão
// registrada no .zunvio-baseline.json e o estado dela nesta análise) + `revisaoHumana`/`chaveRevisao`/`contextoRevisao` selados
// no achado cuja revisão foi ACEITA. Versão por conteúdo: sem revisão registrada, o pack continua 0.7.0 (mesmo formato).
export const VERSAO_COM_REVISAO_HUMANA = '0.8.0';

const IMPACTO_PADRAO = 'Os achados encontrados continuam válidos. A parte não verificada pode esconder problemas que esta análise não conseguiu ver.';

function limitacaoEstruturada({ code, scanner = null, whatWasNotVerified, fileCount = null, files = [], reasons, detail, source }) {
  return {
    code,
    scanner,
    whatWasNotVerified,
    where: { fileCount, files, rules: [] },
    why: { reasons, detail },
    impact: IMPACTO_PADRAO,
    source
  };
}

function projetarCompletudeCanonica(completude) {
  if (!completude) return completudeNaoAvaliada(null);
  return {
    status: completude.status,
    criterion: completude.criterion,
    reasons: completude.reasons,
    affectedFileCount: completude.affectedFileCount,
    affectedFiles: completude.affectedFiles,
    ruleErrors: completude.ruleErrors,
    errorsByType: completude.errorsByType,
    filesScanned: completude.filesScanned,
    effectiveLimits: completude.effectiveLimits,
    source: completude.source,
    // PL-02: universo esperado × análise efetiva e representação auditável da lista truncada, sob o hash.
    ...(completude.affectedFilesTruncated !== undefined ? { affectedFilesTruncated: completude.affectedFilesTruncated } : {}),
    ...(completude.affectedFilesDigest !== undefined ? { affectedFilesDigest: completude.affectedFilesDigest } : {}),
    ...(completude.universe !== undefined ? { universe: completude.universe } : {}),
    // LC-06: cobertura do histórico Git (commits esperados × varridos), sob o hash.
    ...(completude.history !== undefined ? { history: completude.history } : {})
  };
}

// RF-08 (MASS-399): projeta um resultado de sensor informativo para dentro do
// conteúdo canônico, descartando `duracaoMs` — campo volátil por natureza,
// mesmo critério já aplicado ao restante do canonicalContent (timestamp/
// duração ficam em volatileMetadata, nunca sob o hash).
function projetarInformativo(resultado) {
  if (!resultado) return null;
  return {
    status: resultado.status,
    achados: Array.isArray(resultado.achados) ? resultado.achados : [],
    identidade: resultado.identidade || null,
    erro: resultado.erro ?? null
  };
}

/**
 * Constrói e valida o Evidence Pack v0 estruturado e determinístico.
 * @param {object} params
 * @param {string} params.target - Caminho canônico do projeto.
 * @param {number} params.duracaoTotalMs - Duração da análise em ms.
 * @param {object} params.integridade - Resultado de imutabilidade e digest.
 * @param {object} params.inventario - Inventário efetivamente entregue aos scanners.
 * @param {object} params.scanners - Sumário e status dos scanners.
 * @param {Array} params.achados - Lista normalizada e ordenada de achados.
 * @param {object} params.avaliacao - Avaliação com score, cobertura e gates.
 * @param {object|null} [params.claimEvidenceMap=null] - Mapa Claim-to-Evidence v1.
 * @param {object|null} [params.informativos=null] - RF-08 (MASS-399): achados dos sensores informativos (comentário perigoso, CVE/dependência). Sempre fora de canonicalContent.scannersSummary/decision — nunca afeta score, gates, outcome ou o verify existente.
 * @param {object} [params.delta] - Detalhes do Git diff e blast radius.
 * @param {Array} [params.exclusoes=[]] - Exclusões rastreadas.
 * @param {Array} [params.errosLeitura=[]] - Erros de leitura encontrados.
 * @param {boolean} [params.limitesExcedidos=false] - Se limites foram excedidos.
 * @param {string|null} [params.motivoLimite=null] - Motivo do limite excedido.
 * @param {object} [params.resumoSeveridade] - Contagem por severidade.
 * @param {object} [params.resumoCategorias] - Contagem por categoria de origem.
 * @returns {object} Evidence Pack v0 validado e congelado.
 */
export function construirEvidencePackV0({
  target,
  duracaoTotalMs,
  integridade,
  inventario = {},
  scanners,
  achados = [],
  revisoesHumanas = [],
  avaliacao,
  claimEvidenceMap = null,
  informativos = null,
  delta = {},
  exclusoes = [],
  errosLeitura = [],
  limitesExcedidos = false,
  motivoLimite = null,
  resumoSeveridade = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
  resumoCategorias = {
    CODIGO_PROPRIO: 0,
    TERCEIROS_DEPENDENCIAS: 0,
    TESTES_FIXTURES: 0,
    ARTEFATOS_GERADOS: 0
  },
  execucao = null
}) {
  const comSegredosProprio = Boolean(scanners['zunvio-segredos']);
  const completudePorScanner = {
    gitleaks: projetarCompletudeCanonica(scanners.gitleaks?.completude),
    ...(comSegredosProprio ? { 'zunvio-segredos': projetarCompletudeCanonica(scanners['zunvio-segredos'].completude) } : {}),
    semgrep: projetarCompletudeCanonica(scanners.semgrep?.completude)
  };
  // LC-06: baseline do próprio projeto selada por contagem (o verificador deriva o portão Segredos dela).
  const baselineSelada = (s) => (comSegredosProprio ? { suppressedByBaseline: { count: (s?.suprimidosPorBaseline || []).length, blocking: s?.suprimidosBloqueantesPorBaseline || 0 } } : {});
  // LC-06 (0.7.0): o achado suprimido pela baseline continua selado em `findings` (a evidência nunca some); a contagem
  // do sensor é a dos achados SELADOS dele — a supressão fica em `suppressedByBaseline`. (Antes, com baseline, a
  // contagem excluía o suprimido e divergia dos achados selados: todo recibo com baseline era recusado pelo verify.)
  const contagemSelada = (s) => (s?.totalAchados || 0) + (comSegredosProprio ? (s?.suprimidosPorBaseline || []).length : 0);
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
    filesAnalyzed: inventario.contagemArquivos ?? integridade.contagemArquivos ?? 0,
    inventoryDigest: inventario.digest || integridade.digestInicial,
    // O inventário entregue aos scanners pode excluir vendor/gerados. O digest
    // do alvo completo permanece selado separadamente para vincular a prova de
    // integridade ao canonicalHash sem confundir os dois perímetros.
    targetDigest: integridade.digestInicial,
    ...(Number.isInteger(avaliacao.contextoPublicacao?.coverage)
      ? { publicationContextCoverage: avaliacao.contextoPublicacao.coverage }
      : {}),
    scannersSummary: {
      gitleaks: {
        id: scanners.gitleaks?.identidade?.id || 'gitleaks',
        status: scanners.gitleaks?.status || 'UNAVAILABLE',
        findingsCount: contagemSelada(scanners.gitleaks),
        version: scanners.gitleaks?.identidade?.versao ?? null,
        configHash: scanners.gitleaks?.identidade?.configHash ?? null,
        findingsDigest: scanners.gitleaks?.identidade?.findingsDigest ?? null,
        completion: scanners.gitleaks?.identidade?.completion ?? null,
        completeness: completudePorScanner.gitleaks,
        ...baselineSelada(scanners.gitleaks)
      },
      ...(comSegredosProprio ? {
        'zunvio-segredos': {
          id: scanners['zunvio-segredos'].identidade?.id || 'zunvio-segredos',
          status: scanners['zunvio-segredos'].status || 'ERROR',
          findingsCount: contagemSelada(scanners['zunvio-segredos']),
          version: scanners['zunvio-segredos'].identidade?.versao ?? null,
          configHash: scanners['zunvio-segredos'].identidade?.configHash ?? null,
          findingsDigest: scanners['zunvio-segredos'].identidade?.findingsDigest ?? null,
          completion: scanners['zunvio-segredos'].identidade?.completion ?? null,
          completeness: completudePorScanner['zunvio-segredos'],
          // Política (woff/woff2), formatos não inspecionados, codificações e bytes lidos: auditável e selado.
          coverageDetail: scanners['zunvio-segredos'].detalheCobertura ?? null,
          ...baselineSelada(scanners['zunvio-segredos'])
        }
      } : {}),
      semgrep: {
        id: scanners.semgrep?.identidade?.id || 'semgrep',
        status: scanners.semgrep?.status || 'UNAVAILABLE',
        findingsCount: scanners.semgrep?.totalAchados || 0,
        version: scanners.semgrep?.identidade?.versao ?? null,
        configHash: scanners.semgrep?.identidade?.configHash ?? null,
        findingsDigest: scanners.semgrep?.identidade?.findingsDigest ?? null,
        completion: scanners.semgrep?.identidade?.completion ?? null,
        completeness: completudePorScanner.semgrep
      }
    },
    // Fatia 1: completude agregada da análise (pior estado entre os scanners).
    completeness: agregarCompletude(completudePorScanner),
    findingsCount: achados.length,
    findings: achados.map(projetarAchadoCanonico),
    ...(revisoesHumanas.length > 0 ? { humanReviews: revisoesHumanas.map((r) => ({ ...r })) } : {}),
    exclusions: exclusoes.map((e) => ({
      path: e.caminho,
      reason: e.motivo
    })),
    // Fatia 1: limitações estruturadas. Refletem a realidade: com degradação
    // comprovada, `limitations` nunca fica vazia.
    limitations: [
      ...limitacoesDaCompletude(completudePorScanner),
      ...(limitesExcedidos && motivoLimite ? [limitacaoEstruturada({
        code: 'LIMIT_EXCEEDED',
        whatWasNotVerified: 'Parte do projeto ficou fora da análise porque um limite de inventário foi atingido.',
        reasons: ['LIMIT_EXCEEDED'],
        detail: motivoLimite,
        source: 'inventory'
      })] : []),
      ...errosLeitura.map((er) => limitacaoEstruturada({
        code: 'READ_ERROR',
        whatWasNotVerified: 'Um arquivo não pôde ser lido e ficou fora da análise.',
        fileCount: 1,
        files: [er.caminho],
        reasons: ['READ_ERROR'],
        detail: er.erro,
        source: 'inventory'
      }))
    ],
    decision,
    ...(claimEvidenceMap ? { claimEvidenceMap } : {}),
    // Fatia 1: identidade do motor (commit, dirty, codeDigest), opções relevantes e
    // sensores que rodaram juntos. São determinísticos para o mesmo código e as
    // mesmas opções e são materiais para a proveniência, então ficam SOB o
    // canonicalHash (revisão independente r1, achado 3: fora dele, `dirty: true`
    // podia virar `false` sem invalidar a evidência).
    ...(execucao ? {
      execution: {
        engine: execucao.engine ?? null,
        invocation: execucao.invocation ?? null,
        concurrency: execucao.concurrency ?? null
      }
    } : {})
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
    scope: target,
    algorithm: 'SHA-256',
    measurements: ['INICIO_EXECUCAO', 'FIM_EXECUCAO'],
    outsideTargetChanges: 'PERMITIDAS_E_ESPERADAS',
    initialDigest: integridade.digestInicial,
    finalDigest: integridade.digestFinal,
    immutable: integridade.inalterado,
    differences: integridade.diferencas || []
  };

  // 5. Declaração de Cobertura e Risco Residual
  const unexecutedChecks = [];
  if (comSegredosProprio) {
    // LC-06: working tree pelo scanner próprio; histórico pelo Gitleaks (NOT_RUN = sem histórico a varrer, não omissão).
    if (!scanners['zunvio-segredos'].disponivel) unexecutedChecks.push('zunvio-secret-detection');
    if (!['SUCCESS', 'NOT_RUN'].includes(scanners.gitleaks?.status)) unexecutedChecks.push('gitleaks-history-secret-detection');
  } else if (!scanners.gitleaks?.disponivel) unexecutedChecks.push('gitleaks-secret-detection');
  if (!scanners.semgrep?.disponivel) unexecutedChecks.push('semgrep-sast-detection');
  if (!delta.ativo) unexecutedChecks.push('git-delta-blast-radius');

  // Fatia 1: análise incompleta comprovada nunca é descrita como "100% de integridade".
  const limitacoesDeCompletude = canonicalContent.limitations.filter((l) => l.scanner);
  const arquivosIncompletos = limitacoesDeCompletude.reduce((total, l) => total + (l.where?.fileCount || 0), 0);
  const residualRiskStatement = limitacoesDeCompletude.length > 0
    ? `Risco residual existente: verificações omitidas (${unexecutedChecks.join(', ') || 'nenhuma'}), ${exclusoes.length} itens excluídos, ${achados.length} achados reportados e análise incompleta (${limitacoesDeCompletude.map((l) => `${l.scanner}: ${l.code}`).join(', ')}; ${arquivosIncompletos} arquivo(s) não verificado(s) por completo).`
    : unexecutedChecks.length > 0 || exclusoes.length > 0 || !integridade.inalterado
      ? `Risco residual existente: verificações omitidas (${unexecutedChecks.join(', ') || 'nenhuma'}), ${exclusoes.length} itens excluídos e ${achados.length} achados reportados.`
      : `Análise estática local executada com 100% de integridade. O risco residual restringe-se a vulnerabilidades de runtime e dependências de terceiros não analisadas neste lote.`;

  const coverageAndResidualRisk = {
    excludedPaths: exclusoes.map((e) => e.caminho),
    unexecutedChecks,
    residualRiskStatement
  };

  const pack = {
    versao: revisoesHumanas.length > 0 ? VERSAO_COM_REVISAO_HUMANA : (comSegredosProprio ? VERSAO_EVIDENCE_PACK : VERSAO_SEM_SEGREDOS_PROPRIO),
    target,
    canonicalHash,
    canonicalContent,
    volatileMetadata,
    integrityProof,
    decision,
    ...(claimEvidenceMap ? { claimEvidenceMap } : {}),
    // RF-08 (MASS-399): informativo, DELIBERADAMENTE fora de canonicalContent
    // (não entra no canonicalHash). dependenciasCve vem de `npm audit`, uma
    // base de CVE VIVA e mutável — o mesmo commit, escaneado em dias
    // diferentes, pode ter achados de CVE diferentes sem nenhuma mudança de
    // código. Selar isso sob o hash quebraria a garantia central do RF-09
    // (notarização/commit-binding): o mesmo código deixaria de produzir o
    // mesmo canonicalHash de forma reproduzível. Acha achado real de revisão,
    // não presunção — não fica sob o hash até (se algum dia) virar sensor
    // canônico com identidade própria versionada, como gitleaks/semgrep já são.
    ...(informativos ? {
      informativeFindings: {
        comentariosPerigosos: projetarInformativo(informativos.comentariosPerigosos),
        dependenciasCve: projetarInformativo(informativos.dependenciasCve),
        frontendEnvExposure: projetarInformativo(informativos.frontendEnvExposure)
      }
    } : {}),
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
    resumoCategorias,
    achados,
    // Propriedades de compatibilidade para relatórios CLI existentes
    timestamp: timestampIso,
    duracaoTotalMs,
    arquivosAnalisados: inventario.contagemArquivos ?? integridade.contagemArquivos ?? 0,
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
