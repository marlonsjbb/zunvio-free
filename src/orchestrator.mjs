import { validarDiretorioAlvo, calcularDigestDiretorio, verificarImutabilidade } from './utils/integrity.mjs';
import { executarSensorSegredos } from './scanners/segredos.mjs';
import { executarScannerSemgrep } from './scanners/semgrep.mjs';
import { executarScannerComentariosPerigosos } from './scanners/dangerous-comments.mjs';
import { executarScannerDependencias } from './scanners/dependency-audit.mjs';
import { executarScannerExposicaoEnvFrontend } from './scanners/frontend-env-exposure.mjs';
import { obterDiffGit, resolverRefParaSha } from './delta/diff-parser.mjs';
import { calcularBlastRadius, correlacionarAchadosComDelta } from './delta/blast-radius.mjs';
import { redigirObjeto } from './utils/redactor.mjs';
import { avaliarRelatorio } from './decision/evaluator.mjs';
import { carregarBaseline, aplicarBaseline } from './decision/baseline.mjs';
import { aplicarRevisoesHumanas } from './models/human-review.mjs';
import { montarIdentidadeSemgrep } from './scanners/semgrep.mjs';
import { resolverContratoPublicacao, resolverEvidenciasProjeto } from './decision/context-loader.mjs';
import { construirMapaClaimEvidence } from './decision/claim-evidence-map.mjs';
import { construirEvidencePackV0 } from './models/evidence-pack.mjs';
import { completudeNaoAvaliada } from './models/completeness.mjs';
import { identidadeDoMotor } from './utils/engine-identity.mjs';
import {
  CATEGORIAS_ACHADO,
  achadoBloqueiaCodigoProprio,
  compararAchadosNormalizados
} from './models/finding.mjs';
import { criarInventarioScanner } from './scan-inventory.mjs';
import { contarSignificados } from './models/finding-meaning.mjs';

function derivarEstadoOperacional(resultado, provisionamento = {}) {
  if (resultado.status === 'SUCCESS') return 'EXECUTADO';
  // LC-06: alvo sem histórico Git a varrer (ou subdiretório de repositório) — o Gitleaks não tinha o que executar.
  if (resultado.status === 'NOT_RUN') return 'NAO_EXECUTADO';
  if (provisionamento.motivo === 'RECUSADO_PELO_USUARIO') return 'RECUSADO_PELO_USUARIO';
  if (provisionamento.motivo === 'FALHA_DE_PROVISIONAMENTO') return 'FALHA_DE_EXECUCAO';
  if (resultado.status === 'UNAVAILABLE') return 'INDISPONIVEL';
  return 'FALHA_DE_EXECUCAO';
}

function resumirSeveridades(achados) {
  const resumo = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const achado of achados) {
    if (Object.hasOwn(resumo, achado.severity)) resumo[achado.severity] += 1;
  }
  return resumo;
}

/**
 * Orquestra a análise de segurança estática local em modo estritamente read-only e gera o Evidence Pack v0.
 * @param {string} targetPath - Caminho do diretório a analisar.
 * @param {object} [opcoes={}] - Opções customizadas de execução.
 * @param {object} [opcoes.gitleaks] - Opções para o scanner Gitleaks.
 * @param {object} [opcoes.semgrep] - Opções para o scanner Semgrep.
 * @param {object} [opcoes.delta] - Opções para análise de Git diff e blast radius.
 * @param {boolean} [opcoes.delta.ativo=true] - Se deve calcular diff delta.
 * @param {string} [opcoes.delta.baseRef] - Referência base (ex: 'main', 'HEAD~1').
 * @param {string} [opcoes.delta.headRef] - Referência de destino (ex: 'HEAD').
 * @param {Function} [opcoes.delta.runner] - Injeção de runner para testes.
 * @param {object} [opcoes.limites] - Limites defensivos customizados.
 * @param {object} [opcoes.evidencias] - Evidências externas para avaliação dos portões.
 * @param {string} [opcoes.caminhoEvidencias] - Caminho de arquivo JSON com evidências.
 * @param {object} [opcoes.contrato] - Contrato de publicação para o projeto.
 * @param {string} [opcoes.caminhoContrato] - Caminho de arquivo JSON com contrato.
 * @param {Function} [opcoes.provisionarMotores] - Provisiona motores depois do primeiro snapshot de integridade.
 * @param {(nomeEtapa: string, estado: 'iniciando'|'concluida') => void} [opcoes.onEtapa] - Callback opcional de progresso (MASS-103); só observa, nunca decide.
 * @param {boolean} [opcoes.ativarInformativos=false] - RF-08 (MASS-399): liga os sensores informativos (comentário perigoso, CVE/dependência, env var no frontend). Opt-in de propósito — não afetam score/portões em nenhum dos dois estados, mas rodam subprocesso real (npm/semgrep) e não devem ligar sozinhos em chamador que não pediu (ex.: suíte de testes existente). O CLI real (`zunvio analyze`) liga por padrão.
 * @returns {Promise<object>} Evidence Pack v0 sanitizado e validado com comprovação de integridade e delta.
 */
export async function executarAnaliseProjeto(targetPath, opcoes = {}) {
  // Callback opcional de progresso por etapa (MASS-103, comentário 8): só
  // reflete etapas reais já executadas abaixo, nunca decide nem altera
  // avaliação/score. Ausente por padrão (no-op) — nenhum caminho existente
  // muda de comportamento quando o chamador não fornece `opcoes.onEtapa`.
  const onEtapa = typeof opcoes.onEtapa === 'function' ? opcoes.onEtapa : () => {};
  const inicioTotal = Date.now();

  onEtapa('Preparação e integridade', 'iniciando');
  // 1. Validação estrita do diretório-alvo com realpath e rejeição de symlink na raiz
  const targetCanonic = validarDiretorioAlvo(targetPath);

  // 2. Snapshot de Integridade Pré-Varredura com limites defensivos
  const snapshotInicial = calcularDigestDiretorio(targetCanonic, opcoes.limites || {});
  const {
    digest: digestInicial,
    contagemArquivos,
    errosLeitura,
    limitesExcedidos,
    motivoLimite
  } = snapshotInicial;

  // Provisionamento é deliberadamente posterior à primeira medição. Além de
  // seus subprocessos trabalharem fora do alvo, esta ordem garante que uma
  // regressão futura que escreva no projeto seja detectada no snapshot final.
  const provisionamentoAutomatico = typeof opcoes.provisionarMotores === 'function'
    ? (await opcoes.provisionarMotores()) || {}
    : {};
  const provisionamento = {
    ...provisionamentoAutomatico,
    ...(opcoes.provisionamento || {})
  };
  const inventarioScanner = criarInventarioScanner(targetCanonic, {
    includeVendor: opcoes.includeVendor === true,
    limites: opcoes.limites || {}
  });
  onEtapa('Preparação e integridade', 'concluida');

  // 3. Execução Concorrente dos Scanners Read-Only e Diff Git
  const opcoesDelta = opcoes.delta || {};
  const calcularDelta = opcoesDelta.ativo !== false;

  onEtapa('Segredos', 'iniciando');
  onEtapa('Semgrep', 'iniciando');
  const ativarInformativos = opcoes.ativarInformativos === true;
  let resultadosExecucao;
  try {
    // RF-08 (MASS-399): os 3 sensores informativos (comentário perigoso, CVE/
    // dependência, env var no frontend) rodam na MESMA leva concorrente dos
    // sensores canônicos — mesma cópia read-only do alvo, sem esperar a leva
    // canônica terminar primeiro. O resultado não entra em
    // scanners/avaliação/gates: informativo por decisão explícita
    // (docs/checkpoints/MASS-399-preflight-rf08-09-11.md). Opt-in
    // (`ativarInformativos`) pra não ligar sozinho num chamador que não pediu
    // (ex.: suíte de testes existente, que não injeta runner fake pra eles).
    resultadosExecucao = await Promise.all([
      // LC-06: working tree pelo scanner próprio (inventário do ZUNVIO) + histórico Git pelo Gitleaks.
      executarSensorSegredos(targetCanonic, {
        inventario: inventarioScanner,
        includeVendor: opcoes.includeVendor === true,
        gitleaks: opcoes.gitleaks || {}
      }).then((r) => {
        onEtapa('Segredos', 'concluida');
        return r;
      }),
      executarScannerSemgrep(targetCanonic, {
        ...(opcoes.semgrep || {}),
        sourcePath: inventarioScanner.raiz,
        // PL-02: o inventário é o universo esperado contra o qual a análise efetiva é comparada.
        inventario: inventarioScanner
      }).then((r) => {
        onEtapa('Semgrep', 'concluida');
        return r;
      }),
      calcularDelta
        ? obterDiffGit(targetCanonic, {
            baseRef: opcoesDelta.baseRef,
            headRef: opcoesDelta.headRef,
            runner: opcoesDelta.runner
          })
        : Promise.resolve({ disponivel: false, ehRepositorioGit: false, arquivosDelta: [], erro: null }),
      ativarInformativos
        ? Promise.resolve(executarScannerComentariosPerigosos(inventarioScanner))
        : Promise.resolve(null),
      ativarInformativos
        ? Promise.resolve(executarScannerDependencias(inventarioScanner, opcoes.dependenciasCve || {}))
        : Promise.resolve(null),
      ativarInformativos
        ? executarScannerExposicaoEnvFrontend(targetCanonic, inventarioScanner, opcoes.frontendEnvExposure || {})
        : Promise.resolve(null)
    ]);
  } finally {
    inventarioScanner.limpar();
  }
  const [
    resultadoSegredos,
    resultadoSemgrepBruto,
    resultadoDiff,
    resultadoComentarios,
    resultadoDependencias,
    resultadoFrontendEnv
  ] = resultadosExecucao;

  // E2E mínimo: revisões humanas registradas no .zunvio-baseline.json (tipo "revisao") aplicadas aos achados de
  // código. A revisão ACEITA marca o achado (continua selado e visível) e ele deixa de bloquear; obsoleta, não aplicável
  // ou sem achado não tem efeito — todas ficam registradas no Evidence Pack.
  const baselineProjeto = carregarBaseline(targetCanonic);
  const { revisoes: revisoesHumanas, aceitaPorAchado } = baselineProjeto.erro
    ? { revisoes: [], aceitaPorAchado: new Map() }
    : aplicarRevisoesHumanas(resultadoSemgrepBruto.achados, baselineProjeto.revisoes);
  const achadosSemgrepRevisados = resultadoSemgrepBruto.achados.map((a) => (aceitaPorAchado.has(a) ? Object.freeze({ ...a, revisaoHumana: aceitaPorAchado.get(a) }) : a));
  // O achado revisado é selado com a revisão, então o digest do sensor é recalculado sobre os achados como selados.
  const resultadoSemgrep = aceitaPorAchado.size === 0 ? resultadoSemgrepBruto : {
    ...resultadoSemgrepBruto,
    achados: achadosSemgrepRevisados,
    identidade: resultadoSemgrepBruto.identidade ? montarIdentidadeSemgrep({
      versao: resultadoSemgrepBruto.identidade.versao,
      configHash: resultadoSemgrepBruto.identidade.configHash,
      status: resultadoSemgrepBruto.status,
      achados: achadosSemgrepRevisados
    }) : resultadoSemgrepBruto.identidade
  };

  // 4. Agregação e Ordenação Determinística dos Achados
  const { arvore: resultadoArvore, historico: resultadoGitleaks } = resultadoSegredos;
  const todosAchados = [...resultadoArvore.achados, ...resultadoGitleaks.achados, ...resultadoSemgrep.achados];

  // Ordena por severidade (CRITICAL -> INFO) e por caminho/linha
  todosAchados.sort(compararAchadosNormalizados);

  // 5. Correlação de Achados com o Delta Git e Cálculo de Blast Radius
  const blastRadius = calcularBlastRadius(resultadoDiff.arquivosDelta);
  const { achadosCorrelacionados, resumoDelta } = correlacionarAchadosComDelta(
    todosAchados,
    resultadoDiff.arquivosDelta
  );

  // 6. Contagem por Severidade
  const resumoSeveridade = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0
  };
  const resumoCategorias = Object.fromEntries(
    Object.values(CATEGORIAS_ACHADO).map((categoria) => [categoria, 0])
  );

  for (const achado of achadosCorrelacionados) {
    if (Object.hasOwn(resumoSeveridade, achado.severity)) {
      resumoSeveridade[achado.severity] += 1;
    }
    if (Object.hasOwn(resumoCategorias, achado.categoria)) {
      resumoCategorias[achado.categoria] += 1;
    }
  }

  // 7. Verificação de Imutabilidade Pós-Varredura
  const integridade = verificarImutabilidade(targetCanonic, digestInicial, opcoes.limites || {});
  const duracaoTotalMs = Date.now() - inicioTotal;

  // 8. Resumo dos Scanners
  // Baseline (MASS-325): achados de segredo já revisados e aceitos por humano não
  // contam para o portão de decisão, mas a evidência original permanece intacta em
  // `todosAchados`/`achadosCorrelacionados` (agregados no passo 4, antes deste
  // ponto) — só a contagem usada pelo avaliador é afetada.
  const baselineSegredos = baselineProjeto;
  const achadosSemgrepBloqueantes = resultadoSemgrep.achados.filter(achadoBloqueiaCodigoProprio);
  const estadoSemgrep = derivarEstadoOperacional(resultadoSemgrep, provisionamento.semgrep);

  // LC-06: as duas partes do sensor de segredos (working tree = scanner próprio; histórico = Gitleaks), cada uma com
  // identidade, cobertura e contagem próprias. Baseline (MASS-325) vale para as duas e fica SELADA (contagem): pela
  // decisão LC-06, achado suprimido pela baseline do próprio projeto nunca sustenta ATENDE (portão NAO_COMPROVADO).
  const resumoSegredos = (resultado, provisionamentoSensor, extra) => {
    const { achadosRestantes, suprimidos } = baselineSegredos.erro
      ? { achadosRestantes: resultado.achados, suprimidos: [] }
      : aplicarBaseline(resultado.achados, baselineSegredos);
    const bloqueantes = achadosRestantes.filter(achadoBloqueiaCodigoProprio);
    const estado = derivarEstadoOperacional(resultado, provisionamentoSensor);
    return {
      status: resultado.status,
      disponivel: resultado.disponivel,
      estadoOperacional: estado,
      resultadoSeguranca: estado === 'EXECUTADO' ? (
        achadosRestantes.length > 0 ? 'ACHADOS_DETECTADOS' : 'SEM_ACHADOS_DETECTADOS'
      ) : 'NAO_AVALIADO',
      totalAchados: achadosRestantes.length,
      totalAchadosBloqueantes: bloqueantes.length,
      significadosBloqueantes: contarSignificados(bloqueantes),
      totalAchadosInformativos: achadosRestantes.length - bloqueantes.length,
      // PL-03: contagem por significado (RISCO_DEMONSTRADO / REVISAO_NECESSARIA / INFORMATIVO), para o portão
      // explicar POR QUE bloqueia ou não bloqueia.
      significados: contarSignificados(achadosRestantes),
      resumoSeveridade: resumirSeveridades(achadosRestantes),
      duracaoMs: resultado.duracaoMs,
      erro: resultado.erro,
      completude: resultado.completude,
      // Identidade do sensor: id, versão real, hash de configuração, digest da saída normalizada e completude (MASS-97).
      identidade: resultado.identidade || null,
      // Achados suprimidos por baseline auditável (MASS-325): nunca escondidos, só fora da contagem que bloqueia.
      suprimidosPorBaseline: suprimidos,
      suprimidosBloqueantesPorBaseline: suprimidos.filter((s) => achadoBloqueiaCodigoProprio(s.achado)).length,
      erroBaseline: baselineSegredos.erro,
      ...extra
    };
  };

  const scanners = {
    'zunvio-segredos': resumoSegredos(resultadoArvore, { motivo: null }, { detalheCobertura: resultadoArvore.detalheCobertura }),
    gitleaks: resumoSegredos(resultadoGitleaks, provisionamento.gitleaks, {}),
    semgrep: {
      status: resultadoSemgrep.status,
      disponivel: resultadoSemgrep.disponivel,
      estadoOperacional: estadoSemgrep,
      resultadoSeguranca: estadoSemgrep === 'EXECUTADO' ? (
        resultadoSemgrep.achados.length > 0 ? 'ACHADOS_DETECTADOS' : 'SEM_ACHADOS_DETECTADOS'
      ) : 'NAO_AVALIADO',
      totalAchados: resultadoSemgrep.achados.length,
      totalAchadosBloqueantes: achadosSemgrepBloqueantes.length,
      totalAchadosInformativos: resultadoSemgrep.achados.length - achadosSemgrepBloqueantes.length,
      significados: contarSignificados(resultadoSemgrep.achados),
      // Só os achados que bloqueiam (código próprio, significado não INFORMATIVO), para o portão contar o risco
      // demonstrado entre ELES — um RISCO_DEMONSTRADO em node_modules não bloqueia.
      significadosBloqueantes: contarSignificados(achadosSemgrepBloqueantes),
      // E2E mínimo: achados que deixaram de bloquear por revisão humana ACEITA (a decisão precisa dizer isso).
      revisadosPorHumano: resultadoSemgrep.achados.filter((a) => a.revisaoHumana?.estado === 'ACEITA').length,
      // Baseline recusado (JSON inválido ou entrada fora do modelo): nenhuma revisão aplicada — e o usuário precisa saber.
      erroBaseline: baselineProjeto.erro,
      resumoSeveridade: resumirSeveridades(resultadoSemgrep.achados),
      duracaoMs: resultadoSemgrep.duracaoMs,
      erro: resultadoSemgrep.erro,
      identidade: resultadoSemgrep.identidade || null,
      // Fatia 1: completude derivada dos sinais brutos do Semgrep (`errors`,
      // `paths.scanned`). Scanner que não informa completude vira UNKNOWN.
      completude: resultadoSemgrep.completude || completudeNaoAvaliada(resultadoSemgrep.status),
      // E2E mínimo: arquivo/linha/trecho da leitura parcial, só para explicar ao usuário (não selado).
      leituraParcial: Array.isArray(resultadoSemgrep.leituraParcial) ? resultadoSemgrep.leituraParcial : []
    }
  };

  // 9. Resolução de Proveniência Git Real, Contrato e Evidências
  onEtapa('Contexto (contrato e evidências)', 'iniciando');
  let commitReal = null;
  if (resultadoDiff.ehRepositorioGit) {
    try {
      commitReal = resolverRefParaSha(targetCanonic, 'HEAD', opcoesDelta.runner);
    } catch {}
  }

  const contrato = resolverContratoPublicacao(targetCanonic, opcoes, { commitReal });
  const evidencias = resolverEvidenciasProjeto(targetCanonic, opcoes, commitReal);
  const claimEvidenceMap = construirMapaClaimEvidence({ contrato, evidencias });
  onEtapa('Contexto (contrato e evidências)', 'concluida');

  // 10. Avaliação de Portões e Badges
  onEtapa('Decisão', 'iniciando');
  const avaliacao = avaliarRelatorio({
    scanners,
    // PL-01/PL-04: o portão de integridade precisa saber que o snapshot cobriu só parte do projeto.
    integridade: { ...integridade, limitesExcedidos, motivoLimite },
    delta: {
      ativo: calcularDelta && resultadoDiff.ehRepositorioGit,
      disponivel: resultadoDiff.disponivel,
      arquivosAlterados: resultadoDiff.arquivosDelta.length,
      erro: resultadoDiff.erro
    },
    evidencias,
    contrato
  });
  onEtapa('Decisão', 'concluida');

  // 11. Construção Formal do Evidence Pack v0
  const evidencePack = construirEvidencePackV0({
    target: targetCanonic,
    duracaoTotalMs,
    integridade: {
      ...integridade,
      contagemArquivos
    },
    inventario: {
      contagemArquivos: inventarioScanner.contagemArquivos,
      digest: inventarioScanner.digest
    },
    scanners,
    achados: achadosCorrelacionados,
    revisoesHumanas,
    avaliacao,
    claimEvidenceMap,
    informativos: ativarInformativos ? {
      comentariosPerigosos: resultadoComentarios,
      dependenciasCve: resultadoDependencias,
      frontendEnvExposure: resultadoFrontendEnv
    } : null,
    delta: {
      ativo: calcularDelta && resultadoDiff.ehRepositorioGit,
      ehRepositorioGit: resultadoDiff.ehRepositorioGit,
      baseRef: opcoesDelta.baseRef || null,
      headRef: opcoesDelta.headRef || null,
      arquivosAlterados: resultadoDiff.arquivosDelta.length,
      blastRadius,
      resumoAchadosDelta: resumoDelta,
      arquivos: resultadoDiff.arquivosDelta,
      erro: resultadoDiff.erro
    },
    exclusoes: inventarioScanner.exclusoes,
    errosLeitura: [...errosLeitura, ...inventarioScanner.errosLeitura],
    limitesExcedidos,
    motivoLimite,
    resumoSeveridade,
    resumoCategorias,
    // Fatia 1: o que é preciso para reconstruir a execução (fora do canonicalHash).
    execucao: {
      engine: identidadeDoMotor(),
      invocation: {
        informativeSensors: ativarInformativos,
        delta: calcularDelta,
        includeVendor: opcoes.includeVendor === true,
        publicationContract: Boolean(opcoes.caminhoContrato),
        projectEvidence: Boolean(opcoes.caminhoEvidencias)
      },
      // Sensores disparados na MESMA leva concorrente (Promise.all acima). Não é
      // medida de carga: é o fato de quais sensores disputaram a máquina juntos.
      concurrency: {
        parallelBatch: [
          'zunvio-segredos',
          'gitleaks(historico)',
          'semgrep',
          ...(calcularDelta ? ['git-diff'] : []),
          ...(ativarInformativos ? ['dangerous-comments', 'dependency-audit', 'frontend-env-exposure(semgrep)'] : [])
        ],
        externalProcessesInBatch: ativarInformativos ? ['git', 'gitleaks', 'semgrep', 'npm-audit', 'semgrep(frontend-env-exposure)'] : ['git', 'gitleaks', 'semgrep']
      }
    }
  });

  const relatorioRedigido = redigirObjeto(evidencePack);
  return Object.freeze(relatorioRedigido);
}
