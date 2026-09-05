import { validarDiretorioAlvo, calcularDigestDiretorio, verificarImutabilidade } from './utils/integrity.mjs';
import { executarScannerGitleaks } from './scanners/gitleaks.mjs';
import { executarScannerSemgrep } from './scanners/semgrep.mjs';
import { obterDiffGit, resolverRefParaSha } from './delta/diff-parser.mjs';
import { calcularBlastRadius, correlacionarAchadosComDelta } from './delta/blast-radius.mjs';
import { redigirObjeto } from './utils/redactor.mjs';
import { avaliarRelatorio } from './decision/evaluator.mjs';
import { resolverContratoPublicacao, resolverEvidenciasProjeto } from './decision/context-loader.mjs';
import { construirMapaClaimEvidence } from './decision/claim-evidence-map.mjs';
import { carregarBaseline, aplicarBaseline } from './decision/baseline.mjs';
import { gerarBadges } from './badges.mjs';
import { construirEvidencePackV0 } from './models/evidence-pack.mjs';

const ORDEM_SEVERIDADE = {
  CRITICAL: 1,
  HIGH: 2,
  MEDIUM: 3,
  LOW: 4,
  INFO: 5
};

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
 * @param {(nomeEtapa: string, estado: 'iniciando'|'concluida') => void} [opcoes.onEtapa] - Callback opcional de progresso (MASS-103); só observa, nunca decide.
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
    exclusoes,
    errosLeitura,
    limitesExcedidos,
    motivoLimite
  } = snapshotInicial;
  onEtapa('Preparação e integridade', 'concluida');

  // 3. Execução Concorrente dos Scanners Read-Only e Diff Git
  const opcoesDelta = opcoes.delta || {};
  const calcularDelta = opcoesDelta.ativo !== false;

  onEtapa('Gitleaks', 'iniciando');
  onEtapa('Semgrep', 'iniciando');
  const [resultadoGitleaks, resultadoSemgrep, resultadoDiff] = await Promise.all([
    executarScannerGitleaks(targetCanonic, opcoes.gitleaks || {}).then((r) => {
      onEtapa('Gitleaks', 'concluida');
      return r;
    }),
    executarScannerSemgrep(targetCanonic, opcoes.semgrep || {}).then((r) => {
      onEtapa('Semgrep', 'concluida');
      return r;
    }),
    calcularDelta
      ? obterDiffGit(targetCanonic, {
          baseRef: opcoesDelta.baseRef,
          headRef: opcoesDelta.headRef,
          runner: opcoesDelta.runner
        })
      : Promise.resolve({ disponivel: false, ehRepositorioGit: false, arquivosDelta: [], erro: null })
  ]);

  // 3.5. Baseline auditável (MASS-325): achados de segredo já revisados e aceitos
  // por humano (fingerprint + autor + data + justificativa) não contam para o
  // portão de decisão nem para o score. A evidência original nunca é descartada,
  // só fica fora da contagem que bloqueia — auditável em `suprimidosPorBaseline`.
  const baselineGitleaks = carregarBaseline(targetCanonic);
  const { achadosRestantes: achadosGitleaksRestantes, suprimidos: gitleaksSuprimidos } = baselineGitleaks.erro
    ? { achadosRestantes: resultadoGitleaks.achados, suprimidos: [] }
    : aplicarBaseline(resultadoGitleaks.achados, baselineGitleaks);

  // 4. Agregação e Ordenação Determinística dos Achados
  const todosAchados = [...achadosGitleaksRestantes, ...resultadoSemgrep.achados];

  // Ordena por severidade (CRITICAL -> INFO) e por caminho/linha
  todosAchados.sort((a, b) => {
    const pesoA = ORDEM_SEVERIDADE[a.severity] || 99;
    const pesoB = ORDEM_SEVERIDADE[b.severity] || 99;
    if (pesoA !== pesoB) return pesoA - pesoB;
    if (a.filePath !== b.filePath) return a.filePath.localeCompare(b.filePath);
    return a.startLine - b.startLine;
  });

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

  for (const achado of achadosCorrelacionados) {
    if (Object.hasOwn(resumoSeveridade, achado.severity)) {
      resumoSeveridade[achado.severity] += 1;
    }
  }

  // 7. Verificação de Imutabilidade Pós-Varredura
  const integridade = verificarImutabilidade(targetCanonic, digestInicial);
  const duracaoTotalMs = Date.now() - inicioTotal;

  // 8. Resumo dos Scanners
  const scanners = {
    gitleaks: {
      status: resultadoGitleaks.status,
      disponivel: resultadoGitleaks.disponivel,
      totalAchados: achadosGitleaksRestantes.length,
      duracaoMs: resultadoGitleaks.duracaoMs,
      erro: resultadoGitleaks.erro,
      // Escopo efetivamente varrido: working tree e/ou histórico Git (PER-207).
      escopo: resultadoGitleaks.escopo || { workingTree: false, historico: false },
      // Identidade do sensor: id, versão real, hash de configuração, digest da
      // saída normalizada e completude (MASS-97).
      identidade: resultadoGitleaks.identidade || null,
      // Achados suprimidos por baseline auditável (MASS-325): nunca escondidos,
      // só fora da contagem que bloqueia o portão.
      suprimidosPorBaseline: gitleaksSuprimidos,
      erroBaseline: baselineGitleaks.erro
    },
    semgrep: {
      status: resultadoSemgrep.status,
      disponivel: resultadoSemgrep.disponivel,
      totalAchados: resultadoSemgrep.achados.length,
      duracaoMs: resultadoSemgrep.duracaoMs,
      erro: resultadoSemgrep.erro,
      identidade: resultadoSemgrep.identidade || null
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
    integridade,
    delta: {
      ativo: calcularDelta && resultadoDiff.ehRepositorioGit,
      disponivel: resultadoDiff.disponivel,
      arquivosAlterados: resultadoDiff.arquivosDelta.length,
      erro: resultadoDiff.erro
    },
    evidencias,
    contrato
  });
  const badges = gerarBadges(avaliacao, { integridade });
  onEtapa('Decisão', 'concluida');

  // 11. Construção Formal do Evidence Pack v0
  const evidencePack = construirEvidencePackV0({
    target: targetCanonic,
    duracaoTotalMs,
    integridade: {
      ...integridade,
      contagemArquivos
    },
    scanners,
    achados: achadosCorrelacionados,
    avaliacao,
    badges,
    claimEvidenceMap,
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
    exclusoes,
    errosLeitura,
    limitesExcedidos,
    motivoLimite,
    resumoSeveridade
  });

  const relatorioRedigido = redigirObjeto(evidencePack);
  return Object.freeze(relatorioRedigido);
}
