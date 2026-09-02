import { existsSync, readFileSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { executarProcessoSeguro } from '../utils/process-runner.mjs';
import { criarAchadoNormalizado, projetarAchadoCanonico } from '../models/finding.mjs';
import {
  classificarCompletude,
  calcularDigestCanonico,
  extrairVersaoSemver,
  hashTexto
} from '../models/sensor-identity.mjs';

/**
 * Opções de `git log` repassadas ao Gitleaks na varredura de histórico.
 * Fixadas para leitura estritamente passiva: sem diff externo e sem textconv, para
 * que nenhum comando declarado na configuração do repositório-alvo (`diff.external`,
 * `GIT_EXTERNAL_DIFF`, filtros de `.gitattributes`) seja executado durante a leitura.
 * Mesma postura defensiva já adotada em `src/delta/diff-parser.mjs`.
 */
const OPCOES_LOG_HISTORICO = '--no-ext-diff --no-textconv';

// Ruleset versionado e auditável que o Gitleaks efetivamente usa (B5). O hash
// deste arquivo é o configHash da identidade do sensor — não uma string fabricada
// de nome/versão.
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REGRA_GITLEAKS_LOCAL = resolve(__dirname, '../../rules/gitleaks/gitleaks.toml');

function configHashGitleaks() {
  try {
    return hashTexto(readFileSync(REGRA_GITLEAKS_LOCAL, 'utf8'));
  } catch {
    return null; // NÃO COMPROVADO quando o ruleset não pode ser lido (B5)
  }
}

/**
 * Monta a identidade canônica do sensor Gitleaks: id, versão real do binário,
 * hash do ruleset efetivamente usado, digest da saída normalizada e estado de
 * completude. Nada é inventado: versão vem do binário, configHash vem do arquivo
 * de regras realmente passado ao Gitleaks, digests são determinísticos.
 */
function montarIdentidadeGitleaks({ versao, status, achados }) {
  return Object.freeze({
    id: 'gitleaks',
    versao: versao ?? null,
    // configHash só é preenchido quando o sensor concluiu (config efetivamente
    // usada); sem execução, permanece NÃO COMPROVADO (null) — B5.
    configHash: status === 'SUCCESS' ? configHashGitleaks() : null,
    findingsDigest: status === 'SUCCESS' ? calcularDigestCanonico(achados.map(projetarAchadoCanonico)) : null,
    completion: classificarCompletude(status, achados.length)
  });
}

/** Lê um campo do achado bruto do Gitleaks aceitando as duas grafias (PascalCase / camelCase). */
function campoBruto(vazamento, pascal, camel) {
  const v = vazamento[pascal] ?? vazamento[camel];
  return v === undefined ? null : v;
}

/**
 * Caminho do achado relativo à raiz do alvo, na forma canônica (barra normal).
 * A passada de working tree (`--no-git` com `--source` absoluto) reporta `File`
 * como caminho absoluto; a de histórico (`git log`) reporta relativo à raiz do
 * repositório. Sem esta normalização a chave de localização não casaria entre as
 * duas passadas e o mesmo segredo seria contado duas vezes.
 */
function caminhoRelativoAlvo(vazamento, raizAlvo) {
  const bruto = campoBruto(vazamento, 'File', 'file') || '';
  if (!raizAlvo) return bruto.replace(/\\/g, '/');
  return relative(raizAlvo, resolve(raizAlvo, bruto)).replace(/\\/g, '/');
}

/**
 * Chave de localização de um achado: regra + arquivo (relativo) + faixa de linha
 * + faixa de coluna. NÃO inclui o commit — é o agrupador dentro do qual se decide
 * o que é a mesma evidência entre as passadas de working tree e de histórico.
 */
function chaveLocalizacao(vazamento, raizAlvo) {
  // JSON garante fronteira de campo inequivoca, sem depender de um separador que
  // pudesse aparecer numa regra ou num caminho.
  return JSON.stringify([
    campoBruto(vazamento, 'RuleID', 'ruleId') || 'generic-secret',
    caminhoRelativoAlvo(vazamento, raizAlvo),
    campoBruto(vazamento, 'StartLine', 'startLine') ?? 1,
    campoBruto(vazamento, 'EndLine', 'endLine') ?? campoBruto(vazamento, 'StartLine', 'startLine') ?? 1,
    campoBruto(vazamento, 'StartColumn', 'startColumn') ?? '-',
    campoBruto(vazamento, 'EndColumn', 'endColumn') ?? '-'
  ]);
}

/** Instante numérico de uma data ISO/RFC 3339, respeitando o offset. NaN vira -Infinity. */
function instanteDe(vazamento) {
  const bruto = campoBruto(vazamento, 'Date', 'date') || '';
  const t = Date.parse(bruto);
  return Number.isNaN(t) ? Number.NEGATIVE_INFINITY : t;
}

/**
 * Trecho `[inicio..fim]` (1-based, inclusivo) de um arquivo de linhas, ou null. Um span
 * cujo início já passa do fim do arquivo devolve null (não string vazia) — assim uma
 * comparação de dois trechos ausentes NÃO conta como "igual".
 */
function trechoDeLinhas(linhas, inicio, fim) {
  if (!Array.isArray(linhas)) return null;
  const i = Math.max(1, Number(inicio) || 1);
  const f = Math.max(i, Number(fim) || i);
  if (i > linhas.length) return null;
  return linhas.slice(i - 1, f).join('\n');
}

/**
 * Resolve os achados brutos das duas passadas (working tree + histórico) num
 * conjunto sem duplicatas espúrias, preservando achados genuinamente distintos e
 * a proveniência de cada um. Corrige o P2 da PER-207 (Codex): a deduplicação
 * anterior colapsava por regra/arquivo/linha, agrupando credenciais diferentes no
 * mesmo lugar e descartando proveniência de commit.
 *
 * Regras:
 *  - identidade de um achado = (regra, arquivo, faixa de linha, faixa de coluna, commit);
 *  - dentro de uma localização, cada commit distinto é um achado distinto
 *    (credencial rotacionada no mesmo lugar é preservada, com seu commit);
 *  - um achado de working tree só é fundido a um de histórico quando há **prova**
 *    de que é o mesmo segredo: (a) o trecho da linha no working tree é idêntico ao
 *    de `HEAD`, provando que o segredo atual está commitado; e (b) existe um achado
 *    de histórico cujo commit tem, nesse mesmo trecho, exatamente o conteúdo de
 *    `HEAD` — é a esse commit que a proveniência de working tree é anexada. A data
 *    do commit NÃO decide isso (datas Git não são monótonas: clock skew, rebase,
 *    `--date` explícito) — só o conteúdo (revisão do Codex R2). Sem qualquer das
 *    duas provas, o achado de working tree fica SEPARADO, nunca colapsado sobre um
 *    commit ao qual pode não pertencer.
 *
 * @param {object[]} vazamentosBrutos - achados JSON crus das duas passadas, agregados.
 * @param {string} [raizAlvo] - raiz do alvo, para casar o caminho entre as passadas.
 * @param {(ref: string, arquivoRelativo: string) => string[] | null} [lerLinhasDeRef] -
 *   devolve o conteúdo de um arquivo numa ref Git (`'HEAD'` ou um SHA de commit) como
 *   lista de linhas, ou null se indisponível.
 * @returns {object[]} lista resolvida de achados crus, cada um com `__origem` definido.
 */
export function deduplicarAchadosGitleaks(vazamentosBrutos, raizAlvo, lerLinhasDeRef) {
  if (!Array.isArray(vazamentosBrutos)) return [];

  const commitDe = (v) => campoBruto(v, 'Commit', 'commit') || '';
  const spanDe = (v) => [
    campoBruto(v, 'StartLine', 'startLine') ?? 1,
    campoBruto(v, 'EndLine', 'endLine') ?? campoBruto(v, 'StartLine', 'startLine') ?? 1
  ];

  const cacheRef = new Map();
  const linhasDeRef = (ref, arquivoRel) => {
    if (typeof lerLinhasDeRef !== 'function') return null;
    const chave = JSON.stringify([ref, arquivoRel]);
    if (!cacheRef.has(chave)) {
      let r = null;
      try {
        r = lerLinhasDeRef(ref, arquivoRel);
      } catch {
        r = null;
      }
      cacheRef.set(chave, Array.isArray(r) ? r : null);
    }
    return cacheRef.get(chave);
  };
  const cacheWt = new Map();
  const linhasWt = (arquivoRel) => {
    if (!raizAlvo) return null;
    if (!cacheWt.has(arquivoRel)) {
      let r = null;
      try {
        r = readFileSync(join(raizAlvo, arquivoRel), 'utf8').split(/\r?\n/);
      } catch {
        r = null;
      }
      cacheWt.set(arquivoRel, r);
    }
    return cacheWt.get(arquivoRel);
  };

  const grupos = new Map();
  for (const v of vazamentosBrutos) {
    const chave = chaveLocalizacao(v, raizAlvo);
    if (!grupos.has(chave)) grupos.set(chave, { historico: new Map(), workingTree: [] });
    const grupo = grupos.get(chave);
    const commit = commitDe(v);
    if (commit) {
      if (!grupo.historico.has(commit)) grupo.historico.set(commit, v);
    } else {
      grupo.workingTree.push(v);
    }
  }

  const resolvidos = [];
  for (const grupo of grupos.values()) {
    // Ordem só para saída determinística (instante real, desempate por SHA). NÃO decide
    // fusão — isso é por conteúdo (abaixo).
    const historicos = [...grupo.historico.values()].sort((a, b) => {
      const ia = instanteDe(a);
      const ib = instanteDe(b);
      if (ia !== ib) return ib - ia;
      return commitDe(b).localeCompare(commitDe(a));
    });
    const wt = grupo.workingTree[0] || null; // `--no-git` varre o arquivo uma vez

    if (historicos.length === 0) {
      if (wt) resolvidos.push({ ...wt, __origem: 'working-tree' });
      continue;
    }

    // Qual achado de histórico recebe a proveniência de working tree? Só aquele cujo
    // commit tem, no trecho, exatamente o que está em HEAD — e só se o working tree
    // também bate com HEAD (o segredo atual está commitado). Prova por CONTEÚDO, nunca
    // por data (revisão do Codex R2).
    let alvoFusao = null;
    if (wt) {
      const arquivoRel = caminhoRelativoAlvo(wt, raizAlvo);
      const [ini, fim] = spanDe(wt);
      const noWt = trechoDeLinhas(linhasWt(arquivoRel), ini, fim);
      const noHead = trechoDeLinhas(linhasDeRef('HEAD', arquivoRel), ini, fim);
      if (noWt !== null && noHead !== null && noWt === noHead) {
        for (const h of historicos) {
          const noCommit = trechoDeLinhas(linhasDeRef(commitDe(h), arquivoRel), ini, fim);
          if (noCommit !== null && noCommit === noHead) {
            alvoFusao = h;
            break;
          }
        }
      }
    }

    for (const h of historicos) {
      resolvidos.push({ ...h, __origem: h === alvoFusao ? 'working-tree+historico' : 'historico' });
    }
    if (wt && !alvoFusao) {
      resolvidos.push({ ...wt, __origem: 'working-tree' });
    }
  }
  return resolvidos;
}

/**
 * Mapeia o resultado bruto do Gitleaks para o schema unificado do ZUNVIO.
 * @param {object[]} vazamentosBrutos - Lista de achados em formato JSON do Gitleaks.
 * @param {string} raizAlvo - Caminho raiz do projeto analisado.
 * @returns {Array<ReturnType<typeof criarAchadoNormalizado>>}
 */
export function normalizarAchadosGitleaks(vazamentosBrutos, raizAlvo) {
  if (!Array.isArray(vazamentosBrutos)) return [];

  return vazamentosBrutos.map((vazamento) => {
    const ruleId = campoBruto(vazamento, 'RuleID', 'ruleId') || 'generic-secret';
    const descricao = campoBruto(vazamento, 'Description', 'description') || 'Segredo detectado em código-fonte';
    const arquivoBruto = campoBruto(vazamento, 'File', 'file') || '';
    const caminhoRelativo = relative(raizAlvo, resolve(raizAlvo, arquivoBruto)).replace(/\\/g, '/');

    // Determina a severidade baseado na regra
    let severity = 'HIGH';
    const ruleLower = ruleId.toLowerCase();
    if (ruleLower.includes('private-key') || ruleLower.includes('aws') || ruleLower.includes('github-pat')) {
      severity = 'CRITICAL';
    }

    const startLine = campoBruto(vazamento, 'StartLine', 'startLine') ?? 1;
    const endLine = campoBruto(vazamento, 'EndLine', 'endLine') ?? startLine;
    const startColumn = campoBruto(vazamento, 'StartColumn', 'startColumn');
    const endColumn = campoBruto(vazamento, 'EndColumn', 'endColumn');
    const commit = campoBruto(vazamento, 'Commit', 'commit') || null;
    const commitDate = campoBruto(vazamento, 'Date', 'date') || null;
    // Fingerprint do próprio Gitleaks: `<commit>:<arquivo>:<regra>:<startline>` na
    // varredura de histórico e `<arquivo>:<regra>:<startline>` no working tree.
    // Nunca contém o segredo. Guardado como proveniência.
    const gitleaksFingerprint = campoBruto(vazamento, 'Fingerprint', 'fingerprint') || null;
    // `__origem` é definido por `deduplicarAchadosGitleaks`; sem ele, deriva do commit.
    const origem = vazamento.__origem || (commit ? 'historico' : 'working-tree');

    // Identidade que distingue: credencial rotacionada no mesmo lugar (commit
    // diferente) e dois segredos na mesma linha em colunas diferentes. Só dados
    // de localização/commit — nunca o segredo (PER-207, P2 do Codex).
    const identidadeExtra = [commit || 'working-tree', startColumn ?? '-', endColumn ?? '-'].join(':');

    return criarAchadoNormalizado({
      scanner: 'gitleaks',
      ruleId,
      severity,
      message: `${descricao} (${ruleId})`,
      filePath: caminhoRelativo,
      startLine,
      endLine,
      identidadeExtra,
      rawDetails: {
        commit,
        commitDate,
        gitleaksFingerprint,
        startColumn,
        endColumn,
        // 'working-tree', 'historico' ou 'working-tree+historico' (visto nas duas passadas).
        origem,
        entropy: campoBruto(vazamento, 'Entropy', 'entropy'),
        author: campoBruto(vazamento, 'Author', 'author')
      }
    });
  });
}

/**
 * Monta os argumentos do Gitleaks para uma passada de varredura.
 * Usa o subcomando `detect` (estável desde a v8.2, presente na v8.18 usada como
 * referência na PER-207; os subcomandos `git`/`dir` só existem a partir da v8.19).
 * @param {string} targetAbsoluto - Caminho canônico do projeto.
 * @param {string} reportPath - Caminho do relatório JSON temporário.
 * @param {{ historico: boolean }} passada
 * @returns {string[]}
 */
function montarArgumentos(targetAbsoluto, reportPath, { historico }) {
  const args = [
    'detect',
    '--source',
    targetAbsoluto,
    '--config',
    REGRA_GITLEAKS_LOCAL,
    '--report-format',
    'json',
    '--report-path',
    reportPath,
    '--no-banner',
    '--redact'
  ];

  if (historico) {
    // Profundidade: todo o histórico alcançável a partir do HEAD (padrão do git log -p).
    // Decisão registrada em docs/checkpoints/PER-207.md. Para restringir a profundidade
    // (ex.: '--since', '-n'), acrescentar aqui — mantendo sempre OPCOES_LOG_HISTORICO
    // como prefixo e nunca aceitando o valor a partir do projeto analisado.
    args.push('--log-opts', OPCOES_LOG_HISTORICO);
  } else {
    // Varre o working tree como diretório de arquivos, sem tocar no histórico.
    args.push('--no-git');
  }

  return args;
}

/**
 * Interpreta o resultado de uma passada do Gitleaks, distinguindo com rigor
 * "o sensor executou e concluiu a varredura" de "o sensor não conseguiu executar".
 *
 * O código de saída 1 do Gitleaks é ambíguo: significa "vazamentos encontrados"
 * numa varredura concluída, mas também é o código que o binário retorna ao abortar
 * por subcomando desconhecido ou origem inválida. A prova de conclusão é o arquivo
 * de relatório: o Gitleaks sempre o grava (ainda que `[]`) quando roda um scan, e
 * nunca o grava quando aborta antes de varrer.
 *
 * @param {{ status: string, exitCode: number | null, stderr: string }} resultado
 * @param {string} reportPath
 * @returns {{ ok: boolean, tipo: 'SUCCESS' | 'ERROR' | 'UNAVAILABLE' | 'TIMEOUT', vazamentos?: object[], erro?: string }}
 */
function interpretarResultadoScan(resultado, reportPath) {
  if (resultado.status === 'UNAVAILABLE') {
    return { ok: false, tipo: 'UNAVAILABLE', erro: resultado.stderr || 'Binário gitleaks não encontrado no PATH.' };
  }
  if (resultado.status === 'TIMEOUT') {
    return { ok: false, tipo: 'TIMEOUT', erro: resultado.stderr || 'Gitleaks excedeu o tempo limite.' };
  }
  if (resultado.status === 'BUFFER_OVERFLOW') {
    return { ok: false, tipo: 'ERROR', erro: resultado.stderr || 'Saída do Gitleaks excedeu o buffer máximo.' };
  }

  // Gitleaks: 0 = sem achados, 1 = achados. Qualquer outro código é falha de execução.
  if (resultado.exitCode !== 0 && resultado.exitCode !== 1) {
    return {
      ok: false,
      tipo: 'ERROR',
      erro: `Gitleaks encerrou com código ${resultado.exitCode}. ${(resultado.stderr || '').slice(0, 400)}`.trim()
    };
  }

  // Sem relatório após um suposto sucesso => o binário abortou antes de varrer
  // (ex.: "unknown command", origem inexistente, configuração inválida).
  if (!existsSync(reportPath)) {
    return {
      ok: false,
      tipo: 'ERROR',
      erro: `Gitleaks não produziu relatório (código ${resultado.exitCode}); a varredura não foi concluída. ${(resultado.stderr || '').slice(0, 400)}`.trim()
    };
  }

  let conteudo;
  try {
    conteudo = readFileSync(reportPath, 'utf8');
  } catch (err) {
    return { ok: false, tipo: 'ERROR', erro: `Falha ao ler o relatório do Gitleaks: ${err.message}` };
  }

  let vazamentos;
  try {
    vazamentos = conteudo.trim() ? JSON.parse(conteudo) : [];
  } catch (err) {
    return { ok: false, tipo: 'ERROR', erro: `Falha ao interpretar a saída do Gitleaks: ${err.message}` };
  }

  if (!Array.isArray(vazamentos)) {
    return { ok: false, tipo: 'ERROR', erro: 'Saída do Gitleaks não é uma lista de achados.' };
  }

  return { ok: true, tipo: 'SUCCESS', vazamentos };
}

/**
 * Determina se o alvo é a **raiz** de um repositório Git.
 *
 * A varredura de histórico só é feita quando o alvo é a raiz do repositório. Um
 * subdiretório não é um repositório: pedir a análise de um subdiretório e varrer o
 * histórico do repositório inteiro que o contém reportaria segredos de código não
 * relacionado (e tornaria o `canonicalHash` sensível a mudanças fora do alvo).
 *
 * @param {string} targetAbsoluto
 * @param {Function} runner
 * @returns {{ ehRepoRaiz: boolean, dentroDeRepo: boolean, gitDisponivel: boolean }}
 */
function detectarRepositorioGit(targetAbsoluto, runner) {
  const checagem = runner(
    'git',
    ['-C', targetAbsoluto, 'rev-parse', '--is-inside-work-tree', '--show-prefix'],
    { timeout: 5000 }
  );

  if (checagem.status === 'UNAVAILABLE') {
    // git ausente: heurística de fallback — um .git direto na raiz do alvo indica repo.
    const pareceRaiz = existsSync(join(targetAbsoluto, '.git'));
    return { ehRepoRaiz: pareceRaiz, dentroDeRepo: pareceRaiz, gitDisponivel: false };
  }

  if (checagem.status !== 'SUCCESS' || checagem.exitCode !== 0) {
    return { ehRepoRaiz: false, dentroDeRepo: false, gitDisponivel: true };
  }

  const linhas = (checagem.stdout || '').split(/\r?\n/);
  const dentroDeRepo = linhas[0]?.trim() === 'true';
  // '--show-prefix' é vazio na raiz do repositório e 'sub/dir/' num subdiretório.
  const prefixo = (linhas[1] ?? '').trim();
  return { ehRepoRaiz: dentroDeRepo && prefixo === '', dentroDeRepo, gitDisponivel: true };
}

/**
 * Executa o scanner Gitleaks sobre o alvo de forma estritamente somente leitura.
 *
 * Quando o alvo é a raiz de um repositório Git, varre o working tree E o histórico
 * completo (git log). Um segredo commitado e depois removido do working tree
 * permanece no histórico e é detectado — cenário da PER-207. Fora de um repositório
 * Git, ou quando o alvo é um subdiretório de um repositório, varre apenas o working
 * tree (ver `detectarRepositorioGit`).
 *
 * Falha de qualquer passada planejada é fail-closed: o resultado global vira
 * ERROR/UNAVAILABLE/TIMEOUT (portão "NÃO COMPROVADO"), nunca "sem achados".
 *
 * @param {string} targetPath - Caminho do projeto a ser analisado.
 * @param {object} [opcoes={}] - Opções customizadas.
 * @param {string} [opcoes.executavel='gitleaks'] - Caminho ou nome do binário.
 * @param {Function} [opcoes.runner=executarProcessoSeguro] - Função de execução (injeção em testes).
 * @param {number} [opcoes.timeout=30000] - Timeout por passada, em ms.
 * @returns {Promise<{ status: 'SUCCESS' | 'ERROR' | 'UNAVAILABLE' | 'TIMEOUT', disponivel: boolean, achados: Array<ReturnType<typeof criarAchadoNormalizado>>, duracaoMs: number, erro: string | null, escopo: { workingTree: boolean, historico: boolean } }>}
 */
export async function executarScannerGitleaks(targetPath, opcoes = {}) {
  const inicio = Date.now();
  const runner = opcoes.runner || executarProcessoSeguro;
  const executavel = opcoes.executavel || 'gitleaks';
  const timeout = opcoes.timeout || 30_000;
  const targetAbsoluto = resolve(targetPath);

  // Versão real do binário (best-effort; null quando indisponível ou sem semver).
  const resVersao = runner(executavel, ['version'], { cwd: targetAbsoluto, timeout: 15_000 });
  const versao = extrairVersaoSemver(resVersao?.stdout);

  const { ehRepoRaiz, gitDisponivel } = detectarRepositorioGit(targetAbsoluto, runner);

  const passadas = [{ chave: 'workingTree', historico: false }];
  if (ehRepoRaiz) passadas.push({ chave: 'historico', historico: true });

  const escopo = { workingTree: false, historico: false };
  const relatoriosTemp = [];
  const vazamentosAgregados = [];

  try {
    for (const passada of passadas) {
      if (passada.historico && !gitDisponivel) {
        return {
          status: 'UNAVAILABLE',
          disponivel: false,
          achados: [],
          duracaoMs: Date.now() - inicio,
          erro: 'O alvo é um repositório Git, mas o binário git não está disponível para varrer o histórico; a evidência de segredos no histórico não pôde ser produzida.',
          escopo,
          identidade: montarIdentidadeGitleaks({ versao, status: 'UNAVAILABLE', achados: [] })
        };
      }

      const reportPath = join(tmpdir(), `zunvio-gitleaks-${passada.chave}-${randomBytes(6).toString('hex')}.json`);
      relatoriosTemp.push(reportPath);

      const resultado = runner(executavel, montarArgumentos(targetAbsoluto, reportPath, passada), {
        cwd: targetAbsoluto,
        timeout
      });

      const interpretado = interpretarResultadoScan(resultado, reportPath);

      if (!interpretado.ok) {
        const contexto = passada.historico ? 'de histórico Git' : 'do working tree';
        const statusFinal = interpretado.tipo === 'SUCCESS' ? 'ERROR' : interpretado.tipo;
        return {
          status: statusFinal,
          disponivel: interpretado.tipo !== 'UNAVAILABLE',
          achados: [],
          duracaoMs: Date.now() - inicio,
          erro: `Varredura ${contexto} não concluída: ${interpretado.erro || 'motivo desconhecido'}`,
          escopo,
          identidade: montarIdentidadeGitleaks({ versao, status: statusFinal, achados: [] })
        };
      }

      escopo[passada.chave] = true;
      vazamentosAgregados.push(...interpretado.vazamentos);
    }

    // Resolve as duas passadas: preserva achados genuinamente distintos (credencial
    // rotacionada no mesmo lugar, segredos distintos na mesma linha), funde só a
    // duplicata PROVADA entre working tree e histórico (trecho da linha igual ao de
    // HEAD), e mantém a proveniência de commit (PER-207, P2 do Codex — ver
    // deduplicarAchadosGitleaks).
    const lerLinhasDeRef = (ref, arquivoRel) => {
      const r = runner('git', ['-C', targetAbsoluto, 'show', `${ref}:${arquivoRel}`], { timeout: 5000 });
      if (!r || r.status !== 'SUCCESS' || r.exitCode !== 0 || typeof r.stdout !== 'string') return null;
      return r.stdout.split(/\r?\n/);
    };
    const resolvidos = deduplicarAchadosGitleaks(vazamentosAgregados, targetAbsoluto, lerLinhasDeRef);
    const achados = normalizarAchadosGitleaks(resolvidos, targetAbsoluto);

    return {
      status: 'SUCCESS',
      disponivel: true,
      achados,
      duracaoMs: Date.now() - inicio,
      erro: null,
      escopo,
      identidade: montarIdentidadeGitleaks({ versao, status: 'SUCCESS', achados })
    };
  } finally {
    for (const reportPath of relatoriosTemp) {
      if (existsSync(reportPath)) {
        try {
          unlinkSync(reportPath);
        } catch {
          // limpeza best-effort do arquivo temporário
        }
      }
    }
  }
}
