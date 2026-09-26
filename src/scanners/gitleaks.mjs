import { existsSync, mkdirSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { executarProcessoSeguro } from '../utils/process-runner.mjs';
import {
  compararAchadosNormalizados,
  criarAchadoNormalizado,
  projetarAchadoCanonico
} from '../models/finding.mjs';
import { avaliarSignificadoSegredo } from '../models/finding-meaning.mjs';
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
// LC-06: `--text` (arquivo marcado como binário no projeto não esconde conteúdo), `--diff-merges=first-parent`
// (segredo introduzido só na resolução de um merge — perdido sem isto, sonda LC-06 12) e `-M` explícito (renomeação
// determinística, independente da configuração do usuário). O universo esperado é calculado com as MESMAS opções.
export const OPCOES_LOG_HISTORICO = '--no-ext-diff --no-textconv --text --diff-merges=first-parent -M';

const MARCADOR_PLACEHOLDER = /(?:EXAMPLE|DUMMY|FAKE|SAMPLE|PLACEHOLDER|NOTREAL|MOCK|TEST)/i;

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
export function montarIdentidadeGitleaks({ versao, status, achados, id = 'gitleaks', configHash }) {
  return Object.freeze({
    id,
    versao: versao ?? null,
    // configHash só é preenchido quando o sensor concluiu (config efetivamente
    // usada); sem execução, permanece NÃO COMPROVADO (null) — B5.
    configHash: status === 'SUCCESS' ? (configHash !== undefined ? configHash : configHashGitleaks()) : null,
    findingsDigest: status === 'SUCCESS'
      ? calcularDigestCanonico([...achados].sort(compararAchadosNormalizados).map(projetarAchadoCanonico))
      : null,
    // LC-06: NOT_RUN (alvo sem histórico a varrer) não começou nada — NOT_STARTED, nunca FAILED nem CLEAN.
    completion: status === 'NOT_RUN' ? 'NOT_STARTED' : classificarCompletude(status, achados.length)
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

function extrairIdentificadorDeclarador(linha, posicaoAchado) {
  if (/^(?:\/\/|#|\/\*|\*)/.test(linha.trimStart())) return null;

  const candidatos = [];
  const atribuicao = /\b([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+)?=(?!=)/g;
  const chaveDeObjeto = /(?:^|[,{])\s*(?:["']([^"']+)["']|([A-Za-z_$][\w$-]*))\s*:/g;

  for (const padrao of [atribuicao, chaveDeObjeto]) {
    for (const correspondencia of linha.matchAll(padrao)) {
      const identificador = correspondencia[1] || correspondencia[2];
      const indice = correspondencia.index + correspondencia[0].indexOf(identificador);
      if (indice > posicaoAchado) continue;
      candidatos.push({
        identificador,
        indice
      });
    }
  }

  candidatos.sort((a, b) => b.indice - a.indice);
  return candidatos[0]?.identificador || null;
}

function identificadorDoAchadoEhPlaceholder({ raizAlvo, arquivoBruto, startLine, startColumn, segredo }) {
  if (!raizAlvo || !arquivoBruto) return false;

  try {
    const raizReal = realpathSync(resolve(raizAlvo));
    const arquivoReal = realpathSync(resolve(raizReal, arquivoBruto));
    const caminhoDentroDaRaiz = relative(raizReal, arquivoReal);
    if (!caminhoDentroDaRaiz || /^\.\.(?:[\\/]|$)/.test(caminhoDentroDaRaiz) || isAbsolute(caminhoDentroDaRaiz)) {
      return false;
    }

    const numeroLinha = Number(startLine);
    if (!Number.isInteger(numeroLinha) || numeroLinha < 1) return false;
    const linha = readFileSync(arquivoReal, 'utf8').split(/\r?\n/)[numeroLinha - 1];
    if (linha === undefined) return false;

    const indiceSegredo = typeof segredo === 'string' && segredo ? linha.indexOf(segredo) : -1;
    const coluna = Number(startColumn);
    const posicaoAchado = indiceSegredo !== -1
      ? indiceSegredo
      : Number.isInteger(coluna) && coluna > 0
        ? Math.min(coluna - 1, linha.length)
        : null;
    if (posicaoAchado === null) return false;

    const identificador = extrairIdentificadorDeclarador(linha, posicaoAchado);
    return identificador !== null && MARCADOR_PLACEHOLDER.test(identificador);
  } catch {
    // Sem evidência local confiável, mantém a severidade original (fail-safe).
    return false;
  }
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

    const possivelPlaceholder = identificadorDoAchadoEhPlaceholder({
      raizAlvo,
      arquivoBruto,
      startLine,
      startColumn,
      segredo: campoBruto(vazamento, 'Secret', 'secret')
    });
    if (possivelPlaceholder && (severity === 'CRITICAL' || severity === 'HIGH')) {
      severity = 'LOW';
    }
    // PL-03: significado explícito (REVISAO_NECESSARIA): forma de credencial demonstrada, validade não. A mensagem
    // não afirma que o valor É uma credencial válida; o contexto do arquivo (teste/exemplo) nunca afasta um segredo.
    const significado = avaliarSignificadoSegredo({ filePath: caminhoRelativo, possivelPlaceholder });

    return criarAchadoNormalizado({
      // LC-06: quem viu o achado no estado atual dos arquivos é o scanner próprio; o que só existe no histórico é do
      // Gitleaks (a proveniência de commit fica em rawDetails nos dois casos).
      scanner: origem === 'historico' ? 'gitleaks' : 'zunvio-segredos',
      ruleId,
      severity,
      message: `${significado.explicacao} Regra: ${descricao} (${ruleId}).`,
      significado,
      filePath: caminhoRelativo,
      startLine,
      endLine,
      identidadeExtra,
      possivelPlaceholder,
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
 * Argumentos do Gitleaks para a passada de HISTÓRICO (LC-06: o working tree é do scanner próprio).
 * Usa o subcomando `detect` (estável desde a v8.2, presente na v8.18.4 fixada no bootstrap).
 * `--ignore-gitleaks-allow`: comentário `gitleaks:allow` do projeto não reduz a cobertura do auditor (decisão LC-06).
 * @param {string} fonte - clone --bare do alvo (sem working tree ⇒ sem `.gitleaksignore` do projeto na raiz).
 * @param {string} reportPath
 * @returns {string[]}
 */
function montarArgumentosHistorico(fonte, reportPath) {
  return [
    'detect',
    '--source',
    fonte,
    '--config',
    REGRA_GITLEAKS_LOCAL,
    '--report-format',
    'json',
    '--report-path',
    reportPath,
    '--no-banner',
    '--redact',
    '--ignore-gitleaks-allow',
    '--log-opts',
    OPCOES_LOG_HISTORICO
  ];
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

/** Estados da cobertura do histórico (LC-06). */
export const COBERTURA_HISTORICO = Object.freeze({
  COMPLETA: 'COMPLETE',
  DESCONHECIDA: 'UNKNOWN'
});

/** Motivos de cobertura histórica não demonstrada (conjunto fechado; o contrato 1.4.0 usa os mesmos). */
export const MOTIVO_HISTORICO = Object.freeze({
  SHALLOW: 'SHALLOW_HISTORY',
  NAO_DETERMINADO: 'HISTORY_NOT_DETERMINED',
  DIVERGENCIA: 'HISTORY_COVERAGE_MISMATCH'
});

/**
 * Commits do histórico que TÊM o que varrer, calculados pelo próprio Git com as MESMAS opções de log do Gitleaks:
 * commits alcançáveis a partir do HEAD com pelo menos uma mudança que não seja só a remoção de um arquivo. Medido
 * contra o Gitleaks 8.18.4 (sondas LC-06 12 e 13): é exatamente o conjunto que ele declara em "N commits scanned"
 * (arquivo novo, modificado, renomeado, binário com --text, troca de modo; sem remoção pura, sem commit vazio; merge
 * pelo diff contra o primeiro pai).
 * @returns {{ total: number, esperados: number, digest: string } | null}
 */
function commitsDoHistorico(repositorio, runner, timeout) {
  const log = runner('git', ['-C', repositorio, 'log', '--format=%x01%H', '--name-status', ...OPCOES_LOG_HISTORICO.split(' '), 'HEAD'], { timeout, maxBuffer: 512 * 1024 * 1024 });
  if (log.status !== 'SUCCESS' || log.exitCode !== 0) return null;
  const blocos = (log.stdout || '').split('\x01').slice(1);
  const esperados = [];
  for (const bloco of blocos) {
    const [cabeca, ...linhas] = bloco.split(/\r?\n/);
    const sha = cabeca.trim();
    if (!/^[0-9a-f]{40}$/.test(sha)) return null;
    if (linhas.some((l) => l.includes('\t') && !l.startsWith('D'))) esperados.push(sha);
  }
  return { total: blocos.length, esperados: esperados.length, digest: hashTexto(esperados.join('\n')) };
}

function removerSilencioso(caminho) {
  try {
    rmSync(caminho, { recursive: true, force: true });
  } catch {
    // limpeza best-effort de diretório temporário
  }
}

/**
 * Varre o HISTÓRICO Git do alvo com o Gitleaks e demonstra (ou não) a cobertura dele.
 *
 * Cobertura histórica NÃO é inferida da declaração do Gitleaks (decisão LC-06): o ZUNVIO compara o universo histórico
 * esperado, calculado pelo Git, com o que o Gitleaks declara ter varrido. COMPLETA só quando: o alvo é a raiz de um
 * repositório, o repositório NÃO é shallow, o clone varrido tem o mesmo HEAD e o mesmo número de commits do alvo, e
 * commits varridos = commits esperados. Qualquer outra situação é DESCONHECIDA, com motivo — nunca cobertura afirmada.
 *
 * Neutralização de supressões do projeto: a varredura é feita sobre um clone --bare (sem working tree ⇒ o
 * `.gitleaksignore` do projeto não existe na raiz varrida; `refs/replace` e grafts do alvo não são clonados), com o
 * diretório de trabalho do processo num diretório vazio do ZUNVIO e `--ignore-gitleaks-allow`.
 *
 * Fail-closed: falha de execução é ERROR/UNAVAILABLE/TIMEOUT (portão NÃO COMPROVADO), nunca "sem achados".
 *
 * @param {string} targetPath
 * @param {object} [opcoes]
 * @param {string} [opcoes.executavel='gitleaks']
 * @param {Function} [opcoes.runner=executarProcessoSeguro]
 * @param {number} [opcoes.timeout=30000] - timeout do Gitleaks, em ms.
 * @param {number} [opcoes.timeoutGit=60000] - timeout de cada comando git (clone, log), em ms.
 * @returns {Promise<{ status: string, disponivel: boolean, vazamentos: object[], versao: string|null, cobertura: object, erro: string|null, duracaoMs: number }>}
 */
export async function executarHistoricoGitleaks(targetPath, opcoes = {}) {
  const inicio = Date.now();
  const runner = opcoes.runner || executarProcessoSeguro;
  const executavel = opcoes.executavel || 'gitleaks';
  const timeout = opcoes.timeout || 30_000;
  const timeoutGit = opcoes.timeoutGit || 60_000;
  const targetAbsoluto = resolve(targetPath);
  const git = (args, extra = {}) => runner('git', args, { timeout: timeoutGit, ...extra });
  const ok = (r) => r && r.status === 'SUCCESS' && r.exitCode === 0;
  const resultado = (status, cobertura, extra = {}) => ({
    status,
    disponivel: status !== 'UNAVAILABLE',
    vazamentos: [],
    versao: null,
    erro: null,
    ...extra,
    cobertura: Object.freeze({ applicable: true, shallow: null, headCommit: null, commitsTotal: null, commitsExpected: null, commitsScanned: null, expectedDigest: null, reason: null, ...cobertura }),
    duracaoMs: Date.now() - inicio
  });
  const desconhecida = (motivo, extra = {}) => ({ status: COBERTURA_HISTORICO.DESCONHECIDA, reason: motivo, ...extra });

  const { ehRepoRaiz, dentroDeRepo, gitDisponivel } = detectarRepositorioGit(targetAbsoluto, runner);
  if (!gitDisponivel) {
    return resultado('UNAVAILABLE', desconhecida(MOTIVO_HISTORICO.NAO_DETERMINADO), {
      erro: 'O binário git não está disponível: não é possível determinar nem varrer o histórico do alvo.'
    });
  }
  if (!dentroDeRepo) {
    // Alvo sem repositório Git: o histórico do release NÃO está no alvo e não pode ser varrido. Não é "histórico vazio":
    // o release pode ter histórico (e segredos nele) em outro lugar — a proveniência pode até vir de evidência externa.
    // Universo histórico não determinável ⇒ UNKNOWN (decisão LC-06), nunca cobertura afirmada.
    return resultado('NOT_RUN', desconhecida(MOTIVO_HISTORICO.NAO_DETERMINADO, { applicable: false }));
  }
  if (!ehRepoRaiz) {
    // Subdiretório de um repositório: o histórico existe, mas não é varrido (seria o de código não relacionado).
    return resultado('NOT_RUN', desconhecida(MOTIVO_HISTORICO.NAO_DETERMINADO));
  }

  const resVersao = runner(executavel, ['version'], { cwd: targetAbsoluto, timeout: 15_000 });
  const versao = extrairVersaoSemver(resVersao?.stdout);
  const shallowAlvo = git(['-C', targetAbsoluto, 'rev-parse', '--is-shallow-repository']);
  const headAlvo = git(['-C', targetAbsoluto, 'rev-parse', '--verify', '--quiet', 'HEAD^{commit}']);
  if (!ok(shallowAlvo)) return resultado('ERROR', desconhecida(MOTIVO_HISTORICO.NAO_DETERMINADO), { versao, erro: 'Não foi possível determinar se o repositório é shallow.' });
  const shallow = (shallowAlvo.stdout || '').trim() === 'true';
  if (!ok(headAlvo)) {
    // Repositório sem nenhum commit: não há release versionado a comparar com o histórico — não determinável.
    return resultado('NOT_RUN', desconhecida(shallow ? MOTIVO_HISTORICO.SHALLOW : MOTIVO_HISTORICO.NAO_DETERMINADO, { shallow, commitsTotal: 0 }), { versao });
  }
  const head = (headAlvo.stdout || '').trim();
  const contagemAlvo = git(['-C', targetAbsoluto, 'rev-list', '--count', 'HEAD'], { env: { GIT_NO_REPLACE_OBJECTS: '1' } });

  const temporarios = [];
  const bare = join(tmpdir(), `zunvio-historico-${randomBytes(8).toString('hex')}.git`);
  const cwdVazio = join(tmpdir(), `zunvio-historico-cwd-${randomBytes(8).toString('hex')}`);
  const reportPath = join(tmpdir(), `zunvio-gitleaks-historico-${randomBytes(6).toString('hex')}.json`);
  temporarios.push(bare, cwdVazio, reportPath);
  try {
    mkdirSync(cwdVazio, { recursive: true });
    const clone = git(['clone', '--quiet', '--bare', '--no-local', '--', targetAbsoluto, bare], { cwd: cwdVazio });
    if (!ok(clone)) {
      return resultado('ERROR', desconhecida(MOTIVO_HISTORICO.NAO_DETERMINADO, { shallow, headCommit: head }), { versao, erro: 'Não foi possível clonar o repositório para varrer o histórico sem as supressões do projeto.' });
    }
    const headClone = git(['-C', bare, 'rev-parse', '--verify', '--quiet', 'HEAD^{commit}']);
    const contagemClone = git(['-C', bare, 'rev-list', '--count', 'HEAD']);
    const shallowClone = git(['-C', bare, 'rev-parse', '--is-shallow-repository']);
    const universo = commitsDoHistorico(bare, runner, timeoutGit);
    const cloneFiel = ok(headClone) && (headClone.stdout || '').trim() === head
      && ok(contagemClone) && ok(contagemAlvo) && (contagemClone.stdout || '').trim() === (contagemAlvo.stdout || '').trim();

    const saida = runner(executavel, montarArgumentosHistorico(bare, reportPath), { cwd: cwdVazio, timeout });
    const interpretado = interpretarResultadoScan(saida, reportPath);
    if (!interpretado.ok) {
      const statusFinal = interpretado.tipo === 'SUCCESS' ? 'ERROR' : interpretado.tipo;
      return resultado(statusFinal, desconhecida(MOTIVO_HISTORICO.NAO_DETERMINADO, { shallow, headCommit: head }), {
        versao,
        erro: `Varredura de histórico Git não concluída: ${interpretado.erro || 'motivo desconhecido'}`
      });
    }
    const varridos = Number(((saida.stderr || '').replace(/\u001b\[[0-9;]*m/g, '').match(/(\d+) commits scanned/) || [])[1]);
    const commitsScanned = Number.isInteger(varridos) ? varridos : null;
    const base = {
      shallow: shallow || (ok(shallowClone) && (shallowClone.stdout || '').trim() === 'true'),
      headCommit: head,
      commitsTotal: universo ? universo.total : null,
      commitsExpected: universo ? universo.esperados : null,
      commitsScanned,
      expectedDigest: universo ? universo.digest : null
    };
    let cobertura;
    if (base.shallow) cobertura = { ...base, status: COBERTURA_HISTORICO.DESCONHECIDA, reason: MOTIVO_HISTORICO.SHALLOW };
    else if (!cloneFiel || !universo || commitsScanned === null) cobertura = { ...base, status: COBERTURA_HISTORICO.DESCONHECIDA, reason: MOTIVO_HISTORICO.NAO_DETERMINADO };
    else if (commitsScanned !== universo.esperados) cobertura = { ...base, status: COBERTURA_HISTORICO.DESCONHECIDA, reason: MOTIVO_HISTORICO.DIVERGENCIA };
    else cobertura = { ...base, status: COBERTURA_HISTORICO.COMPLETA, reason: null };
    return resultado('SUCCESS', cobertura, { versao, vazamentos: interpretado.vazamentos });
  } finally {
    for (const t of temporarios) removerSilencioso(t);
  }
}
