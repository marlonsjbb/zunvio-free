import { relative, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync, readFileSync } from 'node:fs';
import { executarProcessoSeguroAsync } from '../utils/process-runner.mjs';
import {
  compararAchadosNormalizados,
  criarAchadoNormalizado,
  projetarAchadoCanonico
} from '../models/finding.mjs';
import { redigirTexto } from '../utils/redactor.mjs';
import {
  classificarCompletude,
  calcularDigestCanonico,
  extrairVersaoSemver,
  hashTexto
} from '../models/sensor-identity.mjs';
import { criarAmbienteTemporarioSemgrep, limparTemporariosSemgrep } from './semgrep-env.mjs';
import { avaliarCompletudeSemgrep } from '../models/completeness.mjs';
import { resolverIdentidadeChildProcessExec } from '../models/symbol-identity.mjs';
import { avaliarSignificadoSemgrep, CLASSES_SIGNIFICADO } from '../models/finding-meaning.mjs';
import { calcularIdentidadesDeRevisao } from '../models/human-review.mjs';

// PL-03 · Fatia 1: única regra com resolução de identidade de símbolo.
const REGRA_CHILD_PROCESS_EXEC = 'zunvio.child-process-exec';

function lerArquivoPadrao(caminhoAbsoluto) {
  try {
    return readFileSync(caminhoAbsoluto, 'utf8');
  } catch {
    return null;
  }
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REGRA_PADRAO_LOCAL = resolve(__dirname, '../../rules/semgrep/default-rules.yaml');

/**
 * Monta a identidade canônica do sensor Semgrep: id, versão real do binário,
 * hash da configuração efetiva (conteúdo do rulepack local), digest da saída
 * normalizada e estado de completude. Nada é inventado: versão vem do binário,
 * configHash vem do conteúdo do arquivo de regras usado e a completude deriva
 * do status real.
 */
export function montarIdentidadeSemgrep({ versao, configHash, status, achados }) {
  return Object.freeze({
    id: 'semgrep',
    versao: versao ?? null,
    configHash: configHash ?? null,
    findingsDigest: status === 'SUCCESS'
      ? calcularDigestCanonico([...achados].sort(compararAchadosNormalizados).map(projetarAchadoCanonico))
      : null,
    completion: classificarCompletude(status, achados.length)
  });
}

/**
 * Extrai os IDs lógicos declarados em um rulepack YAML local. O Semgrep prefixa
 * esses IDs com o caminho absoluto da configuração em algumas versões; manter a
 * lista declarada permite remover somente esse prefixo volátil, sem truncar IDs
 * externos desconhecidos ou IDs legítimos que já contenham pontos.
 * @param {string} caminhoConfig
 * @returns {string[]}
 */
function extrairRuleIdsLocais(caminhoConfig) {
  if (!caminhoConfig || !existsSync(caminhoConfig)) return [];

  try {
    const ids = readFileSync(caminhoConfig, 'utf8')
      .split(/\r?\n/)
      .map((linha) => linha.match(/^\s*-\s+id:\s*(?:"([^"]+)"|'([^']+)'|([^\s#]+))/))
      .filter(Boolean)
      .map((match) => match[1] || match[2] || match[3]);
    return [...new Set(ids)].sort((a, b) => b.length - a.length || a.localeCompare(b));
  } catch {
    return [];
  }
}

/**
 * PL-02: linguagens declaradas no rulepack local (`languages:` em lista YAML ou inline). É a COBERTURA DECLARADA
 * que define o universo esperado do Semgrep (models/expected-universe.mjs). Sem declaração legível: [] (o universo
 * não é calculado e a completude fica como na Fatia 1).
 */
export function extrairLinguagensLocais(caminhoConfig) {
  if (!caminhoConfig || !existsSync(caminhoConfig)) return [];
  try {
    const linhas = readFileSync(caminhoConfig, 'utf8').split(/\r?\n/);
    const linguagens = new Set();
    for (let i = 0; i < linhas.length; i++) {
      const m = linhas[i].match(/^(\s*)languages:\s*(.*)$/);
      if (!m) continue;
      const inline = m[2].match(/^\[(.*)\]/);
      if (inline) {
        for (const l of inline[1].split(',')) if (l.trim()) linguagens.add(l.trim().replace(/^["']|["']$/g, '').toLowerCase());
        continue;
      }
      for (let j = i + 1; j < linhas.length; j++) {
        // Revisão r4: comentário e linha em branco no meio da lista não a encerram (senão uma linguagem some do
        // universo esperado); comentário no fim do item é ignorado.
        if (/^\s*(#.*)?$/.test(linhas[j])) continue;
        const item = linhas[j].match(/^\s*-\s*["']?([\w-]+)["']?\s*(#.*)?$/);
        if (!item) break;
        linguagens.add(item[1].toLowerCase());
      }
    }
    return [...linguagens].sort();
  } catch {
    return [];
  }
}

function normalizarRuleIdSemgrep(checkId, ruleIdsLocais) {
  const bruto = checkId || 'semgrep.generic-finding';
  const idDeclarado = ruleIdsLocais.find((id) => bruto === id || bruto.endsWith(`.${id}`));
  return idDeclarado || bruto;
}

/**
 * Converte a severidade do Semgrep para o formato unificado do ZUNVIO.
 * @param {string} semgrepSev - Severidade original do Semgrep (ERROR, WARNING, INFO).
 * @returns {'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'}
 */
function mapearSeveridadeSemgrep(semgrepSev) {
  const sev = String(semgrepSev || '').toUpperCase();
  if (sev === 'ERROR') return 'HIGH';
  if (sev === 'WARNING') return 'MEDIUM';
  if (sev === 'INFO') return 'LOW';
  return 'INFO';
}

/**
 * Mapeia o resultado bruto do Semgrep para o schema unificado do ZUNVIO.
 * @param {object} jsonSemgrep - Saída JSON completa do Semgrep.
 * @param {string} raizAlvo - Caminho raiz do projeto analisado.
 * @param {string[]} [ruleIdsLocais=[]] - IDs declarados no rulepack local efetivamente usado.
 * @param {object} [opcoes={}]
 * @param {(caminhoAbsoluto: string) => string|null} [opcoes.lerArquivo] - Leitura do arquivo analisado (injetável
 *   em teste/replay). Usada para a identidade de símbolo (child-process-exec) e para o significado do achado.
 * @returns {Array<ReturnType<typeof criarAchadoNormalizado>>}
 */
export function normalizarAchadosSemgrep(jsonSemgrep, raizAlvo, ruleIdsLocais = [], opcoes = {}) {
  if (!jsonSemgrep || !Array.isArray(jsonSemgrep.results)) return [];
  const lerArquivo = typeof opcoes.lerArquivo === 'function' ? opcoes.lerArquivo : lerArquivoPadrao;
  const cacheArquivos = new Map();
  const conteudo = (caminhoAbsoluto) => {
    if (!cacheArquivos.has(caminhoAbsoluto)) cacheArquivos.set(caminhoAbsoluto, lerArquivo(caminhoAbsoluto));
    return cacheArquivos.get(caminhoAbsoluto);
  };

  const achados = jsonSemgrep.results.map((resultado) => {
    const checkId = normalizarRuleIdSemgrep(resultado.check_id, ruleIdsLocais);
    const extra = resultado.extra || {};
    const mensagemRegra = extra.message || 'Padrão inseguro detectado pelo Semgrep';
    let severity = mapearSeveridadeSemgrep(extra.severity);
    const arquivoBruto = resultado.path || '';
    const caminhoRelativo = relative(raizAlvo, resolve(raizAlvo, arquivoBruto)).replace(/\\/g, '/');
    const codigo = conteudo(resolve(raizAlvo, arquivoBruto));
    const linha = resultado.start?.line || 1;

    const identidadeSimbolo = checkId === REGRA_CHILD_PROCESS_EXEC
      ? resolverIdentidadeChildProcessExec({ codigo, linha, coluna: resultado.start?.col })
      : null;
    // PL-03: MATCH → CONTEXTO → EVIDÊNCIA → SIGNIFICADO. A mensagem do achado passa a ser a explicação do ZUNVIO,
    // que só afirma propriedades demonstradas; a mensagem da regra fica preservada em rawDetails.mensagemRegra.
    const significado = avaliarSignificadoSemgrep({ ruleId: checkId, codigo, linha, coluna: resultado.start?.col, filePath: caminhoRelativo, identidadeSimbolo });
    if (significado.classe === CLASSES_SIGNIFICADO.INFORMATIVO) severity = 'INFO';

    return criarAchadoNormalizado({
      scanner: 'semgrep',
      ruleId: checkId,
      severity,
      message: significado.explicacao,
      filePath: caminhoRelativo,
      startLine: linha,
      endLine: resultado.end?.line || linha,
      identidadeSimbolo,
      significado,
      rawDetails: {
        lines: extra.lines ? redigirTexto(String(extra.lines).slice(0, 300)) : null,
        mensagemRegra: redigirTexto(String(mensagemRegra).slice(0, 400)),
        metadata: extra.metadata || {}
      }
    });
  });
  // E2E mínimo: identidade estável para a revisão humana (sem número de linha) e contexto para detectar revisão
  // obsoleta. Campos do achado em memória; só entram no Evidence Pack quando uma revisão é aplicada (0.8.0).
  const identidades = calcularIdentidadesDeRevisao(achados, (rel) => conteudo(resolve(raizAlvo, rel)));
  return achados.map((a) => (identidades.has(a) ? Object.freeze({ ...a, ...identidades.get(a) }) : a));
}

/**
 * Executa o scanner Semgrep sobre o diretório de forma estritamente somente leitura e 100% offline.
 * @param {string} targetPath - Caminho do projeto a ser analisado.
 * @param {object} [opcoes={}] - Opções customizadas.
 * @param {string} [opcoes.executavel='semgrep'] - Caminho ou nome do binário.
 * @param {string} [opcoes.config] - Configuração de regras locais do Semgrep (usa rulepack local versionado por padrão).
 * @param {Function} [opcoes.runner=executarProcessoSeguro] - Função de execução.
 * @param {number} [opcoes.timeout=60000] - Timeout em ms.
 * @returns {Promise<{ status: 'SUCCESS' | 'ERROR' | 'UNAVAILABLE' | 'TIMEOUT', disponivel: boolean, achados: Array<ReturnType<typeof criarAchadoNormalizado>>, duracaoMs: number, erro: string | null }>}
 */
export async function executarScannerSemgrep(targetPath, opcoes = {}) {
  const inicio = Date.now();
  const runner = opcoes.runner || executarProcessoSeguroAsync;
  const executavel = opcoes.executavel || 'semgrep';
  const targetAbsoluto = resolve(targetPath);
  const fonteVarredura = resolve(opcoes.sourcePath || targetAbsoluto);

  // Garante regra local offline por padrão, recusando auto-download remoto
  let configRegras = opcoes.config || REGRA_PADRAO_LOCAL;
  if (configRegras === 'auto') {
    // Se o chamador pedir 'auto', força para o rulepack local seguro
    configRegras = REGRA_PADRAO_LOCAL;
  }
  const ruleIdsLocais = extrairRuleIdsLocais(resolve(targetAbsoluto, configRegras));
  const linguagens = extrairLinguagensLocais(resolve(targetAbsoluto, configRegras));

  // Hash da configuração efetivamente usada (conteúdo do rulepack local).
  let configHash = null;
  try {
    configHash = hashTexto(readFileSync(resolve(targetAbsoluto, configRegras), 'utf8'));
  } catch {
    configHash = null;
  }

  const argumentos = [
    'scan',
    '--json',
    '--quiet',
    '--disable-version-check',
    '--metrics=off',
    // O Semgrep ignora em silêncio qualquer diretório que bata seus padrões
    // padrão de .semgrepignore embutidos (inclui nomes comuns como "test"/
    // "tests"), independente de qualquer configuração do ZUNVIO — confirmado
    // empiricamente (MASS-80): uma pasta real chamada "test" com um eval()
    // detectável dava "0 files scanned" sem aviso no relatório. Um scanner de
    // segurança não pode ter um ponto cego silencioso em nome de código
    // legítimo do cliente estar numa pasta com esse nome comum. A flag é
    // marcada --x- (experimental) pelo próprio Semgrep, mas a versão do
    // binário é fixa e verificada por SHA-256 (engine-bootstrap.mjs) — se uma
    // futura atualização de versão remover/quebrar a flag, o teste de
    // regressão associado a ela falha alto, não silenciosamente. MASS-399
    // AJ-01B: desde que dist/build/coverage saíram da exclusão por nome em
    // scan-inventory.mjs, esta flag também é o que impede esses nomes de
    // pasta de caírem no mesmo ponto cego — confirmado empiricamente
    // (docs/checkpoints/aj01b-evidencias/): sem ela, um eval() real dentro de
    // dist/ não é reportado (0 achados); com ela, é.
    '--x-ignore-semgrepignore-files',
    // MASS-399 AJ-01B, correção de #12426: a versão anterior deste
    // comentário afirmava que '--no-git-ignore' fechava uma lacuna real do
    // '--use-git-ignore' (padrão do Semgrep) para dist/build/coverage
    // untracked+ignorado. Reverificado com o código real do pipeline
    // (executarScannerSemgrep + criarInventarioScanner, não uma simulação
    // isolada): o alvo efetivamente escaneado aqui é sempre `sourcePath`
    // (a cópia de inventário), que NUNCA tem `.git` — scan-inventory.mjs a
    // exclui fisicamente da cópia sempre. Sem `.git` no caminho escaneado, o
    // '--use-git-ignore' do Semgrep não tem onde se ancorar, então a flag
    // '--no-git-ignore' não muda nenhum resultado no pipeline real (testado
    // com e sem a flag, mesma fixture, mesmo resultado: achado detectado nos
    // dois casos). A claim anterior media o Semgrep isolado contra um
    // repositório Git de verdade, cenário que este código nunca produz. A
    // flag foi removida por não ter efeito comprovado; quem reintroduzir uma
    // via de escaneamento que preserve `.git` na cópia deve reavaliar este
    // ponto do zero.
    `--config=${configRegras}`,
    fonteVarredura
  ];

  const ambienteSemgrep = criarAmbienteTemporarioSemgrep();
  let resultado;
  let versao = null;
  try {
    // Versão real do binário (best-effort; null quando indisponível ou sem semver).
    const resVersao = await runner(executavel, ['--version'], {
      cwd: targetAbsoluto,
      timeout: 15_000,
      env: ambienteSemgrep.env,
      signal: ambienteSemgrep.signal,
      detached: true
    });
    versao = extrairVersaoSemver(resVersao?.stdout);

    resultado = await runner(executavel, argumentos, {
      cwd: targetAbsoluto,
      timeout: opcoes.timeout || 60_000,
      env: ambienteSemgrep.env,
      signal: ambienteSemgrep.signal,
      detached: true
    });
  } finally {
    limparTemporariosSemgrep(ambienteSemgrep);
  }

  const duracaoMs = Date.now() - inicio;
  // Fatia 1 (Scanner Completeness): converte caminho/regra dos erros do Semgrep
  // para o mesmo referencial dos achados (relativo à cópia de inventário, regra
  // lógica do rulepack local), sem inventar nada.
  const caminhoRelativo = (bruto) => relative(fonteVarredura, resolve(fonteVarredura, String(bruto))).replace(/\\/g, '/');
  const normalizarRegra = (bruto) => normalizarRuleIdSemgrep(bruto, ruleIdsLocais);
  // PL-02: com o inventário do ZUNVIO (enviado pelo orquestrador), a completude é medida contra o universo esperado.
  const completudeDe = (status, json) => avaliarCompletudeSemgrep({
    status, json, caminhoRelativo, normalizarRegra, inventario: opcoes.inventario || null, linguagens
  });

  if (resultado.status === 'UNAVAILABLE') {
    return {
      status: 'UNAVAILABLE',
      disponivel: false,
      achados: [],
      duracaoMs,
      erro: resultado.stderr,
      identidade: montarIdentidadeSemgrep({ versao, configHash, status: 'UNAVAILABLE', achados: [] }),
      completude: completudeDe('UNAVAILABLE', null)
    };
  }

  if (resultado.status === 'TIMEOUT') {
    return {
      status: 'TIMEOUT',
      disponivel: true,
      achados: [],
      duracaoMs,
      erro: resultado.stderr,
      identidade: montarIdentidadeSemgrep({ versao, configHash, status: 'TIMEOUT', achados: [] }),
      completude: completudeDe('TIMEOUT', null)
    };
  }

  if (resultado.status === 'BUFFER_OVERFLOW') {
    return {
      status: 'ERROR',
      disponivel: true,
      achados: [],
      duracaoMs,
      erro: resultado.stderr,
      identidade: montarIdentidadeSemgrep({ versao, configHash, status: 'ERROR', achados: [] }),
      completude: completudeDe('ERROR', null)
    };
  }

  let jsonParseado;
  try {
    if (resultado.stdout && resultado.stdout.trim()) {
      jsonParseado = JSON.parse(resultado.stdout);
    } else {
      jsonParseado = { results: [] };
    }
  } catch (err) {
    return {
      status: 'ERROR',
      disponivel: true,
      achados: [],
      duracaoMs,
      erro: `Falha ao interpretar JSON do Semgrep: ${err.message}. Detalhes: ${resultado.stderr.slice(0, 300)}`,
      identidade: montarIdentidadeSemgrep({ versao, configHash, status: 'ERROR', achados: [] }),
      completude: completudeDe('SUCCESS', null)
    };
  }

  const achados = normalizarAchadosSemgrep(jsonParseado, fonteVarredura, ruleIdsLocais);
  const statusFinal = resultado.exitCode === 0 || resultado.exitCode === 1 ? 'SUCCESS' : 'ERROR';

  return {
    status: statusFinal,
    disponivel: true,
    achados,
    duracaoMs,
    erro: resultado.exitCode > 1 ? resultado.stderr : null,
    identidade: montarIdentidadeSemgrep({ versao, configHash, status: statusFinal, achados }),
    // Fatia 1: o sucesso do processo (exit 0/1) NÃO apaga os erros por arquivo/regra
    // que o Semgrep declara em `errors` — eles viram completude PARTIAL.
    completude: completudeDe(statusFinal, jsonParseado),
    // E2E mínimo: onde a leitura foi parcial, em linguagem do projeto (arquivo, linha, trecho). Não selado: a
    // completude canônica continua sendo a fonte da decisão; isto só explica ao usuário.
    leituraParcial: detalharLeituraParcial(jsonParseado, caminhoRelativo)
  };
}

const TETO_LEITURA_PARCIAL = 50;
/**
 * Detalhe humano dos erros de leitura parcial do Semgrep. Quando o trecho rejeitado é um `&` em texto JSX (limitação
 * do parser TSX do Semgrep 1.176 em código TSX válido), sugere a correção demonstrável: `&amp;` ou "e".
 */
export function detalharLeituraParcial(json, caminhoRelativo) {
  const erros = Array.isArray(json?.errors) ? json.errors : [];
  const saida = [];
  for (const e of erros) {
    const tipo = Array.isArray(e?.type) ? e.type[0] : e?.type;
    if (tipo !== 'PartialParsing' && tipo !== 'Syntax error') continue;
    const span = Array.isArray(e.spans) ? e.spans[0] : null;
    const bruto = span?.file ?? e.path;
    if (!bruto) continue;
    const trecho = (String(e.message || '').match(/`([^`]{1,80})` was unexpected/) || [])[1] ?? null;
    saida.push({
      arquivo: caminhoRelativo(bruto),
      linha: Number.isInteger(span?.start?.line) ? span.start.line : null,
      trecho: trecho ? redigirTexto(trecho) : null,
      dica: trecho && /^&/.test(trecho)
        ? 'O analisador não lê um "&" solto em texto JSX (limitação do Semgrep; o código é válido). Trocar o "&" por "&amp;" ou por "e" permite a leitura completa deste arquivo.'
        : null
    });
    if (saida.length >= TETO_LEITURA_PARCIAL) break;
  }
  return saida;
}
