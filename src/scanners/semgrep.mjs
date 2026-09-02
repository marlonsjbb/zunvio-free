import { relative, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync, readFileSync } from 'node:fs';
import { executarProcessoSeguroAsync } from '../utils/process-runner.mjs';
import { criarAchadoNormalizado, projetarAchadoCanonico } from '../models/finding.mjs';
import { redigirTexto } from '../utils/redactor.mjs';
import {
  classificarCompletude,
  calcularDigestCanonico,
  extrairVersaoSemver,
  hashTexto
} from '../models/sensor-identity.mjs';
import { criarAmbienteTemporarioSemgrep, limparTemporariosSemgrep } from './semgrep-env.mjs';

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
function montarIdentidadeSemgrep({ versao, configHash, status, achados }) {
  return Object.freeze({
    id: 'semgrep',
    versao: versao ?? null,
    configHash: configHash ?? null,
    findingsDigest: status === 'SUCCESS' ? calcularDigestCanonico(achados.map(projetarAchadoCanonico)) : null,
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
 * @returns {Array<ReturnType<typeof criarAchadoNormalizado>>}
 */
export function normalizarAchadosSemgrep(jsonSemgrep, raizAlvo, ruleIdsLocais = []) {
  if (!jsonSemgrep || !Array.isArray(jsonSemgrep.results)) return [];

  return jsonSemgrep.results.map((resultado) => {
    const checkId = normalizarRuleIdSemgrep(resultado.check_id, ruleIdsLocais);
    const extra = resultado.extra || {};
    const message = extra.message || 'Padrão inseguro detectado pelo Semgrep';
    const severity = mapearSeveridadeSemgrep(extra.severity);
    const arquivoBruto = resultado.path || '';
    const caminhoRelativo = relative(raizAlvo, resolve(raizAlvo, arquivoBruto)).replace(/\\/g, '/');

    return criarAchadoNormalizado({
      scanner: 'semgrep',
      ruleId: checkId,
      severity,
      message,
      filePath: caminhoRelativo,
      startLine: resultado.start?.line || 1,
      endLine: resultado.end?.line || resultado.start?.line || 1,
      rawDetails: {
        lines: extra.lines ? redigirTexto(String(extra.lines).slice(0, 300)) : null,
        metadata: extra.metadata || {}
      }
    });
  });
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

  // Garante regra local offline por padrão, recusando auto-download remoto
  let configRegras = opcoes.config || REGRA_PADRAO_LOCAL;
  if (configRegras === 'auto') {
    // Se o chamador pedir 'auto', força para o rulepack local seguro
    configRegras = REGRA_PADRAO_LOCAL;
  }
  const ruleIdsLocais = extrairRuleIdsLocais(resolve(targetAbsoluto, configRegras));

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
    `--config=${configRegras}`,
    targetAbsoluto
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

  if (resultado.status === 'UNAVAILABLE') {
    return {
      status: 'UNAVAILABLE',
      disponivel: false,
      achados: [],
      duracaoMs,
      erro: resultado.stderr,
      identidade: montarIdentidadeSemgrep({ versao, configHash, status: 'UNAVAILABLE', achados: [] })
    };
  }

  if (resultado.status === 'TIMEOUT') {
    return {
      status: 'TIMEOUT',
      disponivel: true,
      achados: [],
      duracaoMs,
      erro: resultado.stderr,
      identidade: montarIdentidadeSemgrep({ versao, configHash, status: 'TIMEOUT', achados: [] })
    };
  }

  if (resultado.status === 'BUFFER_OVERFLOW') {
    return {
      status: 'ERROR',
      disponivel: true,
      achados: [],
      duracaoMs,
      erro: resultado.stderr,
      identidade: montarIdentidadeSemgrep({ versao, configHash, status: 'ERROR', achados: [] })
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
      identidade: montarIdentidadeSemgrep({ versao, configHash, status: 'ERROR', achados: [] })
    };
  }

  const achados = normalizarAchadosSemgrep(jsonParseado, targetAbsoluto, ruleIdsLocais);
  const statusFinal = resultado.exitCode === 0 || resultado.exitCode === 1 ? 'SUCCESS' : 'ERROR';

  return {
    status: statusFinal,
    disponivel: true,
    achados,
    duracaoMs,
    erro: resultado.exitCode > 1 ? resultado.stderr : null,
    identidade: montarIdentidadeSemgrep({ versao, configHash, status: statusFinal, achados })
  };
}
