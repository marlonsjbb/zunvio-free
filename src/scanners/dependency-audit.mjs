import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { executarProcessoSeguro } from '../utils/process-runner.mjs';

// RF-08 camada 4 (MASS-399), parte CVE/dependência: usa `npm audit --json`
// (ferramenta já presente onde há Node/npm, mesmo padrão de reaproveitar
// tooling existente do ecossistema em vez de reimplementar um banco de CVE
// próprio). Informativo por decisão explícita — não é sensor canônico. Ver
// docs/checkpoints/MASS-399-preflight-rf08-09-11.md.

export const ID_SENSOR = 'dependencias-cve';

const MAPA_SEVERIDADE = Object.freeze({
  critical: 'CRITICAL',
  high: 'HIGH',
  moderate: 'MEDIUM',
  low: 'LOW',
  info: 'INFO'
});

function severidadeCanonica(severidadeNpm) {
  return MAPA_SEVERIDADE[String(severidadeNpm || '').toLowerCase()] || 'INFO';
}

function extrairIdAviso(via) {
  if (typeof via.url === 'string') {
    const m = /advisories\/([A-Za-z0-9-]+)/.exec(via.url);
    if (m) return m[1];
  }
  return via.source !== undefined ? `NPM-ADVISORY-${via.source}` : 'NPM-ADVISORY-DESCONHECIDO';
}

// No Windows, `npm` é um shim `.cmd`/`.ps1`, e o Node recusa (por segurança,
// desde a correção de injeção de comando via .bat/.cmd) executar esse tipo de
// arquivo com `shell: false` — sempre falha com ENOENT/EINVAL, binário
// instalado ou não. `cmd.exe /c npm ...` contorna isso sem reintroduzir
// interpretação de shell sobre argumento nenhum: cada elemento do array
// continua um argv literal e discreto, nenhum deles vem de entrada externa.
function comandoAuditoria() {
  if (process.platform === 'win32') {
    return { executavel: 'cmd.exe', argumentos: ['/c', 'npm', 'audit', '--json'] };
  }
  return { executavel: 'npm', argumentos: ['audit', '--json'] };
}

/**
 * Roda `npm audit --json` sobre um inventário já materializado (mesma cópia
 * read-only usada pelos demais scanners — nunca o alvo original) e traduz o
 * resultado para o formato canônico de achado do ZUNVIO.
 *
 * @param {{ raiz: string }} inventario
 * @param {object} [opcoes={}]
 * @param {Function} [opcoes.runner=executarProcessoSeguro] - Injeção de runner para testes.
 * @param {number} [opcoes.timeout=60000]
 * @returns {{ status: string, achados: Array, duracaoMs: number, identidade: object, erro: string|null }}
 */
export function executarScannerDependencias(inventario, opcoes = {}) {
  const inicio = Date.now();
  const runner = opcoes.runner || executarProcessoSeguro;

  if (!existsSync(join(inventario.raiz, 'package.json'))) {
    return {
      status: 'NAO_APLICAVEL',
      achados: [],
      duracaoMs: Date.now() - inicio,
      identidade: { id: ID_SENSOR, completion: 'NOT_STARTED' },
      erro: null
    };
  }

  const { executavel, argumentos } = comandoAuditoria();
  const resultado = runner(executavel, argumentos, {
    cwd: inventario.raiz,
    timeout: Number.isInteger(opcoes.timeout) && opcoes.timeout > 0 ? opcoes.timeout : 60_000
  });

  if (resultado.status === 'UNAVAILABLE') {
    return {
      status: 'UNAVAILABLE',
      achados: [],
      duracaoMs: Date.now() - inicio,
      identidade: { id: ID_SENSOR, completion: 'NOT_STARTED' },
      erro: "Binário 'npm' não encontrado no PATH."
    };
  }
  if (resultado.status === 'TIMEOUT') {
    return {
      status: 'TIMEOUT',
      achados: [],
      duracaoMs: Date.now() - inicio,
      identidade: { id: ID_SENSOR, completion: 'FAILED' },
      erro: 'npm audit excedeu o tempo limite (possível indisponibilidade de rede/registry).'
    };
  }

  // npm audit sai com código 1 quando encontra vulnerabilidades — isso NÃO é
  // erro de execução, é o resultado esperado. O JSON em stdout é a fonte da
  // verdade independentemente do exit code.
  let relatorio;
  try {
    relatorio = JSON.parse(resultado.stdout);
  } catch {
    return {
      status: 'ERROR',
      achados: [],
      duracaoMs: Date.now() - inicio,
      identidade: { id: ID_SENSOR, completion: 'FAILED' },
      erro: 'Saída de "npm audit --json" não é JSON válido (registry indisponível ou lockfile ausente/incompatível).'
    };
  }

  if (relatorio?.error?.code === 'ENOLOCK') {
    // Projeto sem lockfile (nunca rodou `npm install`) — não há árvore de
    // dependências resolvida pra auditar. Não é falha do scanner.
    return {
      status: 'NAO_APLICAVEL',
      achados: [],
      duracaoMs: Date.now() - inicio,
      identidade: { id: ID_SENSOR, completion: 'NOT_STARTED' },
      erro: null
    };
  }

  const vulnerabilidades = relatorio?.vulnerabilities;
  if (!vulnerabilidades || typeof vulnerabilidades !== 'object') {
    // Formato inesperado (schema mais antigo de npm <7, ex. `.advisories`, ou
    // outro erro do npm não mapeado acima). Falha fechado: reporta erro em vez
    // de fingir cobertura.
    return {
      status: 'ERROR',
      achados: [],
      duracaoMs: Date.now() - inicio,
      identidade: { id: ID_SENSOR, completion: 'FAILED' },
      erro: relatorio?.error?.summary
        ? `npm audit falhou: ${relatorio.error.summary}`
        : 'Schema de "npm audit --json" não reconhecido (versão de npm incompatível).'
    };
  }

  const achados = [];
  for (const pacote of Object.values(vulnerabilidades)) {
    const nodePath = Array.isArray(pacote.nodes) && pacote.nodes[0] ? pacote.nodes[0] : `node_modules/${pacote.name}`;
    const vias = Array.isArray(pacote.via) ? pacote.via : [];
    const aviosReais = vias.filter((v) => v && typeof v === 'object');

    if (aviosReais.length === 0) {
      // `via` só com nomes de pacote (dependência transitiva sem advisory
      // direto neste nó) — ainda assim reporta a severidade agregada.
      achados.push({
        scanner: ID_SENSOR,
        ruleId: `NPM-DEP-${pacote.name}`,
        severity: severidadeCanonica(pacote.severity),
        filePath: nodePath,
        startLine: 0,
        endLine: 0,
        message: `Dependência "${pacote.name}" (${pacote.range || 'faixa desconhecida'}) com vulnerabilidade conhecida na cadeia de dependências.`
      });
      continue;
    }

    for (const via of aviosReais) {
      achados.push({
        scanner: ID_SENSOR,
        ruleId: extrairIdAviso(via),
        severity: severidadeCanonica(via.severity),
        filePath: nodePath,
        startLine: 0,
        endLine: 0,
        message: `${via.title || 'Vulnerabilidade conhecida'} em "${pacote.name}" (faixa afetada: ${via.range || pacote.range || 'desconhecida'}).`
      });
    }
  }

  achados.sort((a, b) => a.filePath.localeCompare(b.filePath) || a.ruleId.localeCompare(b.ruleId));

  return {
    status: 'SUCCESS',
    achados,
    duracaoMs: Date.now() - inicio,
    identidade: {
      id: ID_SENSOR,
      completion: achados.length > 0 ? 'WITH_FINDINGS' : 'CLEAN'
    },
    erro: null
  };
}
