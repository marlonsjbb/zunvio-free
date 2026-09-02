import { spawn, spawnSync } from 'node:child_process';

const BUFFER_MAXIMO_PADRAO = 5 * 1024 * 1024; // 5MB
const TIMEOUT_PADRAO_MS = 30_000; // 30 segundos

/**
 * Variáveis de ambiente seguras essenciais para execução de executáveis do sistema.
 */
const VARIAVEIS_SISTEMA_PERMITIDAS = new Set([
  'PATH',
  'Path',
  'path',
  'SYSTEMROOT',
  'SystemRoot',
  'COMSPEC',
  'ComSpec',
  'TEMP',
  'TMP',
  'USERPROFILE',
  'HOME',
  'HOMEDRIVE',
  'HOMEPATH',
  'LANG',
  'LC_ALL',
  'SHELL',
  'TERM'
]);

/**
 * Cria um ambiente de variáveis de execução restrito e sanitizado para subprocessos.
 * @param {Record<string, string>} [envExtra={}]
 * @returns {Record<string, string>}
 */
export function criarAmbienteSanitizado(envExtra = {}) {
  const sanitizado = {};

  // Copia apenas variáveis permitidas da máquina
  for (const [chave, valor] of Object.entries(process.env)) {
    if (VARIAVEIS_SISTEMA_PERMITIDAS.has(chave) && valor !== undefined) {
      sanitizado[chave] = valor;
    }
  }

  // Define variáveis de contenção e isolamento offline
  sanitizado.NO_COLOR = '1';
  sanitizado.CI = '1';
  sanitizado.SEMGREP_ENABLE_VERSION_CHECK = '0';
  // Semgrep atual aceita `on`, `off` ou `auto`; `0` aborta antes da varredura.
  sanitizado.SEMGREP_SEND_METRICS = 'off';
  sanitizado.GITLEAKS_ENABLE_REPORT = '0';

  // Mescla env extra se fornecido
  if (envExtra && typeof envExtra === 'object') {
    for (const [k, v] of Object.entries(envExtra)) {
      if (v !== undefined) {
        sanitizado[k] = String(v);
      }
    }
  }

  return sanitizado;
}

/**
 * Executa um comando externo por subprocesso seguro, sem shell e com limites defensivos.
 * @param {string} executavel - Nome do binário ou caminho absoluto (ex: 'gitleaks', 'semgrep').
 * @param {string[]} [argumentos=[]] - Lista de argumentos em array.
 * @param {object} [opcoes={}] - Opções de execução.
 * @param {string} [opcoes.cwd] - Diretório de trabalho.
 * @param {number} [opcoes.timeout=30000] - Timeout em milissegundos.
 * @param {number} [opcoes.maxBuffer=5242880] - Limite máximo de buffer em bytes.
 * @param {object} [opcoes.env] - Variáveis de ambiente complementares.
 * @returns {{ status: 'SUCCESS' | 'ERROR' | 'UNAVAILABLE' | 'TIMEOUT' | 'BUFFER_OVERFLOW', exitCode: number | null, stdout: string, stderr: string, erro: Error | null }}
 */
export function executarProcessoSeguro(executavel, argumentos = [], opcoes = {}) {
  if (typeof executavel !== 'string' || !executavel.trim()) {
    throw new Error('Executável obrigatório para execução segura de subprocesso');
  }

  const cwd = opcoes.cwd || process.cwd();
  const timeout = Number.isInteger(opcoes.timeout) && opcoes.timeout > 0 ? opcoes.timeout : TIMEOUT_PADRAO_MS;
  const maxBuffer = Number.isInteger(opcoes.maxBuffer) && opcoes.maxBuffer > 0 ? opcoes.maxBuffer : BUFFER_MAXIMO_PADRAO;

  // Garante estritamente que shell é SEMPRE false e o ambiente é sanitizado
  const config = {
    cwd,
    timeout,
    maxBuffer,
    shell: false,
    windowsHide: true,
    encoding: 'utf8',
    env: criarAmbienteSanitizado(opcoes.env)
  };

  const resultado = spawnSync(executavel, argumentos, config);

  if (resultado.error) {
    if (resultado.error.code === 'ENOENT') {
      return {
        status: 'UNAVAILABLE',
        exitCode: null,
        stdout: '',
        stderr: `Binário '${executavel}' não foi encontrado no PATH do sistema.`,
        erro: resultado.error
      };
    }
    if (resultado.error.code === 'ETIMEDOUT') {
      return {
        status: 'TIMEOUT',
        exitCode: null,
        stdout: resultado.stdout || '',
        stderr: `Execução de '${executavel}' excedeu o limite de tempo de ${timeout}ms.`,
        erro: resultado.error
      };
    }
    if (resultado.error.code === 'ENOBUFS') {
      return {
        status: 'BUFFER_OVERFLOW',
        exitCode: null,
        stdout: resultado.stdout || '',
        stderr: `Saída do comando '${executavel}' excedeu o buffer máximo de ${maxBuffer} bytes.`,
        erro: resultado.error
      };
    }
    return {
      status: 'ERROR',
      exitCode: resultado.status,
      stdout: resultado.stdout || '',
      stderr: resultado.stderr || resultado.error.message,
      erro: resultado.error
    };
  }

  return {
    status: 'SUCCESS',
    exitCode: resultado.status,
    stdout: resultado.stdout || '',
    stderr: resultado.stderr || '',
    erro: null
  };
}

/**
 * Variante assíncrona usada quando o chamador precisa reagir a sinais enquanto
 * o subprocesso está ativo. Mantém o mesmo contrato da variante síncrona.
 */
export function executarProcessoSeguroAsync(executavel, argumentos = [], opcoes = {}) {
  if (typeof executavel !== 'string' || !executavel.trim()) {
    throw new Error('Executável obrigatório para execução segura de subprocesso');
  }

  const cwd = opcoes.cwd || process.cwd();
  const timeout = Number.isInteger(opcoes.timeout) && opcoes.timeout > 0 ? opcoes.timeout : TIMEOUT_PADRAO_MS;
  const maxBuffer = Number.isInteger(opcoes.maxBuffer) && opcoes.maxBuffer > 0 ? opcoes.maxBuffer : BUFFER_MAXIMO_PADRAO;
  const detached = opcoes.detached === true;

  return new Promise((resolve) => {
    let finalizado = false;
    let causa = null;
    let erroSpawn = null;
    let stdout = '';
    let stderr = '';
    let bytes = 0;
    let timerForcado = null;

    const filho = spawn(executavel, argumentos, {
      cwd,
      shell: false,
      windowsHide: true,
      detached,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: criarAmbienteSanitizado(opcoes.env)
    });

    const encerrarFilho = (sinal = 'SIGTERM') => {
      try {
        if (detached && filho.pid) process.kill(-filho.pid, sinal);
        else filho.kill(sinal);
      } catch {
        // O subprocesso já encerrou entre a verificação e o sinal.
      }
    };

    const abortar = () => {
      causa = causa || 'ABORTED';
      encerrarFilho('SIGKILL');
    };
    if (opcoes.signal) {
      if (opcoes.signal.aborted) abortar();
      else opcoes.signal.addEventListener('abort', abortar, { once: true });
    }

    const timer = setTimeout(() => {
      causa = causa || 'TIMEOUT';
      encerrarFilho('SIGTERM');
      timerForcado = setTimeout(() => encerrarFilho('SIGKILL'), 500);
      timerForcado.unref?.();
    }, timeout);
    timer.unref?.();

    const acumular = (tipo, chunk) => {
      const texto = String(chunk);
      bytes += Buffer.byteLength(texto);
      if (bytes > maxBuffer) {
        causa = causa || 'BUFFER_OVERFLOW';
        encerrarFilho('SIGTERM');
        return;
      }
      if (tipo === 'stdout') stdout += texto;
      else stderr += texto;
    };
    filho.stdout.setEncoding('utf8');
    filho.stderr.setEncoding('utf8');
    filho.stdout.on('data', (chunk) => acumular('stdout', chunk));
    filho.stderr.on('data', (chunk) => acumular('stderr', chunk));
    filho.once('error', (erro) => { erroSpawn = erro; });
    filho.once('close', (exitCode) => {
      if (finalizado) return;
      finalizado = true;
      clearTimeout(timer);
      if (timerForcado) clearTimeout(timerForcado);
      opcoes.signal?.removeEventListener('abort', abortar);

      if (erroSpawn?.code === 'ENOENT') {
        resolve({ status: 'UNAVAILABLE', exitCode: null, stdout: '', stderr: `Binário '${executavel}' não foi encontrado no PATH do sistema.`, erro: erroSpawn });
      } else if (causa === 'TIMEOUT') {
        resolve({ status: 'TIMEOUT', exitCode: null, stdout, stderr: `Execução de '${executavel}' excedeu o limite de tempo de ${timeout}ms.`, erro: erroSpawn });
      } else if (causa === 'BUFFER_OVERFLOW') {
        resolve({ status: 'BUFFER_OVERFLOW', exitCode: null, stdout, stderr: `Saída do comando '${executavel}' excedeu o buffer máximo de ${maxBuffer} bytes.`, erro: erroSpawn });
      } else if (causa === 'ABORTED') {
        resolve({ status: 'ERROR', exitCode, stdout, stderr: 'Subprocesso interrompido por encerramento do processo.', erro: erroSpawn });
      } else if (erroSpawn) {
        resolve({ status: 'ERROR', exitCode, stdout, stderr: stderr || 'Falha ao iniciar subprocesso.', erro: erroSpawn });
      } else {
        resolve({ status: 'SUCCESS', exitCode, stdout, stderr, erro: null });
      }
    });
  });
}
