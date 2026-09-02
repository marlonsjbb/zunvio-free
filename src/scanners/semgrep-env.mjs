import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { resolverBundleCa } from '../utils/ca-bundle.mjs';

const PREFIXO = 'zunvio-semgrep-';
const RAIZES_ATIVAS = new Set();
const SINAIS = Object.freeze({ SIGINT: 130, SIGTERM: 143 });
let handlersInstalados = false;
let encerrando = false;
const CONTROLADORES_ATIVOS = new Set();

function removerRaiz(raiz) {
  try {
    const stats = lstatSync(raiz);
    if (!stats.isDirectory() || stats.isSymbolicLink()) return false;
    rmSync(raiz, { recursive: true, force: true });
    return true;
  } catch (erro) {
    return erro?.code === 'ENOENT';
  }
}

function pidEstaVivo(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (erro) {
    return erro?.code === 'EPERM';
  }
}

function marcadorConfirmaPropriedade(caminho, pid) {
  try {
    const marcador = join(caminho, '.zunvio-owner');
    const stats = lstatSync(marcador);
    if (!stats.isFile() || stats.isSymbolicLink()) return false;
    return readFileSync(marcador, 'utf8') === `${pid}\n`;
  } catch {
    return false;
  }
}

/**
 * Recupera somente resíduos ZUNVIO cujo PID proprietário não existe mais.
 * Symlinks e diretórios de processos vivos nunca são seguidos/removidos.
 */
export function limparResiduosSemgrep(raizBase = tmpdir()) {
  const removidos = [];
  let nomes;
  try {
    nomes = readdirSync(raizBase);
  } catch {
    return removidos;
  }
  for (const nome of nomes) {
    const match = /^zunvio-semgrep-(\d+)-[A-Za-z0-9_-]+$/.exec(nome);
    if (!match) continue;
    const pid = Number(match[1]);
    if (pid === process.pid || pidEstaVivo(pid)) continue;
    const caminho = join(raizBase, nome);
    try {
      const stats = lstatSync(caminho);
      if (!stats.isDirectory() || stats.isSymbolicLink()) continue;
    } catch {
      continue;
    }
    if (!marcadorConfirmaPropriedade(caminho, pid)) continue;
    if (removerRaiz(caminho)) removidos.push(caminho);
  }
  return removidos;
}

function tratarSinal(sinal) {
  if (encerrando) return;
  encerrando = true;
  for (const controlador of [...CONTROLADORES_ATIVOS]) controlador.abort();
  CONTROLADORES_ATIVOS.clear();
  for (const raiz of [...RAIZES_ATIVAS]) {
    removerRaiz(raiz);
    RAIZES_ATIVAS.delete(raiz);
  }
  for (const nomeSinal of Object.keys(SINAIS)) process.removeListener(nomeSinal, tratarSinal);
  handlersInstalados = false;
  try {
    process.kill(process.pid, sinal);
  } catch {
    process.exit(SINAIS[sinal] || 1);
  }
}

function instalarHandlers() {
  if (handlersInstalados) return;
  encerrando = false;
  for (const sinal of Object.keys(SINAIS)) process.on(sinal, tratarSinal);
  handlersInstalados = true;
}

/**
 * Constrói o ambiente COMPLETO do Semgrep — um diretório temporário EXCLUSIVO
 * por execução, apontando TMPDIR, log, settings e version-cache para essa raiz.
 * Assim, todos os filhos criados pelo Semgrep (incluindo `semgrep-mcp`) ficam
 * dentro da raiz e são removidos em `limparTemporariosSemgrep` (P3).
 * @returns {{ raiz: string, signal: AbortSignal, controlador: AbortController, env: Record<string, string> }}
 */
export function criarAmbienteTemporarioSemgrep() {
  const raizBase = tmpdir();
  limparResiduosSemgrep(raizBase);
  instalarHandlers();
  const raiz = mkdtempSync(join(raizBase, `${PREFIXO}${process.pid}-`));
  const controlador = new AbortController();
  RAIZES_ATIVAS.add(raiz);
  CONTROLADORES_ATIVOS.add(controlador);
  try {
    writeFileSync(join(raiz, '.zunvio-owner'), `${process.pid}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx'
    });
  } catch (erro) {
    removerRaiz(raiz);
    RAIZES_ATIVAS.delete(raiz);
    CONTROLADORES_ATIVOS.delete(controlador);
    throw erro;
  }
  const bundleCa = resolverBundleCa();
  return {
    raiz,
    signal: controlador.signal,
    controlador,
    env: {
      TMPDIR: raiz,
      SEMGREP_ENABLE_VERSION_CHECK: '0',
      SEMGREP_SEND_METRICS: 'off',
      SEMGREP_LOG_FILE: join(raiz, 'semgrep.log'),
      SEMGREP_SETTINGS_FILE: join(raiz, 'settings.yml'),
      SEMGREP_VERSION_CACHE_PATH: join(raiz, 'version-cache'),
      ...(bundleCa ? { SSL_CERT_FILE: bundleCa } : {})
    }
  };
}

/**
 * Remove a raiz INTEIRA do ambiente Semgrep (recursivo), incluindo logs, settings,
 * version-cache e diretórios criados pelo próprio Semgrep (ex.: semgrep-mcp).
 * Nunca lança: a limpeza é best-effort em sucesso, erro ou interrupção.
 * @param {{ raiz?: string }} ambiente
 */
export function limparTemporariosSemgrep(ambiente) {
  if (ambiente && typeof ambiente.raiz === 'string') {
    removerRaiz(ambiente.raiz);
    RAIZES_ATIVAS.delete(ambiente.raiz);
    if (ambiente.controlador) CONTROLADORES_ATIVOS.delete(ambiente.controlador);
    // O listener permanece até o processo encerrar: um sinal pode chegar no
    // limite entre o fechamento do filho e este finally. Removê-lo aqui poderia
    // engolir SIGTERM. Sem raízes ativas ele apenas restaura o término padrão,
    // reemitindo o sinal, e não mantém o event loop aberto.
  }
}
