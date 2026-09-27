// Abertura automática do relatório HTML no navegador padrão (comportamento público até a 0.1.14, perdido na troca
// de linhagem zunvio-free → zunvio-score da 0.1.15). Best-effort: abrir é entrega, não análise — nenhuma falha
// aqui muda decisão, código de saída ou o arquivo já gravado.
//
// O caminho NUNCA vira texto de comando: no Windows vai por variável de ambiente para um PowerShell de caminho
// absoluto (sem parsing do cmd.exe — `&`, `^`, `%VAR%` e aspas no caminho não são interpretados — e sem achar um
// executável homônimo na pasta analisada); no macOS/Linux vai como argumento único, sem shell.
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { extname, join } from 'node:path';

const VARIAVEL_CAMINHO = 'ZUNVIO_RELATORIO_HTML';
const SCRIPT_WINDOWS = "$ErrorActionPreference='Stop';"
  + '$i=New-Object System.Diagnostics.ProcessStartInfo;'
  + `$i.FileName=$env:${VARIAVEL_CAMINHO};`
  + '$i.UseShellExecute=$true;'
  + '[void][System.Diagnostics.Process]::Start($i)';
const ESPERA_MAXIMA_MS = 15000;

// Execução interativa: terminal real e fora de CI (mesmo critério da 0.1.14).
export function sessaoInterativa({ stdoutTTY = process.stdout.isTTY, env = process.env } = {}) {
  return Boolean(stdoutTTY) && !env.CI;
}

export function comandoAbertura(caminho, { plataforma = process.platform, env = process.env } = {}) {
  if (plataforma === 'win32') {
    const powershell = join(env.SystemRoot || env.windir || 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    return {
      executavel: powershell,
      args: ['-NoProfile', '-NonInteractive', '-Command', SCRIPT_WINDOWS],
      env: { ...env, [VARIAVEL_CAMINHO]: caminho }
    };
  }
  if (plataforma === 'darwin') return { executavel: '/usr/bin/open', args: [caminho], env };
  // Sem ambiente gráfico o xdg-open cairia num navegador de texto dentro do próprio terminal.
  if (!env.DISPLAY && !env.WAYLAND_DISPLAY) return null;
  return { executavel: 'xdg-open', args: [caminho], env };
}

/**
 * Abre o relatório já gravado. Resolve { aberto: true } (com confirmado: false se o abridor não retornou a tempo)
 * ou { aberto: false, motivo }, motivo em código fixo: ARQUIVO_AUSENTE, NAO_E_HTML, SEM_AMBIENTE_GRAFICO,
 * ABRIDOR_INDISPONIVEL, ABRIDOR_FALHOU. Nunca rejeita.
 */
export function abrirRelatorio(caminho, { plataforma = process.platform, env = process.env, spawnFn = spawn, esperaMs = ESPERA_MAXIMA_MS } = {}) {
  if (!caminho || !existsSync(caminho)) return Promise.resolve({ aberto: false, motivo: 'ARQUIVO_AUSENTE' });
  // Só .html vai ao navegador: com outra extensão (--relatorio) o Windows abre "Abrir com" e ainda responde sucesso.
  if (!['.html', '.htm'].includes(extname(caminho).toLowerCase())) return Promise.resolve({ aberto: false, motivo: 'NAO_E_HTML' });
  const comando = comandoAbertura(caminho, { plataforma, env });
  if (!comando) return Promise.resolve({ aberto: false, motivo: 'SEM_AMBIENTE_GRAFICO' });
  return new Promise((resolver) => {
    let filho;
    let fim = false;
    let relogio = null;
    const concluir = (resultado) => {
      if (fim) return;
      fim = true;
      if (relogio) clearTimeout(relogio);
      filho?.unref?.();
      resolver(resultado);
    };
    try {
      // Windows sem detached: com ele o PowerShell sai 0 sem o navegador receber o arquivo (medido no Chrome, 26/09).
      filho = spawnFn(comando.executavel, comando.args, {
        env: comando.env, stdio: 'ignore', shell: false, windowsHide: true, detached: plataforma !== 'win32'
      });
    } catch {
      concluir({ aberto: false, motivo: 'ABRIDOR_INDISPONIVEL' });
      return;
    }
    filho.on('error', () => concluir({ aberto: false, motivo: 'ABRIDOR_INDISPONIVEL' }));
    filho.on('exit', (codigo) => concluir(codigo === 0 ? { aberto: true } : { aberto: false, motivo: 'ABRIDOR_FALHOU' }));
    // Abridor que não retorna (ex.: xdg-open preso ao navegador) não segura o terminal: o pedido já foi feito.
    relogio = setTimeout(() => concluir({ aberto: true, confirmado: false }), esperaMs);
    relogio.unref?.();
  });
}

const MOTIVOS = Object.freeze({
  ARQUIVO_AUSENTE: 'o arquivo do relatório não foi encontrado depois de gravado',
  NAO_E_HTML: 'o arquivo não termina em .html',
  SEM_AMBIENTE_GRAFICO: 'não há ambiente gráfico nesta sessão',
  ABRIDOR_INDISPONIVEL: 'o programa que abre arquivos no sistema não está disponível',
  ABRIDOR_FALHOU: 'o sistema não conseguiu abrir o arquivo com o navegador padrão'
});

export function mensagemAbertura(resultado, caminhoLegivel) {
  if (resultado?.aberto) {
    return resultado.confirmado === false
      ? 'Abertura do relatório solicitada ao navegador padrão.'
      : 'Relatório aberto no navegador padrão.';
  }
  const motivo = MOTIVOS[resultado?.motivo] || 'motivo não identificado';
  return `Não foi possível abrir o relatório automaticamente (${motivo}). `
    + `A análise e o relatório estão preservados; abra no navegador: ${caminhoLegivel}`;
}
