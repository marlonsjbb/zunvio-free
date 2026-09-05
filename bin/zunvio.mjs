#!/usr/bin/env node
import { executarCli } from '../src/cli.mjs';
import { garantirGitleaks, garantirSemgrep } from '../src/utils/engine-bootstrap.mjs';
import { podeUsarIndicadorVisual } from '../src/utils/cli-progress.mjs';
import { iniciarChecagemVersao } from '../src/utils/version-check.mjs';
import packageJson from '../package.json' with { type: 'json' };

const args = process.argv.slice(2);

if (args[0] === 'skill') {
  if (args[1] === 'install') {
    const { instalarSkill } = await import('../src/skill-install.mjs');
    process.exitCode = instalarSkill();
  } else {
    console.error('Uso: zunvio skill install   (instala o atalho /zunvio-score no Claude Code)');
    process.exitCode = args[1] ? 2 : 0;
  }
} else {
  // O provisionamento (com consentimento do usuário) só faz sentido quando vai
  // haver varredura de verdade; ajuda/versão/verify não tocam em motor nenhum.
  // `zunvio` sem nenhum argumento É uma varredura real (escaneia o diretório
  // atual, `parseCliArgs` resolve target para '.') — nunca tratar isso como
  // "sem varredura", senão o bootstrap nunca roda e os motores cacheados em
  // `~/.zunvio` ficam invisíveis pro scanner (acharado real, 2026-09-04).
  const semVarredura =
    args.includes('-h') || args.includes('--help') ||
    args.includes('-v') || args.includes('--version') ||
    args[0] === 'verify' || args[0] === 'glossario';

  // Checagem de versão publicada (MASS-388, achado 3): disparada JÁ, em
  // paralelo com o resto da preparação abaixo (bootstrap dos motores, depois
  // a análise em si) — nunca atrasa o início do scan. `executarCli` só
  // aguarda o resultado (com o próprio timeout curto embutido, fail-open)
  // no momento de montar o relatório final. Nunca dispara fora de uma
  // análise real: `--help`/`--version`/`verify`/`glossario` seguem instantâneos.
  const checagemVersaoPromise = semVarredura ? null : iniciarChecagemVersao(packageJson.version);

  if (!semVarredura) {
    const indicadorVisual = podeUsarIndicadorVisual(args);
    await garantirGitleaks({ indicadorVisual });
    await garantirSemgrep({ indicadorVisual });
  }

  const codigoSaida = await executarCli(args, {}, { checagemVersaoPromise });
  if (codigoSaida !== 0) {
    process.exitCode = codigoSaida;
  }
}
