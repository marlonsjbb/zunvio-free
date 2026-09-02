#!/usr/bin/env node
import { executarCli } from '../src/cli.mjs';
import { garantirGitleaks, garantirSemgrep } from '../src/utils/engine-bootstrap.mjs';

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
  const semVarredura =
    args.length === 0 ||
    args.includes('-h') || args.includes('--help') ||
    args.includes('-v') || args.includes('--version') ||
    args[0] === 'verify';

  if (!semVarredura) {
    await garantirGitleaks();
    await garantirSemgrep();
  }

  const codigoSaida = await executarCli(args);
  if (codigoSaida !== 0) {
    process.exitCode = codigoSaida;
  }
}
