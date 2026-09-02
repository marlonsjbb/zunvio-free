#!/usr/bin/env node
import { executarCli } from '../src/cli.mjs';
import { garantirGitleaks } from '../src/utils/engine-bootstrap.mjs';

const args = process.argv.slice(2);

// O provisionamento (com consentimento do usuário) só faz sentido quando vai
// haver varredura de verdade; ajuda/versão/verify não tocam em motor nenhum.
const semVarredura =
  args.length === 0 ||
  args.includes('-h') || args.includes('--help') ||
  args.includes('-v') || args.includes('--version') ||
  args[0] === 'verify';

if (!semVarredura) {
  await garantirGitleaks();
}

const codigoSaida = await executarCli(args);
if (codigoSaida !== 0) {
  process.exitCode = codigoSaida;
}
