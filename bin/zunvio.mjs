#!/usr/bin/env node
import { executarCli } from '../src/cli.mjs';

const codigoSaida = await executarCli(process.argv.slice(2));
if (codigoSaida !== 0) {
  process.exitCode = codigoSaida;
}
