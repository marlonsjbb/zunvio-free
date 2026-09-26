#!/usr/bin/env node
import { executarCli } from '../src/cli.mjs';
import { garantirGitleaks, garantirSemgrep } from '../src/utils/engine-bootstrap.mjs';

const args = process.argv.slice(2);

async function provisionarMotores() {
  return {
    gitleaks: await garantirGitleaks(),
    semgrep: await garantirSemgrep()
  };
}

if (args[0] === 'skill') {
  if (args[1] === 'install') {
    const { instalarSkill } = await import('../src/skill-install.mjs');
    process.exitCode = instalarSkill();
  } else {
    console.error('Uso: zunvio skill install   (instala o atalho /zunvio-score no Claude Code)');
    process.exitCode = args[1] ? 2 : 0;
  }
} else {
  // O núcleo chama esta função somente depois do primeiro snapshot do alvo.
  // Help, versão, glossário, verify, notarize, init e revisar continuam sem provisionamento automático.
  // E2E mínimo: `npx zunvio-score` sem argumentos analisa '.' e PRECISA dos motores (antes caía em INCONCLUSIVO).
  const subcomandosSemMotor = new Set(['verify', 'glossario', 'notarize', 'init', 'revisar']);
  const deveProvisionar = !subcomandosSemMotor.has(args[0])
    && !args.includes('-h') && !args.includes('--help')
    && !args.includes('-v') && !args.includes('--version')
    ;
  // RF-08 (MASS-399): sensores informativos ligados por padrão só no binário
  // real — `executarAnaliseProjeto`/`executarCli` continuam com o padrão
  // desligado pra qualquer outro chamador (inclusive a suíte de testes, que
  // chama `executarCli` direto sem injetar runner fake pra eles).
  const codigoSaida = await executarCli(
    args,
    {},
    // persistir: relatório HTML, evolução e contexto do `init` na pasta do projeto fora do repositório (só no binário).
    deveProvisionar ? { provisionarMotores, ativarInformativos: true, persistir: true } : {}
  );
  if (codigoSaida !== 0) {
    process.exitCode = codigoSaida;
  }
}
