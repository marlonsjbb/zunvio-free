#!/usr/bin/env node
// Atualiza a instalação global do zunvio-score para a versão mais recente
// publicada no npm. Só faz sentido pra quem instalou global
// (`npm install -g zunvio-score`) — quem usa via `npx zunvio-score` já
// recebe a versão mais recente a cada execução (exceto cache antigo, caso
// em que este mesmo comando também resolve limpando via reinstalação).
import { spawnSync } from 'node:child_process';

console.log('[zunvio-upgrade] Atualizando zunvio-score para a versão mais recente publicada no npm...');

const resultado = spawnSync('npm', ['install', '-g', 'zunvio-score@latest'], {
  stdio: 'inherit',
  shell: false
});

if (resultado.error) {
  console.error(`[zunvio-upgrade] Falha ao executar npm: ${resultado.error.message}`);
  process.exitCode = 1;
} else if (resultado.status !== 0) {
  console.error('[zunvio-upgrade] npm install retornou erro; veja a saída acima.');
  process.exitCode = resultado.status ?? 1;
} else {
  console.log('[zunvio-upgrade] Concluído. Rode "zunvio-score --version" para confirmar a versão instalada.');
}
