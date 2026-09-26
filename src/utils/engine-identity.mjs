// Fatia 1 (Scanner Completeness): identidade suficiente do motor para reconstruir
// uma execução (Evidence Pack 0.3.0, volatileMetadata.engine).
//  - version: package.json do zunvio-score;
//  - commit: SHA do checkout do motor quando ele é um repositório Git; null quando
//    não é possível saber (ex.: instalado via npm) — nunca inventado;
//  - dirty: true quando src/ ou rules/ diferem do commit (o commit sozinho não
//    descreveria o código que rodou); null sem Git;
//  - codeDigest: SHA-256 determinístico de src/**/*.{mjs,json} e rules/** (caminho
//    relativo + SHA-256 do conteúdo com fim de linha normalizado para LF, em ordem),
//    que identifica o código mesmo sem Git e não muda entre checkouts CRLF/LF.
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, relative, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import packageJson from '../../package.json' with { type: 'json' };

const RAIZ_MOTOR = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
let cache = null;

function listar(dir, filtro) {
  const out = [];
  const walk = (d) => {
    let entradas;
    try { entradas = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entradas) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile() && filtro(e.name)) out.push(p);
    }
  };
  walk(dir);
  return out;
}

function git(args) {
  if (!existsSync(join(RAIZ_MOTOR, '.git'))) return null;
  try {
    return execFileSync('git', ['-C', RAIZ_MOTOR, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 });
  } catch {
    return null;
  }
}

function commitDoMotor() {
  const sha = git(['rev-parse', 'HEAD'])?.trim();
  return sha && /^[0-9a-f]{40}$/.test(sha) ? sha : null;
}

function codigoAlteradoDesdeOCommit() {
  const status = git(['status', '--porcelain=v1', '--', 'src', 'rules']);
  return status === null ? null : status.trim() !== '';
}

export function identidadeDoMotor() {
  if (cache) return cache;
  const arquivos = [
    ...listar(join(RAIZ_MOTOR, 'src'), (n) => n.endsWith('.mjs') || n.endsWith('.json')),
    ...listar(join(RAIZ_MOTOR, 'rules'), () => true)
  ].map((p) => relative(RAIZ_MOTOR, p).replace(/\\/g, '/')).sort();
  const h = createHash('sha256');
  for (const rel of arquivos) {
    const conteudo = readFileSync(join(RAIZ_MOTOR, rel), 'utf8').replace(/\r\n/g, '\n');
    h.update(`${rel}\0${createHash('sha256').update(conteudo).digest('hex')}\n`);
  }
  cache = Object.freeze({
    name: 'zunvio-score',
    version: packageJson.version,
    commit: commitDoMotor(),
    dirty: codigoAlteradoDesdeOCommit(),
    codeDigest: h.digest('hex'),
    codeDigestScope: 'src/**/*.{mjs,json} + rules/**'
  });
  return cache;
}
