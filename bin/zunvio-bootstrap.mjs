#!/usr/bin/env node
// ZUNVIO bootstrap — preparação ASSISTIDA e não destrutiva da skill /zunvio-score.
//
// Decisão humana MASS-288 (#11329): o MVP NÃO promete instalação/desinstalação
// automática em diretórios externos. Este script é estritamente somente leitura:
// valida a fonte versionada, diagnostica o estado atual e imprime instruções
// EXATAS para que o usuário registre ou remova a integração por conta própria.
// A evolução para bootstrap automático seguro multiplataforma fica em MASS-304.
//
// Garantias: nenhum comando cria, altera ou remove arquivos, symlinks ou
// manifestos em DSH_AGENTS_HOME ou em diretórios de outros agentes. Sem upload,
// telemetria, download silencioso, eval, shell construído, credencial, sudo ou
// alteração de profile de shell.
import {
  existsSync,
  lstatSync,
  readFileSync,
  readlinkSync,
  realpathSync
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { criarAmbienteTemporarioSemgrep, limparTemporariosSemgrep } from '../src/scanners/semgrep-env.mjs';
import { executarProcessoSeguroAsync } from '../src/utils/process-runner.mjs';

const SCRIPT_PATH = realpathSync(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(dirname(SCRIPT_PATH), '..');
const SKILL_SOURCE = join(REPO_ROOT, 'integrations', 'skills', 'zunvio-score');
const SKILL_FILES = ['SKILL.md', 'agents/openai.yaml', 'scripts/run-zunvio-score.mjs'];

// Diretório de usuário suportado (o mesmo que Codex e DeepSeek varrem).
// Apenas LIDO para diagnóstico/instruções — nunca escrito por este script.
const AGENTS_HOME = resolve(process.env.DSH_AGENTS_HOME || join(homedir(), '.agents'));
const SKILLS_DIR = join(AGENTS_HOME, 'skills');
const SKILL_DEST = join(SKILLS_DIR, 'zunvio-score');
const LEGACY_MANIFEST = join(SKILLS_DIR, '.zunvio-bootstrap.json');

const PREREQ = [
  { nome: 'Node.js', executavel: process.execPath, args: ['--version'] },
  { nome: 'Git', executavel: 'git', args: ['--version'] },
  { nome: 'Gitleaks', executavel: 'gitleaks', args: ['version'] },
  { nome: 'Semgrep', executavel: 'semgrep', args: ['--version'] },
  // Opcional: só é necessário para `zunvio notarize` (RF-09/MASS-399). Ausência
  // não bloqueia scan/verify, só aparece como indisponível neste diagnóstico.
  { nome: 'OpenTimestamps (ots)', executavel: 'ots', args: ['--version'] }
];

function executar(executavel, argumentos, env) {
  const r = spawnSync(executavel, argumentos, {
    encoding: 'utf8',
    shell: false,
    timeout: 20_000,
    ...(env ? { env: { ...process.env, ...env } } : {})
  });
  return { ok: r.status === 0 && !r.error, stdout: r.stdout || '', stderr: r.stderr || '' };
}

function primeiraLinha(texto) {
  return String(texto || '').split(/\r?\n/)[0].trim().slice(0, 120);
}

function versaoFerramentaSegura(texto) {
  const match = /(?:^|[^0-9])v?(\d+\.\d+\.\d+)(?:[^0-9]|$)/.exec(String(texto || ''));
  return match ? match[1] : 'DETECTADO';
}

// Codifica qualquer caminho/texto externo como hexadecimal (dado puro), para que
// a saída assistida NUNCA contenha caminho cru, newline ou metacaractere que
// possa ser copiado como comando executável (P1 — newline/metacaracteres).
function hex(caminho) {
  return Buffer.from(String(caminho ?? ''), 'utf8').toString('hex');
}

function realpathQuiet(caminho) {
  try {
    return realpathSync(caminho);
  } catch {
    return null;
  }
}

function hashSkill() {
  const hasher = createHash('sha256');
  for (const arquivo of SKILL_FILES) {
    hasher.update(`${arquivo}\0`);
    hasher.update(readFileSync(join(SKILL_SOURCE, arquivo), 'utf8'));
    hasher.update('\0');
  }
  return hasher.digest('hex');
}

function origemGit() {
  const remote = executar('git', ['-C', REPO_ROOT, 'remote', 'get-url', 'origin']);
  const commit = executar('git', ['-C', REPO_ROOT, 'rev-parse', 'HEAD']);
  if (remote.ok && commit.ok) {
    return { remoteUrl: primeiraLinha(remote.stdout), commit: primeiraLinha(commit.stdout) };
  }
  return null;
}

function versaoCore() {
  try {
    const pacote = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'));
    return typeof pacote.version === 'string' ? pacote.version : null;
  } catch {
    return null;
  }
}

function validarFonte() {
  if (!existsSync(join(SKILL_SOURCE, 'SKILL.md'))) return { ok: false, motivo: 'SKILL.md ausente na fonte' };
  for (const arquivo of SKILL_FILES) {
    if (!existsSync(join(SKILL_SOURCE, arquivo))) return { ok: false, motivo: `${arquivo} ausente na fonte` };
  }
  return { ok: true, hash: hashSkill() };
}

function inspecionarDestino() {
  let stats;
  try {
    stats = lstatSync(SKILL_DEST);
  } catch {
    return { tipo: 'ausente' };
  }
  if (stats.isSymbolicLink()) {
    const alvo = readlinkSync(SKILL_DEST);
    const resolvido = realpathQuiet(SKILL_DEST);
    return { tipo: 'symlink', alvo, resolvido };
  }
  if (stats.isDirectory()) return { tipo: 'diretorio' };
  return { tipo: 'arquivo' };
}

// P3: o preflight usa EXATAMENTE o mesmo ambiente do scanner Semgrep (CA bundle,
// log/settings/version-cache e version-check desativado), via função compartilhada.
async function verificarPrerequisitos() {
  const semgrep = criarAmbienteTemporarioSemgrep();
  try {
    const resultados = [];
    for (const prereq of PREREQ) {
      const env = prereq.nome === 'Semgrep' ? semgrep.env : undefined;
      const r = await executarProcessoSeguroAsync(prereq.executavel, prereq.args, {
        timeout: 20_000,
        env,
        signal: semgrep.signal,
        detached: true
      });
      resultados.push({
        nome: prereq.nome,
        ok: r.status === 'SUCCESS' && r.exitCode === 0,
        versao: r.status === 'SUCCESS' && r.exitCode === 0
          ? versaoFerramentaSegura(r.stdout || r.stderr)
          : null
      });
    }
    return resultados;
  } finally {
    limparTemporariosSemgrep(semgrep);
  }
}

// Instruções estruturadas e NÃO executáveis: os caminhos são codificados como
// hexadecimal (dado puro), nunca como comando shell nem texto cru. Assim, um
// DSH_AGENTS_HOME hostil (aspas/newline/metacaracteres) não consegue injetar
// comando ao ser copiado (P1 — command injection/newline).
function instrucoesRegistro() {
  return [
    '  Ação 1: criar o diretório de skills.',
    `    Diretório (hex): ${hex(SKILLS_DIR)}`,
    '  Ação 2: criar um link simbólico apontando para a fonte versionada.',
    `    Origem (hex):  ${hex(SKILL_SOURCE)}`,
    `    Destino (hex): ${hex(SKILL_DEST)}`
  ];
}

function linhasPublicas(linhas, tech, detalhes) {
  const saida = [...linhas];
  if (tech) saida.push(...detalhes);
  return `${saida.join('\n')}\n`;
}

// install assistido: valida a fonte, diagnostica o estado e imprime instruções
// exatas. NÃO escreve em diretórios externos.
async function comandoInstall({ tech }) {
  const fonte = validarFonte();
  if (!fonte.ok) {
    return { code: 1, texto: linhasPublicas(
      ['Não foi possível preparar o ZUNVIO.', `Motivo: ${fonte.motivo}.`],
      tech,
      [`Fonte (hex): ${hex(SKILL_SOURCE)}`]
    ) };
  }

  const prereqs = await verificarPrerequisitos();
  const faltantes = prereqs.filter((p) => !p.ok);
  const destino = inspecionarDestino();
  const mesmoAlvo = destino.tipo === 'symlink'
    && destino.resolvido === realpathQuiet(SKILL_SOURCE);

  const linhas = ['ZUNVIO — preparação assistida (somente leitura).'];
  linhas.push('');
  linhas.push(`Fonte da skill (hex): ${hex(SKILL_SOURCE)}`);
  linhas.push(`Destino do registro (hex): ${hex(SKILL_DEST)}`);

  if (destino.tipo === 'symlink' && mesmoAlvo) {
    linhas.push('');
    linhas.push('Registro já aponta para a fonte versionada atual.');
    linhas.push('Nenhuma ação é necessária; use "doctor" para conferir.');
  } else if (destino.tipo === 'symlink' || destino.tipo === 'diretorio' || destino.tipo === 'arquivo') {
    linhas.push('');
    linhas.push(`Já existe algo em (hex): ${hex(SKILL_DEST)} (${destino.tipo}).`);
    linhas.push('Revise esse caminho antes de registrar; este script não o altera.');
  } else {
    linhas.push('');
    linhas.push('Para registrar, peça ao seu agente (ou faça manualmente) as ações abaixo:');
    linhas.push(...instrucoesRegistro());
  }

  linhas.push('');
  linhas.push('O ZUNVIO não cria, altera nem remove nada em diretórios externos.');
  linhas.push('Instalação automática segura: prevista para o pós-MVP (MASS-304).');

  if (faltantes.length) {
    linhas.push('');
    linhas.push(`Atenção: motores ausentes — ${faltantes.map((p) => p.nome).join(', ')}.`);
  }

  return { code: 0, texto: linhasPublicas(linhas, tech, [
    `Skill hash: ${fonte.hash}`,
    `Origem (hex): ${origemGit() ? hex(`${origemGit().remoteUrl} @ ${origemGit().commit}`) : 'sem origem git'}`,
    `Versão do core: ${versaoCore()}`,
    `Pré-requisitos: ${prereqs.map((p) => `${p.nome}=${p.ok ? (p.versao || 'ok') : 'AUSENTE'}`).join(' | ')}`
  ]) };
}

// doctor estritamente somente leitura: valida fonte, inspeciona destino e reporta.
async function comandoDoctor({ tech }) {
  const linhas = ['Verificando a integração do ZUNVIO (somente leitura)…'];

  const prereqs = await verificarPrerequisitos();
  const faltantes = prereqs.filter((p) => !p.ok);

  const destino = inspecionarDestino();
  const fonte = validarFonte();
  const fonteReal = realpathQuiet(SKILL_SOURCE);

  let ok = true;
  const detalhes = [
    `Agents home (hex): ${hex(AGENTS_HOME)}`,
    `Destino (hex): ${hex(SKILL_DEST)} (${destino.tipo})`,
    `Pré-requisitos: ${prereqs.map((p) => `${p.nome}=${p.ok ? (p.versao || 'ok') : 'AUSENTE'}`).join(' | ')}`
  ];

  if (!fonte.ok) {
    ok = false;
    linhas.push('Problema: a fonte versionada do ZUNVIO não está íntegra.');
    detalhes.push(`Fonte inválida: ${fonte.motivo}`);
  }

  if (destino.tipo !== 'symlink') {
    ok = false;
    linhas.push('Problema: a skill /zunvio-score não está registrada neste computador.');
    detalhes.push('Registro ausente (ou não é um symlink). Use "install" para ver as instruções.');
  } else if (!destino.resolvido) {
    ok = false;
    linhas.push('Problema: o registro aponta para uma fonte que não existe mais.');
    detalhes.push(`Symlink quebrado para (hex): ${hex(destino.alvo)}`);
  } else if (!fonteReal || destino.resolvido !== fonteReal) {
    ok = false;
    linhas.push('Problema: o registro aponta para uma fonte diferente da fonte versionada atual.');
    detalhes.push(`Resolvido (hex): ${hex(destino.resolvido)}`);
  }

  if (existsSync(LEGACY_MANIFEST)) {
    detalhes.push('Manifesto legado (.zunvio-bootstrap.json) presente; não é usado como prova no MVP assistido.');
  }

  if (faltantes.length) {
    linhas.push(`Atenção: motores ausentes — ${faltantes.map((p) => p.nome).join(', ')}.`);
  }

  if (ok) {
    linhas.push('Registro íntegro: o symlink aponta para a fonte versionada atual.');
    return { code: 0, texto: linhasPublicas(linhas, tech, detalhes) };
  }
  return { code: 1, texto: linhasPublicas(linhas, tech, detalhes) };
}

// uninstall assistido: somente leitura; imprime instruções exatas de remoção.
function comandoUninstall({ tech }) {
  const destino = inspecionarDestino();
  const linhas = ['ZUNVIO — remoção assistida (somente leitura).'];
  linhas.push('');
  linhas.push(`Caminho do registro (hex): ${hex(SKILL_DEST)}`);

  if (destino.tipo === 'symlink') {
    linhas.push('');
    linhas.push('Para remover o registro, peça ao seu agente (ou faça manualmente):');
    linhas.push('  Ação: remover o link simbólico de registro.');
    linhas.push(`    Caminho (hex): ${hex(SKILL_DEST)}`);
    if (existsSync(LEGACY_MANIFEST)) {
      linhas.push('  Ação opcional: remover o manifesto legado.');
      linhas.push(`    Caminho (hex): ${hex(LEGACY_MANIFEST)}`);
    }
  } else if (destino.tipo === 'ausente') {
    linhas.push('');
    linhas.push('Não há registro (symlink) para remover.');
  } else {
    linhas.push('');
    linhas.push(`Existe um caminho não gerenciado (${destino.tipo}); este script não o remove.`);
    linhas.push('Revise manualmente antes de qualquer ação.');
  }

  linhas.push('');
  linhas.push('O ZUNVIO não remove caminhos externos por conta própria.');
  return { code: 0, texto: linhasPublicas(linhas, tech, [
    `Destino (hex): ${hex(SKILL_DEST)} (${destino.tipo})`
  ]) };
}

function usarAjuda() {
  return `ZUNVIO — preparação assistida de primeiro uso (somente leitura, não destrutiva)

USO:
  node bin/zunvio-bootstrap.mjs [comando] [opções]

COMANDOS:
  install     validar a fonte e mostrar instruções exatas de registro (padrão)
  doctor      verificar a integração (estritamente somente leitura)
  uninstall   mostrar instruções exatas de remoção (não remove nada)

OPÇÕES:
  --tech      exibir detalhes técnicos
  -h, --help  esta ajuda

O MVP NÃO instala nem desinstala automaticamente em diretórios externos
(decisão MASS-288 #11329). A evolução automática segura fica em MASS-304.
`;
}

async function main() {
  const args = process.argv.slice(2);
  let comando = 'install';
  let tech = false;

  for (const arg of args) {
    if (arg === '--tech' || arg === '-v') tech = true;
    else if (arg === '-h' || arg === '--help') { process.stdout.write(usarAjuda()); return 0; }
    else if (arg === 'install' || arg === 'doctor' || arg === 'uninstall') comando = arg;
    else if (!arg.startsWith('-')) { /* tolera alias */ }
  }

  let resultado;
  if (comando === 'install') resultado = await comandoInstall({ tech });
  else if (comando === 'doctor') resultado = await comandoDoctor({ tech });
  else if (comando === 'uninstall') resultado = comandoUninstall({ tech });
  else { process.stderr.write(usarAjuda()); return 2; }

  if (resultado.code === 0) process.stdout.write(resultado.texto);
  else process.stderr.write(resultado.texto);
  return resultado.code;
}

process.exitCode = await main();
