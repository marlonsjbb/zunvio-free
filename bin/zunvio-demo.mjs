#!/usr/bin/env node
// Demonstração local e reproduzível do valor do ZUNVIO.
//
// Roda a jornada completa a partir de diretórios temporários controlados, sem
// rede e sem alterar nada fora desses diretórios:
//   1. prepara o ZUNVIO (bootstrap único da MASS-282);
//   2. analisa um projeto sintético APTO;
//   3. analisa um projeto sintético BLOQUEADO (token falso);
//   4. aplica uma correção controlada e analisa de novo;
//   5. valida cada Evidence Pack/receipt gerado.
//
// Os projetos são 100% sintéticos; nenhum segredo operacional existe.
import {
  cpSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { verificarReceipt, RESULTADO } from '../src/receipt/verifier.mjs';

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const REPO_ROOT = resolve(dirname(SCRIPT_PATH), '..');
const CLI = join(REPO_ROOT, 'bin', 'zunvio.mjs');
const BOOTSTRAP = join(REPO_ROOT, 'bin', 'zunvio-bootstrap.mjs');
const FIXTURES = join(REPO_ROOT, 'examples', 'demo', 'fixtures');
const EVIDENCIA = join(FIXTURES, 'evidencias.json');

function fingerprintSeguro(valor) {
  return `fp:${createHash('sha256').update(String(valor ?? '')).digest('hex')}`;
}

function executar(executavel, argumentos, opcoes = {}) {
  return spawnSync(executavel, argumentos, {
    encoding: 'utf8',
    shell: false,
    maxBuffer: 64 * 1024 * 1024,
    ...opcoes
  });
}

function materializarProjeto(origem, destino, gitUser) {
  cpSync(origem, destino, { recursive: true });
  const git = (...args) => executar('git', ['-C', destino, ...args]);
  git('init', '-q');
  git('config', 'user.name', gitUser.name);
  git('config', 'user.email', gitUser.email);
  git('add', '-A');
  git('commit', '-qm', gitUser.commitMessage);
  return executar('git', ['-C', destino, 'rev-parse', 'HEAD']).stdout.trim();
}

// Contrato de Publicação v1 externo e completo (12 dimensões), com o vínculo de
// release preenchido pelo HEAD real do projeto analisado (B7).
function gerarContrato(head) {
  return {
    versaoContrato: '1.0.0',
    id: 'zunvio-demo-contract',
    cliente: 'Demonstração ZUNVIO',
    perfil: 'mvp-demo',
    dimensoes: {
      objetivoProduto: 'Projeto sintético para demonstrar o valor do ZUNVIO.',
      publicoUsuarios: 'Público de demonstração e avaliação.',
      jornadasCriticas: 'Executar a análise local read-only e obter uma decisão.',
      ambientePublicacao: 'CLI local read-only (sem servidor).',
      integracoesIndispensaveis: 'Git, Gitleaks e Semgrep locais.',
      dadosTratados: 'Código-fonte sintético de demonstração.',
      requisitosSegurancaPrivacidade: 'Análise local; nenhum código é enviado.',
      capacidadeDesempenho: 'Análise concluída em segundos.',
      requisitosLegaisRegulatorios: 'Nenhum requisito aplicável à demonstração.',
      operacaoRollback: 'Não aplicável à demonstração.',
      criteriosInaceitaveis: 'Qualquer segredo ou vulnerabilidade sintética detectada.',
      vinculoRelease: head
    }
  };
}

function analisar(projeto, evidencia, contrato) {
  const resultado = executar(process.execPath, [CLI, projeto, '--evidence', evidencia, '--contract', contrato, '--diff', '--json']);
  let relatorio = null;
  try {
    relatorio = JSON.parse(resultado.stdout);
  } catch {
    relatorio = null;
  }
  return { exitCode: resultado.status, relatorio };
}

// MASS-307: analisa SEM a evidência obrigatória de funcionamento, demonstrando o
// terceiro estado canônico INCONCLUSIVO (não PUBLICAR nem NÃO PUBLICAR).
function analisarSemEvidencia(projeto, contrato) {
  const resultado = executar(process.execPath, [CLI, projeto, '--contract', contrato, '--diff', '--json']);
  let relatorio = null;
  try {
    relatorio = JSON.parse(resultado.stdout);
  } catch {
    relatorio = null;
  }
  return { exitCode: resultado.status, relatorio };
}

// Grava o contrato v1 completo (com o HEAD real) em arquivo externo ao projeto.
function gravarContrato(raiz, nome, head) {
  const pasta = join(raiz, 'contratos');
  mkdirSync(pasta, { recursive: true });
  const caminho = join(pasta, `${nome}.json`);
  writeFileSync(caminho, `${JSON.stringify(gerarContrato(head), null, 2)}\n`, 'utf8');
  return caminho;
}

function resumoDe(relatorio) {
  if (!relatorio) return { decisao: 'FALHA FECHADA', score: null, cobertura: null, bloqueadores: [] };
  const decisao = relatorio.avaliacao?.decisao || {};
  const score = relatorio.avaliacao?.score || {};
  const grupos = decisao.impedimentos || {};
  const bloqueadores = [
    ...(grupos.reprovacoesProjeto || []),
    ...(grupos.semEvidenciaCliente || []),
    ...(grupos.falhasMotor || [])
  ];
  return {
    decisao: decisao.rotulo || decisao.decisaoPublicacao || 'INVÁLIDO',
    score: score.observado ?? null,
    maximo: score.maximoPossivel ?? null,
    cobertura: score.cobertura ?? null,
    bloqueadores
  };
}

// Explica, em linguagem comum, o que bloqueou / por que importa / o que fazer.
function explicarBloqueio(resumo) {
  const textos = [];
  for (const b of resumo.bloqueadores) {
    if (/segredo|credencial/i.test(b)) {
      textos.push('Um token sintético foi detectado no código (credencial exposta).');
      textos.push('Importa porque credenciais vazadas podem dar acesso indevido.');
      textos.push('O que fazer: remover/rotacionar o token e rodar a análise de novo.');
    } else if (/funcionamento|evidência/i.test(b)) {
      textos.push('Faltou a evidência de que o projeto funciona (testes).');
      textos.push('Importa porque sem prova não dá para afirmar que está pronto.');
      textos.push('O que fazer: fornecer a evidência de funcionamento e repetir.');
    } else {
      textos.push(`Bloqueio obrigatório identificado (${fingerprintSeguro(b)}).`);
      textos.push('Importa porque é um bloqueio obrigatório.');
      textos.push('O que fazer: resolver esse bloqueio e repetir.');
    }
  }
  return textos;
}

function main() {
  const inicio = Date.now();
  const raiz = mkdtempSync(join(tmpdir(), 'zunvio-demo çã Ω '));
  const agentsHome = join(raiz, 'home-agents');
  const projetos = join(raiz, 'projetos');
  mkdirSync(projetos, { recursive: true });

  const aptoDir = join(projetos, 'apto');
  const bloqueadoDir = join(projetos, 'bloqueado');
  const inconclusivoDir = join(projetos, 'inconclusivo');
  const corrigidoDir = join(projetos, 'corrigido');

  const linhas = [];
  linhas.push('============================================================');
  linhas.push('ZUNVIO — Demonstração local (projetos sintéticos)');
  linhas.push('============================================================');
  linhas.push('');

  // 1. Bootstrap único.
  linhas.push('1) Preparando o ZUNVIO neste computador (bootstrap único)…');
  const boot = executar(process.execPath, [BOOTSTRAP, 'install'], { env: { ...process.env, DSH_AGENTS_HOME: agentsHome } });
  linhas.push(boot.status === 0 ? '   → ZUNVIO pronto.' : '   → falha no bootstrap.');
  linhas.push('');

  try {
    const gitUser = { name: 'ZUNVIO Demo', email: 'demo@zunvio.invalid' };

    // 2. Projeto apto.
    const headApto = materializarProjeto(join(FIXTURES, 'apto'), aptoDir, { ...gitUser, commitMessage: 'demo: projeto apto' });
    const apto = analisar(aptoDir, EVIDENCIA, gravarContrato(raiz, 'apto', headApto));
    const resumoApto = resumoDe(apto.relatorio);

    linhas.push('2) Projeto "apto" (limpo, com contrato v1 e evidência válida):');
    linhas.push(`   → Decisão: ${resumoApto.decisao}`);
    linhas.push(`   → Score: ${resumoApto.score}/${resumoApto.maximo} | Cobertura: ${resumoApto.cobertura}%`);
    linhas.push(`   → Podemos avançar? ${resumoApto.decisao === 'PUBLICAR' ? 'Sim.' : 'Não.'}`);
    // PL-04/LC-06: sem cobertura de segredos demonstrada (arquivos e histórico Git), não há PUBLICAR — e o porquê é dito.
    if (resumoApto.decisao === 'INCONCLUSIVO') {
      linhas.push('   → Por que não PUBLICAR? Não há nenhum bloqueio, mas alguma cobertura exigida não foi comprovada (ex.: arquivos ou histórico Git de segredos); "nenhum achado" não comprova ausência. O ZUNVIO não afirma mais do que a evidência permite.');
    }
    linhas.push(`   → O que foi comprovado? ${resumoApto.cobertura}% dos portões (o restante é cobertura opcional, declarada honestamente).`);
    linhas.push('');

    // 3. Projeto bloqueado.
    const headBloqueado = materializarProjeto(join(FIXTURES, 'bloqueado'), bloqueadoDir, { ...gitUser, commitMessage: 'demo: projeto bloqueado' });
    const bloqueado = analisar(bloqueadoDir, EVIDENCIA, gravarContrato(raiz, 'bloqueado', headBloqueado));
    const resumoBloqueado = resumoDe(bloqueado.relatorio);
    linhas.push('3) Projeto "bloqueado" (token sintético de teste):');
    linhas.push(`   → Decisão: ${resumoBloqueado.decisao}`);
    linhas.push(`   → Score: ${resumoBloqueado.score}/${resumoBloqueado.maximo} | Cobertura: ${resumoBloqueado.cobertura}%`);
    for (const linha of explicarBloqueio(resumoBloqueado)) {
      linhas.push(`   → ${linha}`);
    }
    linhas.push('');

    // 4. Projeto inconclusivo (código limpo, mas SEM a evidência obrigatória de
    //    funcionamento). Demonstra o terceiro estado canônico INCONCLUSIVO.
    const headInconclusivo = materializarProjeto(join(FIXTURES, 'inconclusivo'), inconclusivoDir, { ...gitUser, commitMessage: 'demo: projeto inconclusivo' });
    const inconclusivo = analisarSemEvidencia(inconclusivoDir, gravarContrato(raiz, 'inconclusivo', headInconclusivo));
    const resumoInconclusivo = resumoDe(inconclusivo.relatorio);

    linhas.push('4) Projeto "inconclusivo" (código limpo, SEM evidência obrigatória de funcionamento):');
    linhas.push(`   → Decisão: ${resumoInconclusivo.decisao}`);
    linhas.push(`   → Score: ${resumoInconclusivo.score}/${resumoInconclusivo.maximo} | Cobertura: ${resumoInconclusivo.cobertura}%`);
    linhas.push('   → Por que INCONCLUSIVO? Falta a prova obrigatória de funcionamento — não há bloqueador material, mas também não há prova de atendimento.');
    linhas.push('');

    // 5. Correção controlada (remover o token e gerar um release limpo).
    //    A fonte de onde partimos é o fixture (sem histórico git), então o novo
    //    release não herda o token do histórico — o segredo some por completo.
    cpSync(join(FIXTURES, 'bloqueado'), corrigidoDir, { recursive: true });
    rmSync(join(corrigidoDir, 'src', 'config.js'), { force: true });
    const headAntes = executar('git', ['-C', bloqueadoDir, 'rev-parse', 'HEAD']).stdout.trim();
    executar('git', ['-C', corrigidoDir, 'init', '-q']);
    executar('git', ['-C', corrigidoDir, 'config', 'user.name', gitUser.name]);
    executar('git', ['-C', corrigidoDir, 'config', 'user.email', gitUser.email]);
    executar('git', ['-C', corrigidoDir, 'add', '-A']);
    executar('git', ['-C', corrigidoDir, 'commit', '-qm', 'demo: release limpo (token sintético removido)']);
    const headDepois = executar('git', ['-C', corrigidoDir, 'rev-parse', 'HEAD']).stdout.trim();
    const corrigido = analisar(corrigidoDir, EVIDENCIA, gravarContrato(raiz, 'corrigido', headDepois));
    const resumoCorrigido = resumoDe(corrigido.relatorio);

    linhas.push('5) Correção (remover o token) e reanálise:');
    linhas.push(`   → HEAD antes: ${headAntes}`);
    linhas.push(`   → HEAD depois: ${headDepois}`);
    // PL-04: a decisão responde à evidência quando o bloqueio comprovado some no novo release (PUBLICAR exigiria cobertura
    // comprovada de segredos, que hoje não existe).
    linhas.push(`   → A decisão responde à evidência? ${headAntes !== headDepois && resumoCorrigido.decisao !== resumoBloqueado.decisao && resumoCorrigido.decisao !== 'NÃO PUBLICAR' ? 'Sim (o bloqueio comprovado sumiu no novo release).' : 'Não.'}`);
    linhas.push(`   → Decisão: ${resumoCorrigido.decisao}`);
    linhas.push('');

    // 6. Validação dos receipts.
    const receipts = [
      ['apto', apto],
      ['bloqueado', bloqueado],
      ['inconclusivo', inconclusivo],
      ['corrigido', corrigido]
    ];
    linhas.push('6) Provas (Evidence Packs/receipts):');
    for (const [nome, r] of receipts) {
      const verificacao = r.relatorio ? verificarReceipt(r.relatorio) : { resultado: RESULTADO.INVALIDO, rotulo: 'INVÁLIDO' };
      const hash = r.relatorio?.canonicalHash ? `${r.relatorio.canonicalHash.slice(0, 12)}…` : 'indisponível';
      linhas.push(`   → ${nome}: ${verificacao.rotulo} (hash ${hash})`);
    }
    linhas.push('');

    linhas.push('Detalhes técnicos:');
    linhas.push(`   → Execução temporária: ${fingerprintSeguro(raiz)}`);
    linhas.push(`   → Resultado anterior permanece verificável (o Evidence Pack do bloqueado preserva o hash e o HEAD daquela análise).`);
    linhas.push(`   → Nenhum segredo operacional foi usado (token reservado para teste).`);
    linhas.push('');

    const duracao = ((Date.now() - inicio) / 1000).toFixed(1);
    linhas.push(`Tempo total da demonstração: ${duracao}s`);
    linhas.push('============================================================');

    process.stdout.write(`${linhas.join('\n')}\n`);
    return 0;
  } finally {
    rmSync(raiz, { recursive: true, force: true });
  }
}

process.exitCode = main();
