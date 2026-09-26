#!/usr/bin/env node

import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { gerarRelatorioHtml } from '../../../../src/report/html-report.mjs';
import { textoSeguroParaExibicao } from '../../../../src/utils/redactor.mjs';

const MAX_BUFFER = 64 * 1024 * 1024;
const SCRIPT_PATH = fileURLToPath(import.meta.url);

function executar(executavel, argumentos, opcoes = {}) {
  return spawnSync(executavel, argumentos, {
    encoding: 'utf8',
    maxBuffer: MAX_BUFFER,
    shell: false,
    ...opcoes
  });
}

function lerJson(caminho) {
  return JSON.parse(readFileSync(caminho, 'utf8'));
}

function resolverShaGit(caminho) {
  const resultado = executar('git', ['-C', caminho, 'rev-parse', 'HEAD']);
  if (resultado.status !== 0) return null;
  const sha = resultado.stdout.trim();
  return /^[a-f0-9]{40}$/.test(sha) ? sha : null;
}

function resolverRaizGit(caminho) {
  const resultado = executar('git', ['-C', caminho, 'rev-parse', '--show-toplevel']);
  if (resultado.status !== 0 || !resultado.stdout.trim()) return null;
  try {
    return realpathSync(resultado.stdout.trim());
  } catch {
    return null;
  }
}

export function resolverInstalacao() {
  const raizSkill = realpathSync(resolve(dirname(SCRIPT_PATH), '..'));
  const raizRepositorio = realpathSync(resolve(raizSkill, '../../..'));
  const manifesto = join(raizRepositorio, 'package.json');
  const cli = join(raizRepositorio, 'bin', 'zunvio.mjs');

  if (!existsSync(manifesto) || !existsSync(cli)) {
    throw new Error('Fonte versionada do ZUNVIO incompleta.');
  }

  const pacote = lerJson(manifesto);
  if (pacote.name !== 'zunvio-score' || typeof pacote.version !== 'string') {
    throw new Error('Manifesto canônico do ZUNVIO inválido.');
  }

  // Um pacote em node_modules pode estar dentro do repositório Git do projeto
  // consumidor. Por isso, não basta `git rev-parse`: a raiz versionada precisa
  // ser exatamente a raiz do próprio pacote e conter seu marcador .git.
  const temMarcadorGit = existsSync(join(raizRepositorio, '.git'));
  const raizGit = temMarcadorGit ? resolverRaizGit(raizRepositorio) : null;
  const checkoutLocal = raizGit === raizRepositorio;
  const coreSha = checkoutLocal ? resolverShaGit(raizRepositorio) : null;
  if (checkoutLocal && !coreSha) throw new Error('Não foi possível identificar o release do core ZUNVIO.');

  return {
    raizSkill,
    raizRepositorio,
    cli,
    coreSha,
    coreVersion: pacote.version,
    origem: checkoutLocal ? 'CHECKOUT_LOCAL' : 'PACOTE_NPM'
  };
}

export function resolverWorkspace(argumentos, cwd = process.cwd()) {
  if (argumentos.length > 1 || (argumentos[0] && argumentos[0].startsWith('-'))) {
    throw new Error('Informe no máximo um caminho de workspace, sem opções adicionais.');
  }

  const caminho = resolve(cwd, argumentos[0] || '.');
  if (!existsSync(caminho) || !statSync(caminho).isDirectory()) {
    throw new Error('O workspace informado não é um diretório válido.');
  }
  if (lstatSync(caminho).isSymbolicLink()) {
    throw new Error('A raiz do workspace não pode ser um link simbólico.');
  }
  return realpathSync(caminho);
}

function coletarBloqueadores(relatorio) {
  const decisao = relatorio.avaliacao?.decisao || {};
  const impedimentos = decisao.impedimentos || {};
  const grupos = [
    impedimentos.bloqueiosMateriaisDetectados,
    impedimentos.reprovacoesProjeto,
    impedimentos.semEvidenciaCliente,
    impedimentos.foraCoberturaMotor,
    impedimentos.falhasMotor,
    decisao.bloqueadores
  ];
  return [...new Set(grupos.flatMap((itens) => Array.isArray(itens) ? itens : []))];
}

function fingerprintSeguro(valor) {
  return `fp:${createHash('sha256').update(String(valor ?? '')).digest('hex')}`;
}

function hexSeguro(valor) {
  return Buffer.from(String(valor ?? ''), 'utf8').toString('hex');
}

function caminhoLegivelSeguro(valor) {
  return textoSeguroParaExibicao(valor, 320);
}

function citarCaminho(valor) {
  return `"${String(valor).replaceAll('"', '\\"')}"`;
}

export function montarInstrucoesVerificacao({ evidencePath, evidenceVersion, instalacao }) {
  const caminhoCitado = citarCaminho(evidencePath);
  const mesmaVersao = evidenceVersion === instalacao.coreVersion;
  const checkoutLocal = instalacao.origem === 'CHECKOUT_LOCAL';
  const linhas = [];

  if (checkoutLocal) {
    linhas.push(`VERIFICAR (CHECKOUT LOCAL) · ${citarCaminho(process.execPath)} ${citarCaminho(instalacao.cli)} verify ${caminhoCitado}`);
  } else if (mesmaVersao) {
    linhas.push(`VERIFICAR · npx zunvio-score verify ${caminhoCitado}`);
  } else {
    linhas.push(`VERIFICAR APÓS PUBLICAÇÃO DA v${evidenceVersion} · npx zunvio-score verify ${caminhoCitado}`);
  }

  if (!mesmaVersao) {
    linhas.push(`COMPATIBILIDADE · este Evidence Pack declara v${evidenceVersion}, diferente do pacote em execução v${instalacao.coreVersion}; a verificação via npx só funcionará depois de uma publicação que inclua a v${evidenceVersion}.`);
  }
  return linhas;
}

function gravarArtefatos({ relatorio, workspace, targetSha, instalacao }) {
  const pasta = mkdtempSync(join(tmpdir(), 'zunvio-score-'));
  const sufixo = (targetSha || 'sem-head-git').slice(0, 12);
  const evidencePath = join(pasta, `evidence-pack-${sufixo}.json`);
  const manifestPath = join(pasta, 'run-manifest.json');
  const htmlReportPath = join(pasta, 'zunvio-report.html');
  const evidenceJson = `${JSON.stringify(relatorio, null, 2)}\n`;
  const evidenceDigest = createHash('sha256').update(evidenceJson).digest('hex');
  const htmlReport = gerarRelatorioHtml(relatorio);
  const htmlReportDigest = createHash('sha256').update(htmlReport, 'utf8').digest('hex');

  writeFileSync(evidencePath, evidenceJson, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  writeFileSync(htmlReportPath, htmlReport, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  writeFileSync(manifestPath, `${JSON.stringify({
    schemaVersion: 1,
    workspaceFingerprint: fingerprintSeguro(workspace),
    targetHead: targetSha,
    coreVersion: instalacao.coreVersion,
    coreCommit: instalacao.coreSha,
    evidencePackSha256: evidenceDigest,
    evidencePack: basename(evidencePath),
    htmlReportSha256: htmlReportDigest,
    htmlReport: 'zunvio-report.html'
  }, null, 2)}\n`, { encoding: 'utf8', mode: 0o600, flag: 'wx' });

  return {
    evidencePath,
    manifestPath,
    htmlReportPath,
    artifactFingerprint: fingerprintSeguro(pasta)
  };
}

function montarResumo({ relatorio, workspace, targetSha, instalacao, artefatos, exitCode }) {
  const score = relatorio.avaliacao?.score || {};
  const decisao = relatorio.avaliacao?.decisao || {};
  // MASS-307 revisão: rótulo em três estados canônicos. Decisão desconhecida
  // NUNCA vira decisão de publicação: vira INVÁLIDO (falha fechada).
  const rotulo = decisao.decisaoPublicacao === 'PUBLICAR'
    ? 'PUBLICAR'
    : decisao.decisaoPublicacao === 'INCONCLUSIVO'
      ? 'INCONCLUSIVO'
      : decisao.decisaoPublicacao === 'NAO_PUBLICAR'
        ? 'NÃO PUBLICAR'
        : 'INVÁLIDO';
  const bloqueadores = coletarBloqueadores(relatorio).slice(0, 5);
  const motores = ['gitleaks', 'semgrep'].map((nome) => {
    const scanner = relatorio.scanners?.[nome] || {};
    const status = ['SUCCESS', 'UNAVAILABLE', 'ERROR', 'TIMEOUT', 'BUFFER_OVERFLOW']
      .includes(scanner.status)
      ? scanner.status
      : (scanner.disponivel ? 'ERROR' : 'UNAVAILABLE');
    const estadoOperacional = ['EXECUTADO', 'INDISPONIVEL', 'RECUSADO_PELO_USUARIO', 'FALHA_DE_EXECUCAO']
      .includes(scanner.estadoOperacional)
      ? scanner.estadoOperacional
      : status === 'SUCCESS'
        ? 'EXECUTADO'
        : status === 'UNAVAILABLE'
          ? 'INDISPONIVEL'
          : 'FALHA_DE_EXECUCAO';
    const rotuloEstado = {
      EXECUTADO: 'EXECUTADO',
      INDISPONIVEL: 'INDISPONÍVEL',
      RECUSADO_PELO_USUARIO: 'RECUSADO PELO USUÁRIO',
      FALHA_DE_EXECUCAO: 'FALHA DE EXECUÇÃO'
    }[estadoOperacional];
    const resultado = estadoOperacional === 'EXECUTADO'
      ? `${scanner.totalAchados ?? 0} achado(s) detectado(s)`
      : 'NÃO AVALIADO';
    const severidades = scanner.resumoSeveridade || {};
    const resumoSeveridades = estadoOperacional === 'EXECUTADO'
      ? `CRITICAL ${severidades.CRITICAL ?? 0} | HIGH ${severidades.HIGH ?? 0} | MEDIUM ${severidades.MEDIUM ?? 0} | LOW ${severidades.LOW ?? 0} | INFO ${severidades.INFO ?? 0}`
      : null;
    return { nome, estadoOperacional, rotuloEstado, resultado, resumoSeveridades };
  });
  // MASS-307: próxima ação por estado canônico. exitCode 2 = INCONCLUSIVO.
  const proximaAcao = exitCode === 0
    ? 'Prosseguir para avaliação humana do release.'
    : exitCode === 2
      ? (motores.some((item) => item.estadoOperacional !== 'EXECUTADO')
        ? 'Restaurar os motores indisponíveis e executar novamente.'
        : 'Fornecer as evidências obrigatórias ou o contrato de publicação e executar novamente.')
      : 'Revisar e resolver os bloqueios materiais detectados antes de executar novamente.';

  const linhas = [
    'ZUNVIO SCORE',
    `WORKSPACE · ${fingerprintSeguro(workspace)}`,
    `RELEASE · ${targetSha || 'SEM_HEAD_GIT'}`,
    `CORE · ${instalacao.coreVersion} @ ${instalacao.coreSha || 'PACOTE_NPM'}`,
    `DECISÃO · ${rotulo}`,
    `SCORE · ${score.observado ?? relatorio.decision?.score ?? 0}/${score.maximoPossivel ?? relatorio.decision?.maxPossibleScore ?? 100}`,
    `COBERTURA · ${score.cobertura ?? relatorio.decision?.coverage ?? 0}%`,
    'MOTORES'
  ];
  for (const motor of motores) {
    linhas.push(`  ${motor.nome} · OPERAÇÃO ${motor.rotuloEstado}`);
    linhas.push(`    RESULTADO DE SEGURANÇA · ${motor.resultado}`);
    if (motor.resumoSeveridades) linhas.push(`    SEVERIDADES · ${motor.resumoSeveridades}`);
  }

  const mapa = relatorio.claimEvidenceMap;
  if (mapa?.summary) {
    linhas.push(`CLAIMS · ATENDE ${mapa.summary.atende} | NÃO ATENDE ${mapa.summary.naoAtende} | NÃO COMPROVADO ${mapa.summary.naoComprovado} | COBERTURA ${mapa.coverage}%`);
  }

  if (bloqueadores.length === 0) {
    linhas.push('BLOQUEADORES · nenhum reportado');
  } else {
    linhas.push(`BLOQUEADORES · ${bloqueadores.map(fingerprintSeguro).join(' | ')}`);
  }
  linhas.push(`PRÓXIMA AÇÃO · ${proximaAcao}`);
  linhas.push(`ARTEFATOS · ${artefatos.artifactFingerprint}`);
  linhas.push(`RELATÓRIO HTML (hex) · ${hexSeguro(artefatos.htmlReportPath)}`);
  const evidencePath = caminhoLegivelSeguro(artefatos.evidencePath);
  linhas.push(`EVIDENCE PACK · ${evidencePath}`);
  linhas.push(...montarInstrucoesVerificacao({
    evidencePath,
    evidenceVersion: relatorio.versao,
    instalacao
  }));
  linhas.push(`MANIFESTO DA EXECUÇÃO (hex) · ${hexSeguro(artefatos.manifestPath)}`);
  const limitadas = linhas.map((linha) => (
    linha.length <= 400 ? linha : `LINHA_OMITIDA · ${fingerprintSeguro(linha)}`
  ));
  return `${limitadas.join('\n')}\n`;
}

export function executarRunner(argumentos = process.argv.slice(2), io = {}) {
  const stdout = io.stdout || ((texto) => process.stdout.write(texto));
  const stderr = io.stderr || ((texto) => process.stderr.write(texto));
  // Injeção de executor para testes (mesmo padrão de `runner` já usado em
  // src/delta/diff-parser.mjs e nos scanners): por padrão, spawnSync real.
  const executarCore = io.executar || executar;

  try {
    const instalacao = resolverInstalacao();
    const workspace = resolverWorkspace(argumentos);
    const targetSha = resolverShaGit(workspace);
    const resultado = executarCore(process.execPath, [instalacao.cli, workspace, '--json'], {
      cwd: instalacao.raizRepositorio,
      env: process.env
    });

    // MASS-307 (ressalva do runner): 3 é um código reconhecido do core (erro
    // operacional/uso), não um código desconhecido — precisa passar por este
    // portão para ser tratado explicitamente abaixo, e nunca ser confundido
    // com 2 (INCONCLUSIVO: análise concluída, decisão sem prova).
    if (resultado.error || resultado.signal || ![0, 1, 2, 3].includes(resultado.status)) {
      stderr('ZUNVIO SCORE · FALHA FECHADA\nMOTIVO · o core não concluiu com um código reconhecido.\n');
      return 3;
    }

    let relatorio;
    try {
      relatorio = JSON.parse(resultado.stdout);
    } catch {
      stderr('ZUNVIO SCORE · FALHA FECHADA\nMOTIVO · o core não produziu um Evidence Pack válido.\n');
      return 3;
    }

    // MASS-307: 2 = INCONCLUSIVO (análise concluída, decisão sem prova) segue
    // para o caminho de sucesso abaixo, com resultado.status propagado como
    // está. Só 3 (erro operacional/uso) ou relatorio.erro indicam falha
    // fechada do runner, e propagam 3 — nunca 2 — para o chamador.
    if (resultado.status === 3 || relatorio.erro) {
      stderr('ZUNVIO SCORE · FALHA FECHADA\nMOTIVO · workspace ou contexto inválido para análise.\n');
      return 3;
    }

    const artefatos = gravarArtefatos({ relatorio, workspace, targetSha, instalacao });
    stdout(montarResumo({ relatorio, workspace, targetSha, instalacao, artefatos, exitCode: resultado.status }));
    return resultado.status;
  } catch {
    // MASS-307: argumentos inválidos, workspace inválido ou instalação
    // incompleta são falhas operacionais/de uso do runner — 3, não 2.
    stderr('ZUNVIO SCORE · FALHA FECHADA\nMOTIVO · RUNNER_ERROR\n');
    return 3;
  }
}

const executadoDiretamente = process.argv[1]
  && existsSync(process.argv[1])
  && realpathSync(process.argv[1]) === realpathSync(SCRIPT_PATH);

if (executadoDiretamente) {
  process.exitCode = executarRunner();
}
