import { resolve } from 'node:path';
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync as execFileSyncCli } from 'node:child_process';
import {
  contextoDeclarado, executarInit, executarRevisar, formatarEvolucao, gravarRelatorio, registrarEvolucao, registrarRevisaveis
} from './cli-produto.mjs';
import { gerarRelatorioHtml } from './report/html-report.mjs';
import { createHash } from 'node:crypto';
import { executarAnaliseProjeto } from './orchestrator.mjs';
import { VERSAO_EVIDENCE_PACK } from './models/evidence-pack.mjs';
import { apoiosDaDecisao, descreverApoios, TITULO_APOIOS } from './report/apoios.mjs';
import packageJson from '../package.json' with { type: 'json' };
import { verificarReceipt, RESULTADO } from './receipt/verifier.mjs';
import { notarizarCanonicalHash, STATUS_NOTARIZACAO } from './receipt/notarizacao-ots.mjs';
import { ID_SENSOR as ID_SENSOR_COMENTARIOS } from './scanners/dangerous-comments.mjs';
import { ID_SENSOR as ID_SENSOR_DEPENDENCIAS } from './scanners/dependency-audit.mjs';
import { ID_SENSOR as ID_SENSOR_FRONTEND_ENV } from './scanners/frontend-env-exposure.mjs';
import { calcularHashCanonico } from './utils/canonical-json.mjs';
import { textoSeguroParaExibicao } from './utils/redactor.mjs';
import { TERMOS_GLOSSARIO } from './glossary/termos.mjs';
import { criarIndicadorEtapas } from './utils/cli-progress.mjs';
import { selecionarBanner } from './branding/banner.mjs';

// Versão do produto/CLI deriva do package.json. A versão do Evidence Pack/schema
// (0.2.0) é independente e aparece separadamente no relatório — não são a mesma coisa.
const VERSAO = packageJson.version;

export function parseCliArgs(args = []) {
  let target = null;
  let json = false;
  let help = false;
  let version = false;
  let diff = false;
  let baseRef = null;
  let headRef = null;
  let caminhoContrato = null;
  let caminhoEvidencias = null;
  let includeVendor = false;
  let noBanner = false;
  let caminhoRelatorio = null;

  // `analyze` não existe mais como comando (26/09). Aceito em silêncio só por compatibilidade com quem copiou a
  // forma antiga (npm 0.1.14); não é documentado.
  const inicio = args[0] === 'analyze' ? 1 : 0;

  for (let i = inicio; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      help = true;
    } else if (arg === '--version' || arg === '-v') {
      version = true;
    } else if (arg === '--json') {
      json = true;
    } else if (arg === '--relatorio') {
      caminhoRelatorio = args[++i] ?? null;
    } else if (arg === '--include-vendor') {
      includeVendor = true;
    } else if (arg === '--no-banner') {
      noBanner = true;
    } else if (arg === '--diff' || arg === '-d') {
      diff = true;
    } else if (arg === '--base' || arg === '--since') {
      baseRef = args[++i];
      diff = true;
    } else if (arg === '--head') {
      headRef = args[++i];
      diff = true;
    } else if (arg === '--contract' || arg === '-c') {
      caminhoContrato = args[++i];
    } else if (arg === '--evidence' || arg === '--evidences' || arg === '-e') {
      caminhoEvidencias = args[++i];
    } else if (arg === '--target' || arg === '-t') {
      target = args[++i];
    } else if (!arg.startsWith('-') && !target) {
      target = arg;
    }
  }

  return {
    target: target || '.',
    json,
    help,
    version,
    diff,
    baseRef,
    headRef,
    caminhoContrato,
    caminhoEvidencias,
    ...(includeVendor ? { includeVendor: true } : {}),
    ...(noBanner ? { noBanner: true } : {}),
    ...(caminhoRelatorio ? { caminhoRelatorio } : {})
  };
}

export function gerarTextoAjuda() {
  return `
ZUNVIO Score v${VERSAO} — Avaliação de Prontidão e Análise Estática Segura (Read-Only)

USO:
  npx zunvio-score [caminho-do-projeto] [opções]
  npx zunvio-score verify <receipt.json>
  npx zunvio-score notarize <receipt.json>
  npx zunvio-score glossario
  npx zunvio-score init [caminho-do-projeto]         descreve o projeto e como ele foi testado
  npx zunvio-score revisar <chave> [caminho]         registra a revisão humana de um item "REVISÃO NECESSÁRIA"

OPÇÕES:
  -t, --target <dir>       Caminho do diretório local a analisar (padrão: '.')
  -c, --contract <arquivo> Caminho do arquivo JSON do contrato de publicação
  -e, --evidence <arquivo> Caminho do arquivo JSON com evidências adicionais
  -d, --diff               Habilita a análise de delta Git e cálculo de Blast Radius
  --base, --since <ref>    Referência Git base para o diff (ex: 'main', 'HEAD~1')
  --head <ref>             Referência Git de destino para o diff (padrão: 'HEAD')
  --json                   Exibe a saída em formato JSON estruturado
  --include-vendor         Inclui dependências vendorizadas; achados ficam informativos
  --no-banner              Omite a arte do banner do relatório humano
  --relatorio <arquivo>    Onde gravar o relatório HTML (padrão: ~/.zunvio/projetos/<projeto>/relatorios)
  -h, --help               Exibe esta mensagem de ajuda
  -v, --version            Exibe a versão do ZUNVIO

EXEMPLOS:
  npx zunvio-score
  npx zunvio-score ./meu-projeto --contract ./zunvio-contract.json
  npx zunvio-score ./meu-projeto --evidence ./evidences.json --json
  npx zunvio-score --diff --base origin/main
  npx zunvio-score verify ./score-receipt.json
  npx zunvio-score notarize ./score-receipt.json
  npx zunvio-score glossario

DECISÃO (código de saída):
  0 = PUBLICAR      avaliação obrigatória concluída e nenhum bloqueador
  1 = NÃO PUBLICAR  achado alto a revisar ou outra reprovação material
  2 = INCONCLUSIVO  sensor ausente/falha/timeout/truncamento/cobertura insuficiente
  3 = erro          uso inválido ou falha operacional
`;
}

// Extrai o SHA de 40 hex do release auditado a partir do portão de proveniência
// (dado já existente no Evidence Pack; nada é inventado). Retorna null quando o
// alvo não é um repositório Git auditável.
function extrairShaRelease(relatorio) {
  const portoes = relatorio?.avaliacao?.portoes || [];
  const prov = portoes.find((p) => p.id === 'proveniencia_auditabilidade');
  if (!prov) return null;
  for (const evidencia of prov.evidencias || []) {
    const m = /[0-9a-f]{40}/i.exec(String(evidencia));
    if (m) return m[0];
  }
  return null;
}

// Tabela determinística de impacto curto e próxima ação concreta por portão
// bloqueante. A "causa comprovada" vem dos próprios dados do portão (evidências/
// motivo); aqui se definem apenas impacto e ação derivados do tipo do portão e da
// subcausa — sem inventar arquivo, linha, severidade, proprietário ou remediação.
const ACAO_POR_PORTAO = Object.freeze({
  segredos: Object.freeze({
    NAO_ATENDE: Object.freeze({
      impacto: 'Credencial/segredo exposto bloqueia a publicação.',
      acao: 'Remova ou rotacione o segredo detectado e repita a análise.'
    }),
    MOTOR_FALHOU: Object.freeze({
      impacto: 'Sem cobertura de segredos: não há prova de ausência de segredos.',
      acao: 'Restaure o ambiente da ferramenta (git e Gitleaks, usados no histórico) e repita a análise.'
    }),
    // LC-06: achado aceito pela baseline do próprio projeto — declaração do avaliado não comprova ausência.
    SEM_EVIDENCIA_DO_CLIENTE: Object.freeze({
      impacto: 'Há segredo aceito pela baseline do próprio projeto; o aceite do avaliado não comprova ausência de segredos.',
      acao: 'Remova ou rotacione o segredo e retire a entrada da baseline (.zunvio-baseline.json); depois repita a análise.'
    }),
    // PL-04 (portão Segredos = opção A): nenhum segredo encontrado ≠ ausência comprovada de segredos.
    FORA_DE_COBERTURA_DO_MOTOR: Object.freeze({
      impacto: 'Nenhum segredo foi encontrado pelo sensor, mas não foi possível comprovar quais arquivos ele analisou; isso não comprova ausência de segredos.',
      acao: 'Não há o que corrigir no projeto por este motivo: é um limite atual do ZUNVIO. Revise segredos por outro meio antes de publicar.'
    })
  }),
  seguranca_estatica: Object.freeze({
    NAO_ATENDE: Object.freeze({
      impacto: 'Há pontos no código do projeto que impedem a publicação: risco demonstrado ou revisão pendente.',
      acao: 'Veja cada item em "Detalhamento dos Achados". Corrija o que for risco. Se um item marcado "REVISÃO NECESSÁRIA" foi revisado e não é risco neste contexto, registre a revisão com o comando indicado no próprio item. Depois repita a análise.'
    }),
    MOTOR_FALHOU: Object.freeze({
      impacto: 'Sem cobertura de SAST: não há prova de ausência de vulnerabilidades.',
      acao: 'Instale ou restaure o Semgrep no ambiente da ferramenta e repita a análise.'
    })
  }),
  funcionamento: Object.freeze({
    NAO_ATENDE: Object.freeze({
      impacto: 'Jornada crítica sem comprovação de funcionamento.',
      acao: 'Corrija a falha comprovada e forneça evidência de funcionamento aprovada.'
    }),
    SEM_EVIDENCIA_DO_CLIENTE: Object.freeze({
      impacto: 'Não há prova de que o release funciona.',
      acao: 'Declare como o projeto foi testado respondendo a "npx zunvio-score init" e repita a análise.'
    })
  }),
  integridade: Object.freeze({
    NAO_ATENDE: Object.freeze({
      impacto: 'O alvo mudou durante a análise; read-only não comprovado.',
      acao: 'Garanta um alvo estável durante a análise e repita.'
    }),
    MOTOR_FALHOU: Object.freeze({
      impacto: 'Integridade read-only não pôde ser comprovada.',
      acao: 'Garanta acesso de leitura ao alvo e repita a análise.'
    }),
    // PL-01: acima do limite operacional o digest cobre só parte do projeto — não houve alteração detectada.
    FORA_DE_COBERTURA_DO_MOTOR: Object.freeze({
      impacto: 'O projeto passa do limite operacional do ZUNVIO: a integridade foi verificada só em parte.',
      acao: 'Para uma verificação completa, analise um recorte menor do projeto (por exemplo, um subdiretório).'
    })
  }),
  proveniencia_auditabilidade: Object.freeze({
    NAO_ATENDE: Object.freeze({
      impacto: 'Release sem vínculo comprovado com o artefato analisado.',
      acao: 'Corrija o vínculo de release (commit/proveniência) e repita a análise.'
    }),
    SEM_EVIDENCIA_DO_CLIENTE: Object.freeze({
      impacto: 'Release sem proveniência auditável.',
      acao: 'Forneça o commit/SHA exato do release analisado e repita a análise.'
    })
  })
});

function descreverAcao(portao, contexto = {}) {
  const tabela = ACAO_POR_PORTAO[portao.id];
  let impacto = 'Requisito não atendido.';
  let acao = 'Resolva o requisito indicado e repita a análise.';
  if (tabela) {
    const chave = portao.estado === 'NAO_COMPROVADO' ? (portao.subcausa || '') : 'NAO_ATENDE';
    // PL-01 + PL-04: o sensor executou, mas a análise não foi comprovadamente completa (arquivos fora, limite
    // operacional, timeout...). Não é falha de instalação — a ação é entender o que ficou de fora.
    const analiseIncompleta = portao.estado === 'NAO_COMPROVADO' && portao.subcausa === 'MOTOR_FALHOU'
      && typeof portao.motivo === 'string'
      && (portao.motivo.startsWith('A análise do sensor não foi comprovadamente completa') || portao.motivo.startsWith('A análise de segredos dos arquivos não foi comprovadamente completa'));
    // LC-06: o histórico Git não foi comprovadamente varrido (ex.: clone raso) — não é falha do projeto nem instalação.
    const historicoNaoComprovado = portao.id === 'segredos' && portao.estado === 'NAO_COMPROVADO'
      && portao.subcausa === 'FORA_DE_COBERTURA_DO_MOTOR' && typeof portao.motivo === 'string' && portao.motivo.startsWith('O histórico Git esperado');
    // E2E mínimo: a incompletude do Semgrep vem de arquivos lidos só em parte (ex.: "&" solto em JSX). A ação é
    // olhar a lista — arquivo, trecho e como resolver —, não reduzir o recorte da análise.
    const lidosEmParte = portao.id === 'seguranca_estatica' && analiseIncompleta && Number.isInteger(contexto.lidosEmParte)
      ? contexto.lidosEmParte : 0;
    const desc = lidosEmParte > 0
      ? {
          impacto: `O analisador leu ${lidosEmParte} arquivo(s) só em parte: a ausência de achados nesses trechos não comprova ausência de problemas.`,
          acao: 'Veja "Lido em parte" em "Status dos Motores": cada arquivo aparece com o trecho que o analisador não reconheceu e como resolver. Ajuste e repita a análise.'
        }
      : historicoNaoComprovado
      ? {
          impacto: 'Nenhum segredo foi encontrado, mas não foi possível comprovar que todo o histórico Git foi varrido; isso não comprova ausência de segredos no histórico.',
          acao: 'Analise a raiz do repositório com o histórico completo (sem clone raso: git fetch --unshallow) e repita a análise.'
        }
      : analiseIncompleta
      ? {
          impacto: 'A análise não cobriu todo o código esperado: a ausência de achados não comprova ausência de problemas.',
          acao: 'Veja em "Status dos Motores" o que ficou fora da análise e por quê; se o projeto passa do limite operacional, analise um recorte menor.'
        }
      : (tabela[chave] || tabela.NAO_ATENDE);
    if (desc) {
      impacto = desc.impacto;
      acao = desc.acao;
    }
  }
  // B6: a "causa" NÃO imprime conteúdo bruto de scanner/evidência (que poderia
  // carregar prompt injection em qualquer idioma). Usa um resumo SEGURO derivado
  // somente de campos estruturados (nome canônico/estado/subcausa validada).
  const nome = NOMES_PORTAO[portao.id] || 'Portão não identificado';
  const subcausa = portao.estado === 'NAO_COMPROVADO' && SUBCAUSAS_VALIDAS.has(portao.subcausa)
    ? ` (${portao.subcausa})`
    : '';
  const causa = portao.estado === 'NAO_COMPROVADO'
    ? `Portão "${nome}" não comprovado${subcausa}.`
    : `Portão "${nome}" não atendido.`;
  return { causa, impacto, acao };
}

// B6: nomes canônicos de portão e conjuntos de enum/pattern aceitos na saída
// humana. A regra é: imprimir SOMENTE números, enums validados, hex digests,
// fingerprints e templates fixos — nunca texto bruto externo.
const NOMES_PORTAO = Object.freeze({
  segredos: 'Segredos e credenciais',
  seguranca_estatica: 'Segurança estática',
  funcionamento: 'Funcionamento e testes',
  integridade: 'Integridade read-only',
  proveniencia_auditabilidade: 'Proveniência e vínculo ao release',
  impacto_delta: 'Impacto do delta',
  manutencao_documentacao: 'Manutenção e documentação'
});
const ROTULOS_DIMENSOES_CONTRATO = Object.freeze({
  objetivoProduto: 'Objetivo do produto',
  publicoUsuarios: 'Público e usuários',
  jornadasCriticas: 'Jornadas críticas',
  ambientePublicacao: 'Ambiente de publicação',
  integracoesIndispensaveis: 'Integrações indispensáveis',
  dadosTratados: 'Dados tratados',
  requisitosSegurancaPrivacidade: 'Segurança e privacidade',
  capacidadeDesempenho: 'Capacidade e desempenho',
  requisitosLegaisRegulatorios: 'Requisitos legais e regulatórios',
  operacaoRollback: 'Operação e rollback',
  criteriosInaceitaveis: 'Critérios inaceitáveis',
  vinculoRelease: 'Vínculo com a release'
});
const SUBCAUSAS_VALIDAS = new Set(['SEM_EVIDENCIA_DO_CLIENTE', 'FORA_DE_COBERTURA_DO_MOTOR', 'MOTOR_FALHOU']);
const ENUM_SEVERIDADE = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
const ENUM_PEGADA = new Set(['NENHUMA', 'LOCALIZADA', 'MODULAR', 'TRANSVERSAL']);
const ENUM_RISCO = new Set(['BAIXO', 'MEDIO', 'ALTO']);
// LC-06: NOT_RUN = o Gitleaks não tinha histórico Git a varrer.
const ENUM_STATUS = new Set(['SUCCESS', 'UNAVAILABLE', 'ERROR', 'TIMEOUT', 'BUFFER_OVERFLOW', 'NOT_RUN']);
const ENUM_NATUREZA = new Set(['NENHUM', 'LIMITE_ZUNVIO', 'MISTO', 'PROJETO_OU_CLIENTE']);
// MASS-307: estados canônicos de decisão de publicação (inclui INCONCLUSIVO).
const ENUM_DECISAO = new Set(['PUBLICAR', 'NAO_PUBLICAR', 'INCONCLUSIVO']);
// B6: dimensões canônicas do contrato (enum interno) — nunca allowlist sintática.
const DIMENSOES_VALIDAS = new Set(Object.keys(ROTULOS_DIMENSOES_CONTRATO));
const PADRAO_HEX64 = /^[a-f0-9]{64}$/;
// B6: fingerprint REAL de achado (ZVS-GIT-/ZVS-SEM- + 16 hex). Identificadores
// externos que não sejam esse fingerprint são substituídos por fingerprint.
const PADRAO_FINDING_ID = /^ZVS-(?:GIT|SEM)-[a-f0-9]{16}$/;

function fp(texto) {
  return createHash('sha256').update(String(texto ?? '')).digest('hex').slice(0, 12);
}
function numSeguro(v) {
  return typeof v === 'number' && Number.isFinite(v) ? String(v) : '-';
}
function hexSeguro(v) {
  return typeof v === 'string' && PADRAO_HEX64.test(v) ? v : `fp:${fp(v)}`;
}
// B6: um fingerprint real de achado (ZVS-...) pode ser impresso; qualquer outro
// identificador externo vira fingerprint (nunca é ecoado cru).
function achadoIdSeguro(v) {
  return typeof v === 'string' && PADRAO_FINDING_ID.test(v) ? v : `fp:${fp(v)}`;
}
function enumSeguro(v, conjunto) {
  return typeof v === 'string' && conjunto.has(v) ? v : '?';
}
function mensagemDerivada(decisaoPublicacao, natureza, total) {
  if (decisaoPublicacao === 'PUBLICAR') {
    return 'Todos os portões obrigatórios atendem aos critérios de publicação.';
  }
  if (decisaoPublicacao === 'INCONCLUSIVO') {
    if (natureza === 'LIMITE_ZUNVIO') {
      return 'AVALIAÇÃO INCONCLUSIVA POR LIMITE DO ZUNVIO (sensor/cobertura). NÃO AFIRMO QUE PODE PUBLICAR.';
    }
    return 'AVALIAÇÃO INCONCLUSIVA: faltam evidências obrigatórias ou cobertura mínima. NÃO AFIRMO QUE PODE PUBLICAR.';
  }
  if (decisaoPublicacao === 'NAO_PUBLICAR') {
    if (natureza === 'MISTO') return 'Há bloqueios materiais detectados que exigem revisão e limitações do ZUNVIO.';
    return `Existem ${total} bloqueador(es) preventivo(s) que exigem revisão antes da publicação.`;
  }
  // INVÁLIDO: decisão desconhecida/incompatível — nunca uma decisão de publicação.
  return 'DECISÃO DESCONHECIDA OU INVÁLIDA — FALHA FECHADA.';
}

// Formatos que o motor atual produz; relatório com outro valor mostra o formato vigente.
const FORMATOS_EVIDENCE_PACK = new Set(['0.7.0', '0.8.0']);

export function formatarRelatorioHumano(relatorio, opcoes = {}) {
  // Primeira linha vazia: o banner nunca cola na última linha do
  // provisionamento (e a folha de marca pede respiro).
  const linhas = [''];
  const lim = (s) => String(s).slice(0, 400);
  const contextoAcoes = { lidosEmParte: Array.isArray(relatorio.scanners?.semgrep?.leituraParcial) ? relatorio.scanners.semgrep.leituraParcial.length : 0 };
  const arteBanner = selecionarBanner({ noBanner: opcoes.noBanner === true });
  if (arteBanner) linhas.push(...arteBanner);
  linhas.push('');
  linhas.push(`ZUNVIO CLI v${VERSAO}`);
  // A versão é a do pack produzido (0.8.0 quando há revisão humana registrada), não a constante do formato padrão.
  linhas.push(`Evidence Pack v${FORMATOS_EVIDENCE_PACK.has(relatorio.versao) ? relatorio.versao : VERSAO_EVIDENCE_PACK}`);
  linhas.push('================================================================');
  linhas.push('  Relatório de Avaliação de Prontidão');
  linhas.push('================================================================');
  // O relatório humano é do DONO do projeto: caminho e regra aparecem de
  // verdade, com controles/escapes neutralizados (B6: injeção de terminal).
  // O fingerprint continua sendo a regra na projeção --json (Evidence Pack).
  linhas.push(lim(`Alvo Analisado:      ${textoLegivelSeguro(relatorio.target, 200)}`));
  const sha = extrairShaRelease(relatorio);
  linhas.push(lim(`Release/HEAD:        ${typeof sha === 'string' && /^[0-9a-f]{40}$/i.test(sha) ? sha : '(não auditável via Git)'}`));
  linhas.push(lim(`Duração:             ${numSeguro(relatorio.duracaoTotalMs)}ms`));
  // PL-01: acima do limite operacional, dizer que parte do projeto ficou fora da análise.
  const limiteInventario = (relatorio.canonicalContent?.limitations || []).some((l) => l?.code === 'LIMIT_EXCEEDED' && l?.source === 'inventory');
  linhas.push(lim(`Arquivos Varredura:  ${numSeguro(relatorio.arquivosAnalisados)}${limiteInventario ? ' (limite operacional atingido: parte do projeto ficou fora da análise)' : ''}`));

  if (relatorio.avaliacao) {
    const score = relatorio.avaliacao.score;
    const decisao = relatorio.avaliacao.decisao;
    // MASS-307 revisão: decisão em TRÊS estados. A fonte de verdade é
    // `decisaoPublicacao`. Valor desconhecido/incompatível NÃO vira decisão de
    // publicação (nem PUBLICAR nem NÃO PUBLICAR): vira INVÁLIDO (falha fechada).
    const decisaoPublicacao = ENUM_DECISAO.has(decisao.decisaoPublicacao)
      ? decisao.decisaoPublicacao
      : 'INVALIDO';
    const publicar = decisaoPublicacao === 'PUBLICAR';
    const inconclusivo = decisaoPublicacao === 'INCONCLUSIVO';
    const invalido = decisaoPublicacao === 'INVALIDO';
    const natureza = enumSeguro(decisao.naturezaImpedimento, ENUM_NATUREZA);
    const totalBloqueadores = Array.isArray(decisao.bloqueadores) ? decisao.bloqueadores.length : 0;
    // Hoisted para reuso na camada "Resumo para decisão" (abaixo) e na lista
    // completa de "Próximas ações" (mais adiante) — mesma seleção, uma só vez.
    const portoesBloqueantes = (relatorio.avaliacao.portoes || []).filter(
      (p) => p && p.obrigatorio === true && (p.estado === 'NAO_ATENDE' || p.estado === 'NAO_COMPROVADO')
    );

    // MASS-103 comentário 9: camada de linguagem comum ANTES do detalhe
    // técnico ("divulgação progressiva em duas camadas"). Responde, nesta
    // ordem, às 6 perguntas aprovadas pelo dono: podemos avançar? qual o
    // nível de confiança? o que impede avançar? qual o impacto de negócio?
    // o que fazer agora? onde consultar o técnico? Todo o texto vem de
    // campos estruturados/enums já validados ou de templates fixos — nunca
    // de conteúdo bruto de scanner/achado (mesma disciplina B6 do resto
    // deste relatório).
    linhas.push('================================================================');
    linhas.push('  Resumo para decisão');
    linhas.push('================================================================');
    const rotuloResumo = publicar ? 'PUBLICAR' : (inconclusivo ? 'INCONCLUSIVO' : (invalido ? 'INVÁLIDO' : 'NÃO PUBLICAR'));
    linhas.push(`DECISÃO · ${rotuloResumo}`);
    linhas.push(lim(mensagemDerivada(decisaoPublicacao, natureza, totalBloqueadores)));
    const coberturaPrincipal = Number.isInteger(score.coberturaMotores) ? score.coberturaMotores : score.cobertura;
    if (Number.isInteger(coberturaPrincipal)) {
      linhas.push(`Os portões têm conclusão para ${coberturaPrincipal}% do peso avaliado; o contexto do contrato é medido separadamente.`);
    }
    if (totalBloqueadores > 0) {
      linhas.push(`Foram encontrados ${totalBloqueadores} bloqueio(s) obrigatório(s).`);
    }
    // E2E mínimo: baseline recusado não some em silêncio — nenhuma revisão nem aceite dele foi aplicado.
    const erroBaseline = relatorio.scanners?.semgrep?.erroBaseline || relatorio.scanners?.['zunvio-segredos']?.erroBaseline;
    if (erroBaseline) {
      linhas.push('');
      linhas.push(lim(`Atenção: ${textoLegivelSeguro(erroBaseline, 240)}`));
      linhas.push('  Nenhuma revisão nem aceite desse arquivo foi aplicado nesta análise. Corrija o arquivo (ou registre de novo com "npx zunvio-score revisar") e repita a análise.');
    }
    // E2E mínimo: o que é declaração do responsável ou revisão humana aparece AO LADO da decisão, não só no detalhe.
    const apoios = descreverApoios(apoiosDaDecisao(relatorio), (t) => textoLegivelSeguro(t, 120));
    if (apoios.length > 0) {
      linhas.push('');
      linhas.push(TITULO_APOIOS);
      for (const a of apoios) linhas.push(lim(`  - ${a}`));
    }
    // Portão de maior prioridade para a manchete: um bloqueio material
    // (NAO_ATENDE) fala mais alto que uma evidência ainda faltando.
    const portaoPrincipal = portoesBloqueantes.find((p) => p.estado === 'NAO_ATENDE') || portoesBloqueantes[0] || null;
    if (portaoPrincipal) {
      const { impacto, acao } = descreverAcao(portaoPrincipal, contextoAcoes);
      linhas.push('');
      linhas.push(`Principal motivo: ${lim(NOMES_PORTAO[portaoPrincipal.id] || 'Portão não identificado')}`);
      linhas.push(lim(`  ${impacto}`));
      linhas.push('O que fazer agora:');
      linhas.push(lim(`  ${acao}`));
    } else if (publicar) {
      linhas.push('');
      linhas.push('O que fazer agora:');
      linhas.push('  Revise as limitações e o contexto da release antes da decisão final.');
    }
    linhas.push('');
    linhas.push('Entenda os termos: rode "npx zunvio-score glossario" ou veja os detalhes técnicos abaixo.');

    linhas.push('----------------------------------------------------------------');
    // PL-04: terminar a execução não é completar a análise.
    linhas.push('EXECUÇÃO CONCLUÍDA.');
    if (relatorio.canonicalContent?.completeness?.status && relatorio.canonicalContent.completeness.status !== 'COMPLETE') {
      linhas.push('A completude da análise não foi comprovada (veja "Status dos Motores" e as limitações).');
    }
    // A escala do score é SEMPRE 0 a 100 (soma dos pesos dos portões).
    // maximoPossivel é outra informação: o teto que ESTE projeto ainda
    // alcança depois de descontar bloqueios materiais. O rótulo antigo
    // (SCORE MÁXIMO) fazia parecer que a escala encolhia (Marlon, 2026-09-02).
    linhas.push('');
    linhas.push('SCORE');
    linhas.push(lim(`  ZUNVIO SCORE · ${numSeguro(score.observado)} de 100`));
    if (Number.isInteger(score.maximoPossivel) && score.maximoPossivel < 100) {
      linhas.push(lim(`  AINDA ALCANÇÁVEL · ${numSeguro(score.maximoPossivel)} (bloqueios preventivos descontam o teto)`));
    }
    // Cobertura por responsabilidade, cada conta na sua linha. O total
    // min(motores, contrato) existe só para o portão de PUBLICAR (interno,
    // regra inalterada): como manchete ele era um 0% perpétuo sem informação
    // em todo scan sem contrato, então saiu da vitrine (decisão de Marlon,
    // 2026-09-02).
    linhas.push('');
    linhas.push('COBERTURA');
    if (Number.isInteger(score.cobertura)) {
      linhas.push(lim(`  COBERTURA DA AVALIAÇÃO · ${numSeguro(score.cobertura)}%`));
      linhas.push('  Valor usado pela decisão: o menor percentual entre os portões concluídos e o contexto comprovado do contrato.');
    }
    if (Number.isInteger(score.coberturaMotores)) {
      linhas.push(lim(`  COBERTURA DOS MOTORES · ${numSeguro(score.coberturaMotores)}%`));
      linhas.push('  Como é calculada: soma dos pesos dos portões com conclusão; motores executados podem coexistir com outros portões sem evidência.');
      const semContrato = !Number.isInteger(score.coberturaContrato) || score.coberturaContrato === 0;
      linhas.push(lim(semContrato
        ? '  CONTEXTO DO CONTRATO  · 0% (sem contrato de publicação; forneça com --contract)'
        : `  CONTEXTO DO CONTRATO  · ${numSeguro(score.coberturaContrato)}%`));
      linhas.push('  Como é calculado: percentual das 12 dimensões declaradas no contrato; a evidência externa é detalhada no mapa abaixo.');
    } else {
      linhas.push('  Como é calculada: percentual ponderado dos portões com conclusão; execução sem conclusão não conta como cobertura.');
    }
    const portoesSemConclusao = (relatorio.avaliacao.portoes || [])
      .filter((portao) => portao?.estado === 'NAO_COMPROVADO')
      .map((portao) => {
        const nome = NOMES_PORTAO[portao.id] || 'Portão não identificado';
        return Number.isInteger(portao.peso) ? `${nome} (${portao.peso}%)` : nome;
      });
    linhas.push(lim(portoesSemConclusao.length > 0
      ? `  Falta nos portões: ${portoesSemConclusao.join(', ')}`
      : '  Falta nos portões: nenhuma; consulte abaixo o contexto do contrato e o risco residual.'));
    const rotulo = publicar ? 'PUBLICAR' : (inconclusivo ? 'INCONCLUSIVO' : (invalido ? 'INVÁLIDO' : 'NÃO PUBLICAR'));
    const sufixo = inconclusivo
      ? ' (avaliação incompleta; não é reprovação do projeto)'
      : invalido
        ? ' (decisão desconhecida/incompatível — falha fechada)'
        : '';
    linhas.push('');
    linhas.push('DECISÃO');
    linhas.push(`  DECISÃO · ${rotulo}${sufixo}`);
    linhas.push(lim(`  RESUMO · ${mensagemDerivada(decisaoPublicacao, natureza, totalBloqueadores)}`));

    const temPortaoNaoComprovado = (relatorio.avaliacao.portoes || [])
      .some((portao) => portao?.estado === 'NAO_COMPROVADO');
    const temDimensaoNaoComprovada = relatorio.claimEvidenceMap?.claims
      ?.some((claim) => claim?.status === 'NAO_COMPROVADO') === true;
    const coberturaLegadaParcial = !Number.isInteger(score.coberturaMotores)
      && Number.isInteger(score.cobertura)
      && score.cobertura < 100;
    const saudeAvaliacao = invalido
      ? 'INVÁLIDA'
      : inconclusivo
        ? 'INCOMPLETA'
        : (temPortaoNaoComprovado || temDimensaoNaoComprovada || coberturaLegadaParcial ? 'PARCIAL' : 'CONCLUSIVA');
    linhas.push('');
    linhas.push('SAÚDE DA AVALIAÇÃO');
    linhas.push(`  SAÚDE DA AVALIAÇÃO · ${saudeAvaliacao}`);
    linhas.push('  Indica se os portões produziram conclusões suficientes; não substitui a decisão de publicação.');

    const coberturaRisco = relatorio.coverageAndResidualRisk || {};
    const caminhosExcluidos = Array.isArray(coberturaRisco.excludedPaths)
      ? coberturaRisco.excludedPaths.length
      : 0;
    const verificacoesNaoExecutadas = Array.isArray(coberturaRisco.unexecutedChecks)
      ? coberturaRisco.unexecutedChecks.length
      : 0;
    linhas.push('');
    linhas.push('RISCO RESIDUAL');
    linhas.push('  RISCO RESIDUAL · PRESENTE');
    linhas.push(`  Verificações não executadas: ${verificacoesNaoExecutadas} | caminhos excluídos: ${caminhosExcluidos}`);
    linhas.push('  Análise estática não elimina riscos de runtime, de operação ou de dependências fora do escopo analisado.');

    // Impedimentos/Bloqueadores: apenas contagens (números) + títulos fixos.
    const grupos = decisao.impedimentos;
    const gruposRelatorio = grupos && typeof grupos === 'object' ? [
      ['Bloqueios materiais detectados', grupos.reprovacoesProjeto],
      ['Evidências sob responsabilidade do cliente', grupos.semEvidenciaCliente],
      ['Fora da cobertura atual do ZUNVIO', grupos.foraCoberturaMotor],
      ['Falhas operacionais dos motores ZUNVIO', grupos.falhasMotor]
    ] : [];
    const temGrupos = gruposRelatorio.some(([, itens]) => Array.isArray(itens) && itens.length > 0);
    if (temGrupos) {
      linhas.push('  Impedimentos e limites por responsabilidade:');
      // Nomes por grupo: só o nome canônico do portão (enum NOMES_PORTAO) e o
      // peso estruturado; nunca texto bruto de scanner/evidência (B6). O peso
      // responde na prática "o que compõe a cobertura que falta" (Marlon).
      const portoesDoRelatorio = relatorio.avaliacao.portoes || [];
      const nomesDoGrupo = (filtro) => portoesDoRelatorio
        .filter((p) => p && filtro(p))
        .map((p) => {
          const nome = NOMES_PORTAO[p.id] || 'Portão não identificado';
          return p.estado === 'NAO_COMPROVADO' && Number.isInteger(p.peso) ? `${nome} (${p.peso}%)` : nome;
        });
      const nomesPorTitulo = {
        'Bloqueios materiais detectados': nomesDoGrupo((p) => p.estado === 'NAO_ATENDE'),
        'Evidências sob responsabilidade do cliente': nomesDoGrupo((p) => p.estado === 'NAO_COMPROVADO' && p.subcausa === 'SEM_EVIDENCIA_DO_CLIENTE'),
        'Fora da cobertura atual do ZUNVIO': nomesDoGrupo((p) => p.estado === 'NAO_COMPROVADO' && p.subcausa === 'FORA_DE_COBERTURA_DO_MOTOR'),
        'Falhas operacionais dos motores ZUNVIO': nomesDoGrupo((p) => p.estado === 'NAO_COMPROVADO' && p.subcausa === 'MOTOR_FALHOU')
      };
      for (const [titulo, itens] of gruposRelatorio) {
        const n = Array.isArray(itens) ? itens.length : 0;
        if (n > 0) {
          const nomes = [...(nomesPorTitulo[titulo] || [])];
          // Entradas de contrato no grupo do cliente não são portões; o título fixo cobre.
          if (n > nomes.length) nomes.push('Contrato de publicação');
          const sufixo = nomes.length > 0 ? ` · ${nomes.join(', ')}` : '';
          linhas.push(lim(`  ${titulo}: ${n}${sufixo}`));
        }
      }
    } else if (totalBloqueadores > 0) {
      linhas.push(lim(`  Bloqueadores: ${totalBloqueadores}`));
    }

    // Próximas ações: derivadas de campos estruturados dos gates.
    linhas.push('  Próximas ações:');
    if (publicar) {
      linhas.push('    Nenhum bloqueador. Estado limpo: pronto para publicar conforme contrato e evidências.');
    } else {
      let temAcao = false;
      for (const portao of portoesBloqueantes) {
        const { causa, impacto, acao } = descreverAcao(portao, contextoAcoes);
        // Linha em branco antes de cada item: legibilidade pedida por Marlon.
        linhas.push('');
        linhas.push(lim(`    - ${NOMES_PORTAO[portao.id] || 'Portão não identificado'}`));
        linhas.push(lim(`      Causa:   ${causa}`));
        linhas.push(lim(`      Impacto: ${impacto}`));
        linhas.push(lim(`      Ação:    ${acao}`));
        temAcao = true;
      }
      // Contrato: sinal detectado por prefixo estruturado nos impedimentos, mas a
      // causa é TEMPLATE fixo (o texto do bloqueador nunca é impresso).
      const temContratoInconclusivo = Array.isArray(grupos?.semEvidenciaCliente)
        && grupos.semEvidenciaCliente.some((b) => typeof b === 'string' && b.startsWith('Contrato de publicação'));
      if (temContratoInconclusivo) {
        linhas.push('');
        linhas.push('    - Contrato de publicação');
        linhas.push('      Causa:   Contrato de publicação insuficiente ou ausente.');
        linhas.push('      Impacto: Sem contrato suficiente, não é possível aprovar a publicação.');
        linhas.push('      Ação:    Descreva o projeto respondendo a "npx zunvio-score init" e repita a análise.');
        temAcao = true;
      }
      if (!temAcao) {
        linhas.push('    Bloqueio sem causa estruturada; consulte o Evidence Pack para detalhes.');
      }
    }
  }

  if (relatorio.claimEvidenceMap) {
    const mapa = relatorio.claimEvidenceMap;
    linhas.push('----------------------------------------------------------------');
    linhas.push(lim(`CLAIMS · ATENDE ${numSeguro(mapa.summary.atende)} | NÃO ATENDE ${numSeguro(mapa.summary.naoAtende)} | NÃO COMPROVADO ${numSeguro(mapa.summary.naoComprovado)} | COBERTURA ${numSeguro(mapa.coverage)}%`));
    linhas.push('Cobertura das evidências: percentual das 12 dimensões com evidência conclusiva; uma divergência é coberta, mas não atendida.');
    // B6: dimensões de claim são enums internos (12 canônicas) — qualquer outra é
    // omitida (não ecoada como texto externo).
    const claimsSeguras = (Array.isArray(mapa.claims) ? mapa.claims : [])
      .filter((claim) => claim && typeof claim.dimension === 'string' && DIMENSOES_VALIDAS.has(claim.dimension));
    const claimsPorDimensao = new Map(claimsSeguras.map((claim) => [claim.dimension, claim]));
    const claimsUnicas = [...claimsPorDimensao.values()];
    const totalCobertas = claimsUnicas.filter((claim) => claim.status === 'ATENDE' || claim.status === 'NAO_ATENDE').length;
    const totalNaoAplicaveis = claimsUnicas.filter((claim) => claim.status === 'NAO_APLICAVEL').length;
    const totalAusentes = Object.keys(ROTULOS_DIMENSOES_CONTRATO).length - totalCobertas - totalNaoAplicaveis;
    linhas.push(`SITUAÇÃO · COBERTAS ${totalCobertas} | AUSENTES ${totalAusentes} | NÃO APLICÁVEIS ${totalNaoAplicaveis}`);
    linhas.push('DIMENSÕES DO CONTRATO (evidência externa; o que foi respondido no init é contexto declarado, não evidência — AUSENTE = sem evidência externa)');
    for (const [dimensao, rotuloDimensao] of Object.entries(ROTULOS_DIMENSOES_CONTRATO)) {
      const claim = claimsPorDimensao.get(dimensao);
      const estadoHumano = claim?.status === 'NAO_APLICAVEL'
        ? 'NÃO APLICÁVEL'
        : claim?.status === 'ATENDE'
          ? 'COBERTA'
          : claim?.status === 'NAO_ATENDE'
            ? 'COBERTA · NÃO ATENDE'
            : 'AUSENTE';
      linhas.push(`  - ${rotuloDimensao}: ${estadoHumano}`);
    }
    const rotulosDimensoes = (claims) => (Array.isArray(claims) ? claims : [])
      .filter((claim) => claim && typeof claim.dimension === 'string' && DIMENSOES_VALIDAS.has(claim.dimension))
      .map((claim) => ROTULOS_DIMENSOES_CONTRATO[claim.dimension]);
    const divergencias = rotulosDimensoes(claimsSeguras.filter((claim) => claim.divergence === true));
    if (divergencias.length > 0) linhas.push(lim(`DIVERGÊNCIAS · ${divergencias.join(', ')}`));
    const faltantes = rotulosDimensoes(claimsSeguras.filter((claim) => claim.status === 'NAO_COMPROVADO')).slice(0, 3);
    if (faltantes.length > 0) linhas.push(lim(`MÍNIMO FALTANTE · evidência externa para ${faltantes.join(', ')}`));
  }

  // Seção Delta e Blast Radius (quando ativo)
  if (relatorio.delta && relatorio.delta.ativo) {
    const d = relatorio.delta;
    const b = d.blastRadius || {};
    linhas.push('----------------------------------------------------------------');
    linhas.push('Análise de Delta Git & Raio de Impacto (Blast Radius):');
    linhas.push(lim(`  Arquivos no Delta: ${numSeguro(d.arquivosAlterados)} alterados | +${numSeguro(b.linhasAdicionadas)} -${numSeguro(b.linhasRemovidas)} (Churn: ${numSeguro(b.totalChurn)} linhas)`));
    linhas.push(lim(`  Raio de Impacto:   [${enumSeguro(b.pegadaMudanca, ENUM_PEGADA)}] — Nível de Risco: ${enumSeguro(b.rotuloRisco, ENUM_RISCO)}`));
    linhas.push(lim(`  Módulos Tocados:   ${numSeguro(Array.isArray(b.modulosAfetados) ? b.modulosAfetados.length : 0)}`));
    if (d.resumoAchadosDelta) {
      linhas.push(lim(`  Foco de Riscos:    ${numSeguro(d.resumoAchadosDelta.totalAchadosNoDelta)} achados no delta atual | ${numSeguro(d.resumoAchadosDelta.totalAchadosHistoricos)} no histórico`));
    }
  }

  linhas.push('----------------------------------------------------------------');
  linhas.push('Status dos Motores:');
  const imprimirMotor = (nome, motor = {}, rotulosMotivoProprios = {}) => {
    const estadoDerivado = motor.status === 'SUCCESS'
      ? 'EXECUTADO'
      : motor.status === 'UNAVAILABLE' || !motor.disponivel
        ? 'INDISPONIVEL'
        : 'FALHA_DE_EXECUCAO';
    const estado = enumSeguro(motor.estadoOperacional || estadoDerivado, ENUM_ESTADO_OPERACIONAL);
    const rotulosEstado = {
      EXECUTADO: 'EXECUTADO',
      INDISPONIVEL: 'INDISPONÍVEL',
      RECUSADO_PELO_USUARIO: 'RECUSADO PELO USUÁRIO',
      FALHA_DE_EXECUCAO: 'FALHA DE EXECUÇÃO',
      NAO_EXECUTADO: 'NÃO EXECUTADO (sem histórico Git no alvo)'
    };
    linhas.push(`  - ${nome}:`);
    linhas.push(`      Operação: ${rotulosEstado[estado] || '?'}`);
    // LC-06: cobertura do histórico Git (commits esperados pelo Git × varridos pelo Gitleaks), também quando não executou.
    const h = motor.completude?.history;
    if (h && typeof h === 'object') {
      const ROTULOS_HISTORICO = { SHALLOW_HISTORY: 'clone raso (shallow): parte do histórico não está no alvo', HISTORY_NOT_DETERMINED: 'histórico esperado não determinado (ou alvo é subdiretório de um repositório)', HISTORY_COVERAGE_MISMATCH: 'commits varridos não batem com os esperados' };
      const motivoH = (motor.completude.reasons || []).map((m) => ROTULOS_HISTORICO[m]).filter(Boolean).join('; ');
      linhas.push(lim(h.applicable === false
        ? '      Histórico Git: cobertura NÃO COMPROVADA — o alvo não é um repositório Git; o histórico do release não pôde ser varrido.'
        : motor.completude.status === 'COMPLETE'
          ? `      Histórico Git: ${numSeguro(h.commitsScanned)} de ${numSeguro(h.commitsExpected)} commit(s) esperados varridos — cobertura COMPROVADA.`
          : `      Histórico Git: cobertura NÃO COMPROVADA${motivoH ? ` (${motivoH})` : ''}${Number.isInteger(h.commitsExpected) && Number.isInteger(h.commitsScanned) ? ` — ${numSeguro(h.commitsScanned)} de ${numSeguro(h.commitsExpected)} commit(s) esperados` : ''}.`));
    }
    if (estado !== 'EXECUTADO') {
      linhas.push('      Resultado de segurança: NÃO AVALIADO');
      return;
    }
    const severidades = motor.resumoSeveridade || {};
    linhas.push(lim(`      Resultado de segurança: ${numSeguro(motor.totalAchados)} achado(s) detectado(s)`));
    linhas.push(lim(`      Severidades: CRITICAL ${numSeguro(severidades.CRITICAL)} | HIGH ${numSeguro(severidades.HIGH)} | MEDIUM ${numSeguro(severidades.MEDIUM)} | LOW ${numSeguro(severidades.LOW)} | INFO ${numSeguro(severidades.INFO)}`));
    // PL-02: o que esperávamos analisar × o que foi analisado (contagens e motivos; nenhum caminho).
    const u = motor.completude?.universe;
    if (u && Number.isInteger(u.expected)) {
      if (u.evidence === 'SCANNER_REPORTS_NO_COVERAGE_SIGNAL') {
        linhas.push(lim(`      Universo esperado: ${numSeguro(u.expected)} arquivo(s). O sensor não informa quais analisou: cobertura NÃO COMPROVÁVEL.`));
      } else if (Number.isInteger(u.notAnalyzed) && Number.isInteger(u.partiallyAnalyzed)) {
        const ROTULOS_MOTIVO = {
          UNSUPPORTED_EXTENSION: 'extensão não reconhecida pelo scanner', SIZE_LIMIT_EXCEEDED: 'acima do limite de tamanho do scanner',
          OPERATIONAL_LIMIT: 'fora dos limites operacionais do ZUNVIO', READ_ERROR: 'ilegível para o ZUNVIO', UNKNOWN_CAUSE: 'motivo não demonstrado', TIMEOUT: 'tempo esgotado',
          FILE_SKIPPED: 'pulado pelo scanner', PARTIAL_PARSING: 'lido em parte', PARSE_ERROR: 'código ilegível', FILE_ERROR: 'erro no arquivo'
        };
        const motivos = Object.entries(u.byReason || {}).map(([m, n]) => `${numSeguro(n)} ${rotulosMotivoProprios[m] || ROTULOS_MOTIVO[m] || '?'}`).join(', ');
        linhas.push(lim(u.notAnalyzed + u.partiallyAnalyzed === 0
          ? `      Universo esperado: ${numSeguro(u.expected)} arquivo(s) — todos analisados.`
          : `      Universo esperado: ${numSeguro(u.expected)} arquivo(s) — ${numSeguro(u.analyzed)} analisados, ${numSeguro(u.partiallyAnalyzed)} em parte, ${numSeguro(u.notAnalyzed)} NÃO analisados (${motivos}).`));
      }
    } else if (Array.isArray(motor.completude?.reasons) && motor.completude.reasons.includes('LIMIT_EXCEEDED')) {
      // PL-01: nem a contagem do universo coube no limite — não se afirma quanto ficou de fora.
      linhas.push('      Universo esperado: NÃO DETERMINÁVEL — o projeto passa dos limites operacionais do ZUNVIO; não sabemos quanto ficou fora da análise.');
    }
    // E2E mínimo: onde a leitura foi parcial — o arquivo, a linha e o trecho que o analisador não leu. A decisão
    // continua vindo da completude selada; isto só explica o que fazer.
    const parciais = Array.isArray(motor.leituraParcial) ? motor.leituraParcial : [];
    if (parciais.length > 0) {
      linhas.push('      Lido em parte (a análise deste código não pode ser dada como completa):');
      for (const p of parciais.slice(0, 10)) {
        const onde = `${textoLegivelSeguro(p.arquivo, 160)}${Number.isInteger(p.linha) ? `:${numSeguro(p.linha)}` : ''}`;
        linhas.push(lim(`        - ${onde}${p.trecho ? ` — o analisador não reconheceu "${textoLegivelSeguro(p.trecho, 60)}"` : ''}`));
        if (p.dica) linhas.push(lim(`          ${textoLegivelSeguro(p.dica, 240)}`));
      }
      if (parciais.length > 10) linhas.push(lim(`        … e mais ${numSeguro(parciais.length - 10)} arquivo(s) (lista completa no relatório HTML).`));
    }
    // LC-06: o que ficou fora do universo por política e o que não pôde ser inspecionado (contagens; nenhum caminho).
    const d = motor.detalheCobertura;
    if (d && typeof d === 'object') {
      if (Number.isInteger(d.policyExclusions?.count) && d.policyExclusions.count > 0) {
        linhas.push(lim(`      Fora do universo por política: ${numSeguro(d.policyExclusions.count)} arquivo(s) de fonte (${(d.policyExclusions.extensions || []).map((e) => textoLegivelSeguro(e, 12)).join(', ')}) — não contam como analisados.`));
      }
    }
  };
  if (relatorio.scanners['zunvio-segredos']) {
    // LC-06: segredos em duas partes, cada uma com a sua cobertura.
    imprimirMotor('Segredos — estado atual dos arquivos (ZUNVIO)', relatorio.scanners['zunvio-segredos'], {
      UNSUPPORTED_EXTENSION: 'conteúdo compactado não inspecionável (zip, docx, xlsx, gzip, pdf e equivalentes)'
    });
    imprimirMotor('Segredos — histórico Git (Gitleaks)', relatorio.scanners.gitleaks);
  } else {
    imprimirMotor('GitLeaks', relatorio.scanners.gitleaks);
  }
  imprimirMotor('Semgrep', relatorio.scanners.semgrep);

  linhas.push('----------------------------------------------------------------');
  linhas.push(lim(`Total de Achados: ${numSeguro(relatorio.totalAchados)}`));
  const rs = relatorio.resumoSeveridade || {};
  linhas.push(lim(`  CRITICAL: ${numSeguro(rs.CRITICAL)} | HIGH: ${numSeguro(rs.HIGH)} | MEDIUM: ${numSeguro(rs.MEDIUM)} | LOW: ${numSeguro(rs.LOW)} | INFO: ${numSeguro(rs.INFO)}`));
  const rc = relatorio.resumoCategorias || {};
  linhas.push('Categorias dos Achados:');
  linhas.push(lim(`  CÓDIGO PRÓPRIO: ${numSeguro(rc.CODIGO_PROPRIO)}`));
  linhas.push(lim(`  TERCEIROS/DEPENDÊNCIAS: ${numSeguro(rc.TERCEIROS_DEPENDENCIAS)} (informativo; não bloqueia o código próprio)`));
  linhas.push(lim(`  TESTES/FIXTURES: ${numSeguro(rc.TESTES_FIXTURES)}`));
  linhas.push(lim(`  ARTEFATOS GERADOS: ${numSeguro(rc.ARTEFATOS_GERADOS)} (informativo; não bloqueia o código próprio)`));

  if (Array.isArray(relatorio.achados) && relatorio.achados.length > 0) {
    linhas.push('----------------------------------------------------------------');
    linhas.push('Detalhamento dos Achados:');
    // O dono precisa AGIR sobre o achado: arquivo:linha e regra reais, com
    // controles/escapes neutralizados (B6). O valor do segredo em si nunca é
    // impresso em lugar nenhum. Na projeção --json tudo segue fingerprintado.
    for (const a of relatorio.achados) {
      const tagDelta = a.deltaInfo?.noDelta ? ' [NOVO NO DELTA]' : '';
      linhas.push(lim(`  [${enumSeguro(a.severity, ENUM_SEVERIDADE)}] ${textoLegivelSeguro(a.filePath, 160)}:${numSeguro(a.startLine)}${tagDelta}`));
      linhas.push(lim(`    Categoria: ${enumSeguro(a.categoria, ENUM_CATEGORIA_ACHADO)}`));
      linhas.push(`    Detecção:  ${enumSeguro(a.estadoDeteccao, ENUM_ESTADO_DETECCAO)}`);
      const statusValidacao = enumSeguro(a.statusValidacao, ENUM_STATUS_VALIDACAO_ACHADO);
      linhas.push(`    Validação: ${statusValidacao === 'NECESSITA_REVISAO' ? 'NECESSITA REVISÃO' : statusValidacao}`);
      linhas.push(lim(`    Regra:    ${textoLegivelSeguro(a.ruleId, 120)}`));
      // PL-03 (fechamento): o significado em linguagem humana — o que foi (e o que não foi) demonstrado.
      if (a.significado) {
        const rotulosSignificado = {
          RISCO_DEMONSTRADO: 'RISCO DEMONSTRADO (impede a publicação)',
          REVISAO_NECESSARIA: 'REVISÃO NECESSÁRIA (risco não demonstrado; impede a publicação até revisão)',
          INFORMATIVO: 'INFORMATIVO (não impede a publicação)'
        };
        linhas.push(lim(`    Significado: ${rotulosSignificado[enumSeguro(a.significado.classe, ENUM_CLASSE_SIGNIFICADO)] || '?'}`));
        linhas.push(lim(`    ${textoLegivelSeguro(a.significado.explicacao, 400)}`));
      }
      // E2E mínimo: revisão humana registrável (só para REVISÃO NECESSÁRIA; nunca para risco demonstrado).
      if (a.revisaoHumana?.estado === 'ACEITA') {
        linhas.push(lim(`    Revisão humana: aceita neste contexto por ${textoLegivelSeguro(a.revisaoHumana.autor, 80)} em ${textoLegivelSeguro(a.revisaoHumana.data, 20)} — "${textoLegivelSeguro(a.revisaoHumana.justificativa, 200)}"`));
        linhas.push('    (não impede a publicação; o achado continua registrado; revisão humana não é prova de ausência de risco)');
      } else if (a.significado?.classe === 'REVISAO_NECESSARIA' && /^[0-9a-f]{16}$/.test(a.chaveRevisao ?? '')) {
        linhas.push(lim(`    Revisou e não é risco neste contexto? Registre: npx zunvio-score revisar ${a.chaveRevisao}`));
      }
      linhas.push(lim(`    Id:       ${achadoIdSeguro(a.id)}`));
    }
  }

  // E2E mínimo: todas as revisões registradas e o que valeu nesta análise.
  const revisoes = Array.isArray(relatorio.canonicalContent?.humanReviews) ? relatorio.canonicalContent.humanReviews : [];
  if (revisoes.length > 0) {
    const conta = (e) => revisoes.filter((r) => r.estado === e).length;
    linhas.push('----------------------------------------------------------------');
    linhas.push(`Revisões humanas registradas: ${numSeguro(revisoes.length)} · aceitas ${numSeguro(conta('ACEITA'))} · obsoletas ${numSeguro(conta('OBSOLETA'))} · sem efeito ${numSeguro(conta('NAO_APLICAVEL') + conta('SEM_ACHADO'))}`);
    for (const r of revisoes.filter((x) => x.estado !== 'ACEITA')) {
      const onde = r.arquivo ? textoLegivelSeguro(r.arquivo, 160) : r.chaveRevisao;
      const motivo = {
        OBSOLETA: 'o código em volta mudou desde a revisão; revise de novo e registre outra vez',
        NAO_APLICAVEL: 'o item agora tem risco demonstrado; revisão humana não vale para risco demonstrado',
        SEM_ACHADO: 'o item não aparece mais nesta análise; a revisão pode ser removida do .zunvio-baseline.json'
      }[r.estado] || '?';
      linhas.push(lim(`  - ${onde} (${textoLegivelSeguro(r.regra || '', 60)}): ${motivo}.`));
    }
  }

  // RF-08 (MASS-399): achados informativos — nunca contam pro score, pros
  // portões nem pra decisão de publicação. Mesmo tratamento de texto real do
  // resto do relatório humano (textoLegivelSeguro, nunca fingerprint).
  const informativos = relatorio.informativeFindings;
  if (informativos) {
    const BLOCOS_INFORMATIVOS = [
      ['Comentário perigoso', informativos.comentariosPerigosos],
      ['CVE/dependência', informativos.dependenciasCve],
      ['Variável de ambiente no frontend', informativos.frontendEnvExposure]
    ];
    const totalAchadosInformativos = BLOCOS_INFORMATIVOS.reduce(
      (soma, [, bloco]) => soma + (Array.isArray(bloco?.achados) ? bloco.achados.length : 0),
      0
    );
    linhas.push('----------------------------------------------------------------');
    linhas.push('Achados Informativos (RF-08 — não afetam score/portões/decisão):');
    for (const [rotulo, bloco] of BLOCOS_INFORMATIVOS) {
      if (!bloco) continue;
      const status = enumSeguro(bloco.status, ENUM_STATUS_INFORMATIVO);
      const achados = Array.isArray(bloco.achados) ? bloco.achados : [];
      if (status !== 'SUCCESS') {
        linhas.push(`  - ${rotulo}: ${status === 'NAO_APLICAVEL' ? 'não aplicável' : status.toLowerCase()}`);
        continue;
      }
      linhas.push(`  - ${rotulo}: ${achados.length} achado(s)`);
      for (const a of achados) {
        linhas.push(lim(`      [${enumSeguro(a.severity, ENUM_SEVERIDADE)}] ${textoLegivelSeguro(a.filePath, 160)}${Number.isInteger(a.startLine) && a.startLine > 0 ? `:${a.startLine}` : ''}`));
        linhas.push(lim(`        ${textoLegivelSeguro(a.message, 200)}`));
      }
    }
    if (totalAchadosInformativos === 0) {
      linhas.push('  Nenhum achado informativo nesta análise.');
    }
  }

  linhas.push('----------------------------------------------------------------');
  linhas.push('Prova de integridade do repositório-alvo:');
  linhas.push(lim(`  Perímetro verificado: ${textoLegivelSeguro(relatorio.target, 200)}`));
  linhas.push('  Algoritmo:            SHA-256');
  linhas.push('  Medições:             início e fim da execução');
  linhas.push(lim(`  Digest final:          ${hexSeguro(relatorio.integridade.digestFinal)}`));
  linhas.push(`  Resultado:             ${relatorio.integridade.inalterado === true
    ? (limiteInventario
      ? 'Sem alteração na parte verificada; o projeto passa do limite operacional, então a integridade foi verificada só em parte'
      : 'Repositório-alvo permanece inalterado')
    : 'ALTERAÇÃO NO REPOSITÓRIO-ALVO DETECTADA'}`);
  linhas.push('  Alterações fora do alvo (como instalação de sensores) são permitidas e esperadas; não fazem parte desta medição.');
  if (relatorio.canonicalHash) {
    linhas.push(lim(`  Hash canônico do Evidence Pack: ${hexSeguro(relatorio.canonicalHash)}`));
  }
  linhas.push('================================================================');
  // E2E mínimo: o relatório HTML local (gerado fora do projeto) é o próximo passo concreto.
  if (opcoes.caminhoRelatorio) linhas.push(lim(`Relatório para compartilhar: ${textoLegivelSeguro(opcoes.caminhoRelatorio, 300)}`));
  linhas.push('');

  return linhas.join('\n');
}

const ENUM_GATE_ID = new Set(Object.keys(NOMES_PORTAO));
const ENUM_GATE_ESTADO = new Set(['ATENDE', 'NAO_ATENDE', 'NAO_COMPROVADO', 'NAO_APLICAVEL']);
const ENUM_OUTCOME = new Set(['ACCEPT', 'REJECT', 'UNPROVEN']);
const ENUM_COMPLETUDE = new Set(['CLEAN', 'WITH_FINDINGS', 'NOT_STARTED', 'FAILED']);
const ENUM_SENSOR = new Set(['gitleaks', 'zunvio-segredos', 'semgrep']);
const ENUM_CATEGORIA_ACHADO = new Set([
  'CODIGO_PROPRIO', 'TERCEIROS_DEPENDENCIAS', 'TESTES_FIXTURES', 'ARTEFATOS_GERADOS'
]);
const ENUM_ESTADO_DETECCAO = new Set(['DETECTADO']);
const ENUM_STATUS_VALIDACAO_ACHADO = new Set(['NECESSITA_REVISAO', 'CONFIRMADO']);
// PL-03 · Fatia 1: identidade de símbolo (hoje só zunvio.child-process-exec). Projetada só como enum.
const ENUM_STATUS_IDENTIDADE_SIMBOLO = new Set(['CONFIRMADA', 'RECUSADA', 'NAO_DETERMINADA']);
// PL-03 (fechamento): significado do achado. Projetado só como enums (classe e efeito na decisão), para que o
// verificador reconcilie o portão também sobre a projeção segura.
const ENUM_CLASSE_SIGNIFICADO = new Set(['RISCO_DEMONSTRADO', 'REVISAO_NECESSARIA', 'INFORMATIVO']);
const ENUM_EFEITO_NA_DECISAO = new Set(['BLOQUEIA', 'NAO_BLOQUEIA']);
const ENUM_ESTADO_OPERACIONAL = new Set([
  'EXECUTADO', 'INDISPONIVEL', 'RECUSADO_PELO_USUARIO', 'FALHA_DE_EXECUCAO', 'NAO_EXECUTADO'
]);
const ENUM_RESULTADO_SEGURANCA = new Set([
  'SEM_ACHADOS_DETECTADOS', 'ACHADOS_DETECTADOS', 'NAO_AVALIADO'
]);
const ENUM_CHECK = new Set(['gitleaks-secret-detection', 'zunvio-secret-detection', 'gitleaks-history-secret-detection', 'semgrep-sast-detection', 'git-delta-blast-radius']);
// RF-08 (MASS-399): sensores informativos — nunca entram em ENUM_SENSOR (esse
// continua exclusivo dos dois sensores canônicos/gateados).
const ENUM_SENSOR_INFORMATIVO = new Set([ID_SENSOR_COMENTARIOS, ID_SENSOR_DEPENDENCIAS, ID_SENSOR_FRONTEND_ENV]);
const ENUM_STATUS_INFORMATIVO = new Set([
  'SUCCESS', 'NAO_APLICAVEL', 'UNAVAILABLE', 'TIMEOUT', 'ERROR'
]);
const MAX_LINHA_JSON = 400;

/**
 * Texto real legível para o relatório humano local: mostra caminho/regra
 * reais (não fingerprint) para quem lê o próprio terminal, mas nunca deixa
 * segredo, controle de terminal, disfarce bidirecional (Trojan Source) ou
 * payload de injeção (HTML/prompt/shell) atravessar. Delega para a defesa
 * compartilhada em utils/redactor.mjs. NÃO substitui o fingerprint da
 * projeção --json.
 */
function textoLegivelSeguro(valor, max = 200) {
  return textoSeguroParaExibicao(valor, max);
}

function fpCompleto(valor) {
  return createHash('sha256').update(String(valor ?? '')).digest('hex');
}

export function fingerprintSeguro(valor) {
  return `fp:${fpCompleto(valor)}`;
}

function fingerprintOuNulo(valor) {
  return valor === null || valor === undefined ? null : fingerprintSeguro(valor);
}

/**
 * Timestamp volátil: o contrato Scanner→SaaS (MASS-299/MASS-301) exige uma
 * data válida em volatileMetadata.timestamp — fingerprintar sempre quebrava a
 * ingestão real (achado do primeiro E2E CLI→SaaS, MASS-318 item 6). Deixa
 * passar SOMENTE o que é data estrita (charset fechado, tamanho curto,
 * Date.parse válido): um receipt hostil com texto arbitrário nesse campo
 * continua sendo fingerprintado, exatamente como o teste adversarial B6 exige.
 */
function timestampVolatilSeguro(valor) {
  if (
    typeof valor === 'string' &&
    valor.length >= 10 &&
    valor.length <= 40 &&
    /^[0-9TZ:.+\-]+$/.test(valor) &&
    !Number.isNaN(Date.parse(valor))
  ) {
    return valor;
  }
  return fingerprintSeguro(valor);
}

/** Fingerprint interno do achado (hash hex curto) — já é seguro por natureza. */
function achadoFingerprintSeguro(valor) {
  return typeof valor === 'string' && /^[0-9a-f]{8,64}$/.test(valor) ? valor : null;
}

function digestSeguro(valor, tamanho = 64) {
  const re = tamanho === 40 ? /^[a-f0-9]{40}$/i : /^[a-f0-9]{64}$/;
  return typeof valor === 'string' && re.test(valor) ? valor.toLowerCase() : fpCompleto(valor);
}

function numeroFinito(valor, fallback = 0) {
  return typeof valor === 'number' && Number.isFinite(valor) ? valor : fallback;
}

function inteiroNaoNegativo(valor) {
  return Number.isInteger(valor) && valor >= 0 ? valor : 0;
}

function enumInterno(valor, conjunto, fallback = 'DESCONHECIDO') {
  return typeof valor === 'string' && conjunto.has(valor) ? valor : fallback;
}

function evidenciaSegura(valor) {
  const sha = /[0-9a-f]{40}/i.exec(String(valor ?? ''));
  return sha ? `sha:${sha[0].toLowerCase()}` : fingerprintSeguro(valor);
}

function projetarGateSeguro(gate = {}) {
  const id = enumInterno(gate.id, ENUM_GATE_ID, 'GATE_DESCONHECIDO');
  const projetado = {
    id,
    nome: id === 'GATE_DESCONHECIDO' ? id : NOMES_PORTAO[id],
    peso: numeroFinito(gate.peso),
    obrigatorio: gate.obrigatorio === true,
    estado: enumInterno(gate.estado, ENUM_GATE_ESTADO, 'NAO_COMPROVADO'),
    evidencias: Array.isArray(gate.evidencias) ? gate.evidencias.map(evidenciaSegura) : [],
    bloqueadores: Array.isArray(gate.bloqueadores) ? gate.bloqueadores.map(fingerprintSeguro) : [],
    motivo: fingerprintSeguro(gate.motivo)
  };
  if (projetado.estado === 'NAO_COMPROVADO') {
    projetado.subcausa = enumInterno(gate.subcausa, SUBCAUSAS_VALIDAS, 'MOTOR_FALHOU');
  }
  return projetado;
}

function projetarDecisaoSegura(decisao = {}) {
  return {
    score: inteiroNaoNegativo(decisao.score),
    coverage: inteiroNaoNegativo(decisao.coverage),
    outcome: enumInterno(decisao.outcome, ENUM_OUTCOME, 'UNPROVEN'),
    maxPossibleScore: inteiroNaoNegativo(decisao.maxPossibleScore),
    gates: Array.isArray(decisao.gates) ? decisao.gates.map(projetarGateSeguro) : []
  };
}

const ENUM_ESTADO_REVISAO = new Set(['ACEITA', 'OBSOLETA', 'NAO_APLICAVEL', 'SEM_ACHADO']);
const hex16Seguro = (v) => (/^[0-9a-f]{16}$/.test(v ?? '') ? v : null);
function projetarRevisaoHumanaSegura(r = {}) {
  if (!r || typeof r !== 'object') return null;
  return {
    ...(r.modelo === 'revisao-humana-1.0' ? { modelo: r.modelo } : {}),
    chaveRevisao: hex16Seguro(r.chaveRevisao),
    contextoRevisao: hex16Seguro(r.contextoRevisao),
    classificacaoOriginal: enumInterno(r.classificacaoOriginal, ENUM_CLASSE_SIGNIFICADO, 'RISCO_DEMONSTRADO'),
    ...(r.regra !== undefined ? { regra: fingerprintSeguro(r.regra) } : {}),
    ...(r.arquivo !== undefined ? { arquivo: fingerprintSeguro(r.arquivo) } : {}),
    autor: fingerprintSeguro(r.autor),
    data: /^\d{4}-\d{2}-\d{2}(?:T[\d:.]+Z)?$/.test(r.data ?? '') ? r.data : fingerprintSeguro(r.data),
    justificativa: fingerprintSeguro(r.justificativa),
    estado: enumInterno(r.estado, ENUM_ESTADO_REVISAO, 'SEM_ACHADO'),
    ...(r.findingId !== undefined ? { findingId: fingerprintSeguro(r.findingId) } : {}),
    ...(r.classificacaoAtual !== undefined ? { classificacaoAtual: r.classificacaoAtual === null ? null : enumInterno(r.classificacaoAtual, ENUM_CLASSE_SIGNIFICADO, 'RISCO_DEMONSTRADO') } : {}),
    ...(r.contextoAtual !== undefined ? { contextoAtual: r.contextoAtual === null ? null : hex16Seguro(r.contextoAtual) } : {})
  };
}

function projetarAchadoSeguro(achado = {}) {
  return {
    scanner: enumInterno(achado.scanner, ENUM_SENSOR, 'gitleaks'),
    ruleId: fingerprintSeguro(achado.ruleId),
    severity: enumInterno(achado.severity, ENUM_SEVERIDADE, 'INFO'),
    filePath: fingerprintSeguro(achado.filePath),
    categoria: enumInterno(achado.categoria, ENUM_CATEGORIA_ACHADO, 'CODIGO_PROPRIO'),
    estadoDeteccao: enumInterno(achado.estadoDeteccao, ENUM_ESTADO_DETECCAO, 'DETECTADO'),
    statusValidacao: enumInterno(
      achado.statusValidacao,
      ENUM_STATUS_VALIDACAO_ACHADO,
      'NECESSITA_REVISAO'
    ),
    startLine: inteiroNaoNegativo(achado.startLine),
    endLine: inteiroNaoNegativo(achado.endLine),
    message: fingerprintSeguro(achado.message),
    ...(achado.possivelPlaceholder === true ? { possivelPlaceholder: true } : {}),
    ...(achado.identidadeSimbolo
      ? { identidadeSimbolo: { status: enumInterno(achado.identidadeSimbolo.status, ENUM_STATUS_IDENTIDADE_SIMBOLO, 'NAO_DETERMINADA') } }
      : {}),
    // E2E mínimo: revisão humana selada no achado (0.8.0) — chave/contexto são hex; texto livre vira fingerprint.
    ...(achado.revisaoHumana !== undefined
      ? {
          chaveRevisao: hex16Seguro(achado.chaveRevisao),
          contextoRevisao: hex16Seguro(achado.contextoRevisao),
          revisaoHumana: projetarRevisaoHumanaSegura(achado.revisaoHumana)
        }
      : {}),
    // Fail closed: valor fora do enum vira REVISAO_NECESSARIA/BLOQUEIA, nunca INFORMATIVO.
    ...(achado.significado
      ? { significado: {
        classe: enumInterno(achado.significado.classe, ENUM_CLASSE_SIGNIFICADO, 'REVISAO_NECESSARIA'),
        efeitoNaDecisao: achado.significado.classe === 'INFORMATIVO'
          ? enumInterno(achado.significado.efeitoNaDecisao, ENUM_EFEITO_NA_DECISAO, 'BLOQUEIA')
          : 'BLOQUEIA'
      } }
      : {})
  };
}

// RF-08 (MASS-399): achado dos sensores informativos (comentário perigoso,
// CVE/dependência). Mesmo tratamento de segurança dos achados canônicos
// (fingerprint, nunca texto cru) — sem categoria/estadoDeteccao/
// statusValidacao, que são conceitos do ciclo de vida do achado GATEADO e
// não existem para um achado informativo.
function projetarAchadoInformativoSeguro(achado = {}) {
  return {
    scanner: enumInterno(achado.scanner, ENUM_SENSOR_INFORMATIVO, 'DESCONHECIDO'),
    ruleId: fingerprintSeguro(achado.ruleId),
    severity: enumInterno(achado.severity, ENUM_SEVERIDADE, 'INFO'),
    filePath: fingerprintSeguro(achado.filePath),
    startLine: inteiroNaoNegativo(achado.startLine),
    endLine: inteiroNaoNegativo(achado.endLine),
    message: fingerprintSeguro(achado.message)
  };
}

// RF-08 (MASS-399): projeta um bloco `{status, achados, identidade, erro}` de
// sensor informativo com o mesmo padrão de segurança do resto do --json.
function projetarInformativoSeguro(bloco) {
  if (!bloco) return null;
  const achados = Array.isArray(bloco.achados) ? bloco.achados.map(projetarAchadoInformativoSeguro) : [];
  return {
    status: enumInterno(bloco.status, ENUM_STATUS_INFORMATIVO, 'ERROR'),
    findingsCount: achados.length,
    achados,
    erro: bloco.erro ? fingerprintSeguro(bloco.erro) : null
  };
}

function projetarMapaClaimsSeguro(mapa) {
  if (!mapa || !Array.isArray(mapa.claims)) return null;
  const claims = mapa.claims.map((item = {}) => ({
    dimension: typeof item.dimension === 'string' && DIMENSOES_VALIDAS.has(item.dimension)
      ? item.dimension
      : 'objetivoProduto',
    claim: {
      declared: item.claim?.declared === true,
      summary: fingerprintOuNulo(item.claim?.summary)
    },
    evidence: {
      observed: item.evidence?.observed === true,
      reference: fingerprintOuNulo(item.evidence?.reference),
      summary: fingerprintOuNulo(item.evidence?.summary)
    },
    status: enumInterno(item.status, new Set(['ATENDE', 'NAO_ATENDE', 'NAO_COMPROVADO']), 'NAO_COMPROVADO'),
    coverage: item.coverage === 100 ? 100 : 0,
    conclusionSource: enumInterno(item.conclusionSource, new Set([
      'NO_DECLARED_CLAIM', 'DECLARATION_ONLY', 'EXTERNAL_CLAIM_EVIDENCE',
      'GIT_PROVENANCE', 'UNTRUSTED_EVIDENCE'
    ]), 'NO_DECLARED_CLAIM'),
    divergence: typeof item.divergence === 'boolean' ? item.divergence : null,
    minimumMissing: fingerprintOuNulo(item.minimumMissing)
  }));
  return {
    schemaVersion: '1.0.0',
    totalClaims: inteiroNaoNegativo(mapa.totalClaims),
    coverage: inteiroNaoNegativo(mapa.coverage),
    summary: {
      atende: inteiroNaoNegativo(mapa.summary?.atende),
      naoAtende: inteiroNaoNegativo(mapa.summary?.naoAtende),
      naoComprovado: inteiroNaoNegativo(mapa.summary?.naoComprovado)
    },
    claims
  };
}

// Fatia 1 (Scanner Completeness): projeção segura da completude. Estados, motivos,
// critérios e contagens são enums/inteiros internos e ficam em claro (o verify
// precisa deles para reconciliar sensor ↔ portão); caminhos, regras e tipos de
// erro vindos do scanner são fingerprintados como o resto da projeção.
const ENUM_COMPLETENESS_STATUS = new Set(['COMPLETE', 'PARTIAL', 'DEGRADED', 'UNKNOWN']);
const ENUM_COMPLETENESS_REASON = new Set(['TIMEOUT', 'FILE_SKIPPED', 'PARTIAL_PARSING', 'PARSE_ERROR', 'FILE_ERROR', 'RULE_ERROR', 'SCANNER_FAILURE', 'SIGNALS_MISSING', 'NOT_EVALUATED',
  // PL-02 (universo esperado)
  'UNSUPPORTED_EXTENSION', 'SIZE_LIMIT_EXCEEDED', 'OPERATIONAL_LIMIT', 'UNKNOWN_CAUSE', 'SCANNER_REPORTS_NO_COVERAGE_SIGNAL', 'READ_ERROR', 'LIMIT_EXCEEDED',
  // LC-06 (histórico Git)
  'SHALLOW_HISTORY', 'HISTORY_NOT_DETERMINED', 'HISTORY_COVERAGE_MISMATCH']);
const ENUM_COMPLETENESS_CRITERION = new Set([
  'SCANNER_STATUS_NOT_SUCCESS', 'SCANNER_OUTPUT_UNREADABLE', 'SUCCESS_WITHOUT_COMPLETENESS_SIGNALS',
  'SCANNER_WITHOUT_COMPLETENESS_MODEL', 'SUCCESS_WITH_FILE_OR_RULE_ERRORS', 'SUCCESS_ERRORS_EMPTY_AND_PATHS_PRESENT',
  // PL-02
  'SUCCESS_EXPECTED_UNIVERSE_ANALYZED', 'SUCCESS_WITH_UNANALYZED_EXPECTED_FILES',
  // LC-06
  'SUCCESS_EXPECTED_HISTORY_SCANNED'
]);
const ENUM_UNIVERSE_SOURCE = new Set(['RULEPACK_LANGUAGES', 'ALL_FILES_SENT']);
const ENUM_UNIVERSE_EVIDENCE = new Set(['SCANNER_REPORTS_NO_COVERAGE_SIGNAL']);
const ENUM_TIPO_EXCLUSAO = new Set(['DIRETORIO_POLITICA', 'LINK_SIMBOLICO', 'LIMITE_TAMANHO_ARQUIVO', 'OUTRA']);

// PL-02: o universo esperado é todo feito de contagens, enums e digests (nada vindo do alvo em claro); caminho algum
// aparece aqui. Valor fora da forma conhecida vira null — nunca um número inventado.
function projetarUniversoSeguro(u) {
  if (!u || typeof u !== 'object') return undefined;
  const inteiroOuNulo = (v) => (Number.isInteger(v) && v >= 0 ? v : null);
  const hex = (v) => (/^[0-9a-f]{64}$/.test(v ?? '') ? v : null);
  const b = u.boundary || {};
  return {
    model: /^pl\d{2}-\d+\.\d+$/.test(u.model ?? '') ? u.model : null,
    coverage: {
      languages: (Array.isArray(u.coverage?.languages) ? u.coverage.languages : []).filter((l) => l === 'javascript' || l === 'typescript'),
      expectedExtensions: (Array.isArray(u.coverage?.expectedExtensions) ? u.coverage.expectedExtensions : []).filter((e) => /^\.[a-z]{1,5}$/.test(e)),
      includesNodeShebangWithoutExtension: u.coverage?.includesNodeShebangWithoutExtension === true,
      source: enumInterno(u.coverage?.source, ENUM_UNIVERSE_SOURCE, 'RULEPACK_LANGUAGES')
    },
    boundary: {
      filesSent: inteiroNaoNegativo(b.filesSent),
      policyExclusions: inteiroNaoNegativo(b.policyExclusions),
      policyExclusionsByKind: Object.fromEntries(Object.entries(b.policyExclusionsByKind || {})
        .map(([k, n]) => [enumInterno(k, ENUM_TIPO_EXCLUSAO, 'OUTRA'), inteiroNaoNegativo(n)])),
      operationalLimitExclusions: inteiroNaoNegativo(b.operationalLimitExclusions),
      readErrors: inteiroNaoNegativo(b.readErrors)
    },
    expected: inteiroNaoNegativo(u.expected),
    ...(u.expectedBytes !== undefined ? { expectedBytes: inteiroOuNulo(u.expectedBytes) } : {}),
    analyzed: inteiroOuNulo(u.analyzed),
    partiallyAnalyzed: inteiroOuNulo(u.partiallyAnalyzed),
    notAnalyzed: inteiroOuNulo(u.notAnalyzed),
    scannedOutsideExpected: inteiroOuNulo(u.scannedOutsideExpected),
    byReason: Object.fromEntries(Object.entries(u.byReason || {})
      .filter(([k]) => ENUM_COMPLETENESS_REASON.has(k))
      .map(([k, n]) => [k, inteiroNaoNegativo(n)])),
    ...(u.notAnalyzedDigest !== undefined ? { notAnalyzedDigest: hex(u.notAnalyzedDigest) } : {}),
    ...(u.scannedDigest !== undefined ? { scannedDigest: hex(u.scannedDigest) } : {}),
    ...(u.evidence !== undefined ? { evidence: enumInterno(u.evidence, ENUM_UNIVERSE_EVIDENCE, 'SCANNER_REPORTS_NO_COVERAGE_SIGNAL') } : {})
  };
}

function projetarCompletudeSegura(c) {
  if (!c || typeof c !== 'object') {
    return { status: 'UNKNOWN', criterion: 'SCANNER_WITHOUT_COMPLETENESS_MODEL', reasons: ['NOT_EVALUATED'], affectedFileCount: 0, affectedFiles: [], ruleErrors: [], errorsByType: {}, filesScanned: null, effectiveLimits: null };
  }
  const motivos = (lista) => (Array.isArray(lista) ? lista : []).map((m) => enumInterno(m, ENUM_COMPLETENESS_REASON, 'FILE_ERROR'));
  return {
    status: enumInterno(c.status, ENUM_COMPLETENESS_STATUS, 'UNKNOWN'),
    criterion: enumInterno(c.criterion, ENUM_COMPLETENESS_CRITERION, 'SUCCESS_WITHOUT_COMPLETENESS_SIGNALS'),
    reasons: motivos(c.reasons),
    affectedFileCount: inteiroNaoNegativo(c.affectedFileCount),
    affectedFiles: (Array.isArray(c.affectedFiles) ? c.affectedFiles : []).map((a) => ({
      path: fingerprintSeguro(a?.path),
      reasons: motivos(a?.reasons),
      rules: (Array.isArray(a?.rules) ? a.rules : []).map((r) => fingerprintSeguro(r)),
      timeouts: inteiroNaoNegativo(a?.timeouts)
    })),
    ruleErrors: (Array.isArray(c.ruleErrors) ? c.ruleErrors : []).map((r) => ({
      reason: enumInterno(r?.reason, ENUM_COMPLETENESS_REASON, 'RULE_ERROR'),
      rule: fingerprintOuNulo(r?.rule)
    })),
    errorsByType: Object.fromEntries(Object.entries(c.errorsByType || {}).map(([tipo, n]) => [fingerprintSeguro(tipo), inteiroNaoNegativo(n)])),
    filesScanned: Number.isInteger(c.filesScanned) ? c.filesScanned : null,
    effectiveLimits: c.effectiveLimits && typeof c.effectiveLimits === 'object'
      ? {
          perRuleTimeoutSeconds: numeroFinito(c.effectiveLimits.perRuleTimeoutSeconds, null),
          timeoutsBeforeFileSkipped: Number.isInteger(c.effectiveLimits.timeoutsBeforeFileSkipped) ? c.effectiveLimits.timeoutsBeforeFileSkipped : null,
          maxTargetBytes: Number.isInteger(c.effectiveLimits.maxTargetBytes) ? c.effectiveLimits.maxTargetBytes : null
        }
      : null,
    // PL-02
    ...(c.affectedFilesTruncated !== undefined ? { affectedFilesTruncated: c.affectedFilesTruncated === true } : {}),
    ...(c.affectedFilesDigest !== undefined ? { affectedFilesDigest: /^[0-9a-f]{64}$/.test(c.affectedFilesDigest) ? c.affectedFilesDigest : null } : {}),
    ...(c.universe !== undefined ? { universe: projetarUniversoSeguro(c.universe) } : {}),
    // LC-06: cobertura do histórico Git — só números, SHA e booleanos com forma conhecida.
    ...(c.history !== undefined ? { history: projetarHistoricoSeguro(c.history) } : {})
  };
}

function projetarHistoricoSeguro(h) {
  const inteiroOuNulo = (n) => (Number.isInteger(n) && n >= 0 ? n : null);
  return {
    model: h?.model === 'lc06-1.0' ? 'lc06-1.0' : null,
    scope: h?.scope === 'HEAD_REACHABLE' ? 'HEAD_REACHABLE' : null,
    logOptions: typeof h?.logOptions === 'string' ? fingerprintSeguro(h.logOptions) : null,
    applicable: typeof h?.applicable === 'boolean' ? h.applicable : null,
    shallow: typeof h?.shallow === 'boolean' ? h.shallow : null,
    headCommit: /^[0-9a-f]{40}$/.test(h?.headCommit ?? '') ? h.headCommit : null,
    commitsTotal: inteiroOuNulo(h?.commitsTotal),
    commitsExpected: inteiroOuNulo(h?.commitsExpected),
    commitsScanned: inteiroOuNulo(h?.commitsScanned),
    ...(h?.expectedDigest !== undefined ? { expectedDigest: /^[0-9a-f]{64}$/.test(h.expectedDigest) ? h.expectedDigest : null } : {})
  };
}

// LC-06: detalhe da cobertura do scanner próprio de segredos — contagens e digests; caminhos só como fingerprint.
function projetarDetalheCoberturaSeguro(d) {
  if (!d || typeof d !== 'object') return null;
  const hex = (v) => (/^[0-9a-f]{64}$/.test(v ?? '') ? v : null);
  return {
    model: d.model === 'lc06-1.0' ? 'lc06-1.0' : null,
    bytesRead: inteiroNaoNegativo(d.bytesRead),
    encodings: Object.fromEntries(Object.entries(d.encodings || {}).filter(([k]) => ['bytes', 'utf16le', 'utf16be'].includes(k)).map(([k, n]) => [k, inteiroNaoNegativo(n)])),
    policyExclusions: {
      extensions: (Array.isArray(d.policyExclusions?.extensions) ? d.policyExclusions.extensions : []).filter((e) => /^\.[a-z0-9]{1,8}$/.test(e)),
      count: inteiroNaoNegativo(d.policyExclusions?.count),
      files: (Array.isArray(d.policyExclusions?.files) ? d.policyExclusions.files : []).map((p) => fingerprintSeguro(p)),
      digest: hex(d.policyExclusions?.digest)
    },
    notInspected: {
      count: inteiroNaoNegativo(d.notInspected?.count),
      files: (Array.isArray(d.notInspected?.files) ? d.notInspected.files : []).map((f) => ({ path: fingerprintSeguro(f?.path), format: ['zip', 'gzip', 'pdf', '7z', 'xz', 'bzip2', 'zstd', 'rar'].includes(f?.format) ? f.format : null, detection: ['EXTENSAO', 'ASSINATURA'].includes(f?.detection) ? f.detection : null })),
      digest: hex(d.notInspected?.digest)
    },
    universeDetermined: d.universeDetermined === true
  };
}

// Fatia 1 (revisão r1, achado 3): identidade da execução, canônica. Só valores internos
// com forma conhecida saem em claro (SHA hex, booleanos, ids de sensores do próprio
// motor); qualquer outra coisa vira null ou é descartada.
const SENSORES_DO_LOTE = new Set(['gitleaks', 'semgrep', 'git-diff', 'dangerous-comments', 'dependency-audit',
  'zunvio-segredos', 'gitleaks(historico)', 'git',
  'frontend-env-exposure(semgrep)', 'npm-audit', 'semgrep(frontend-env-exposure)']);
function projetarExecucaoSegura(execucao) {
  const eng = execucao?.engine || {};
  const lista = (v) => (Array.isArray(v) ? v.filter((x) => SENSORES_DO_LOTE.has(x)) : []);
  const inv = execucao?.invocation || {};
  return {
    engine: {
      name: eng.name === 'zunvio-score' ? 'zunvio-score' : null,
      version: /^\d+\.\d+\.\d+$/.test(eng.version ?? '') ? eng.version : null,
      commit: /^[0-9a-f]{40}$/.test(eng.commit ?? '') ? eng.commit : null,
      dirty: typeof eng.dirty === 'boolean' ? eng.dirty : null,
      codeDigest: /^[0-9a-f]{64}$/.test(eng.codeDigest ?? '') ? eng.codeDigest : null
    },
    invocation: Object.fromEntries(['informativeSensors', 'delta', 'includeVendor', 'publicationContract', 'projectEvidence']
      .map((k) => [k, typeof inv[k] === 'boolean' ? inv[k] : null])),
    concurrency: {
      parallelBatch: lista(execucao?.concurrency?.parallelBatch),
      externalProcessesInBatch: lista(execucao?.concurrency?.externalProcessesInBatch)
    }
  };
}

function projetarScannerCanonicoSeguro(sensor = {}, id, achados) {
  const achadosDoSensor = achados.filter((achado) => achado.scanner === id);
  const completion = enumInterno(sensor.completion, ENUM_COMPLETUDE, 'FAILED');
  return {
    id,
    status: enumInterno(sensor.status, ENUM_STATUS, 'ERROR'),
    findingsCount: achadosDoSensor.length,
    version: sensor.version === null || sensor.version === undefined ? null : fingerprintSeguro(sensor.version),
    configHash: sensor.configHash === null || sensor.configHash === undefined ? null : digestSeguro(sensor.configHash),
    findingsDigest: completion === 'CLEAN' || completion === 'WITH_FINDINGS'
      ? calcularHashCanonico(achadosDoSensor)
      : null,
    completion,
    ...(sensor.completeness !== undefined ? { completeness: projetarCompletudeSegura(sensor.completeness) } : {}),
    // LC-06: baseline do projeto selada por contagem e detalhe da cobertura do scanner próprio.
    ...(sensor.suppressedByBaseline !== undefined ? { suppressedByBaseline: { count: inteiroNaoNegativo(sensor.suppressedByBaseline?.count), blocking: inteiroNaoNegativo(sensor.suppressedByBaseline?.blocking) } } : {}),
    ...(sensor.coverageDetail !== undefined ? { coverageDetail: projetarDetalheCoberturaSeguro(sensor.coverageDetail) } : {})
  };
}

// Limitações na projeção continuam uma coleção de fingerprints (compatível com
// consumidores da projeção); a informação estruturada fica em `completeness`.
function projetarLimitacoesSeguras(limitacoes) {
  return projetarColecaoLivre((Array.isArray(limitacoes) ? limitacoes : []).map((l) => (
    l && typeof l === 'object' ? `${l.code}|${l.scanner ?? ''}|${l.where?.fileCount ?? ''}` : l
  )));
}

function projetarColecaoLivre(valores) {
  return Array.isArray(valores) ? valores.map((valor) => {
    if (valor && typeof valor === 'object' && !Array.isArray(valor)) {
      return Object.fromEntries(Object.keys(valor).sort().map((chave) => [fingerprintSeguro(chave), fingerprintSeguro(valor[chave])]));
    }
    return fingerprintSeguro(valor);
  }) : [];
}

function projetarScannerPublicoSeguro(scanner = {}, canonico = {}) {
  return {
    status: canonico.status,
    disponivel: scanner.disponivel === true,
    estadoOperacional: enumInterno(scanner.estadoOperacional, ENUM_ESTADO_OPERACIONAL, 'INDISPONIVEL'),
    resultadoSeguranca: enumInterno(scanner.resultadoSeguranca, ENUM_RESULTADO_SEGURANCA, 'NAO_AVALIADO'),
    totalAchados: canonico.findingsCount,
    totalAchadosBloqueantes: inteiroNaoNegativo(scanner.totalAchadosBloqueantes),
    totalAchadosInformativos: inteiroNaoNegativo(scanner.totalAchadosInformativos),
    ...(scanner.significados
      ? { significados: Object.fromEntries(['RISCO_DEMONSTRADO', 'REVISAO_NECESSARIA', 'INFORMATIVO', 'SEM_SIGNIFICADO']
        .map((c) => [c, inteiroNaoNegativo(scanner.significados[c])])) }
      : {}),
    resumoSeveridade: Object.fromEntries(
      [...ENUM_SEVERIDADE].map((sev) => [sev, inteiroNaoNegativo(scanner.resumoSeveridade?.[sev])])
    ),
    duracaoMs: numeroFinito(scanner.duracaoMs),
    erro: scanner.erro ? 'SCANNER_ERROR' : null,
    identidade: {
      id: canonico.id,
      versao: canonico.version,
      configHash: canonico.configHash,
      findingsDigest: canonico.findingsDigest,
      completion: canonico.completion
    }
  };
}

/**
 * Cria uma projeção de saída que continua sendo um Receipt verificável, sem
 * alterar o objeto canônico em memória e sem publicar texto externo cru.
 */
export function projetarRelatorioJsonSeguro(relatorio) {
  const originalCc = relatorio?.canonicalContent || {};
  const findings = Array.isArray(originalCc.findings)
    ? originalCc.findings.map(projetarAchadoSeguro)
    : [];
  const mapa = projetarMapaClaimsSeguro(originalCc.claimEvidenceMap);
  const decision = projetarDecisaoSegura(originalCc.decision || relatorio?.decision);
  const canonicalContent = {
    filesAnalyzed: inteiroNaoNegativo(originalCc.filesAnalyzed),
    inventoryDigest: digestSeguro(originalCc.inventoryDigest),
    targetDigest: digestSeguro(originalCc.targetDigest ?? relatorio?.integrityProof?.initialDigest),
    ...(Number.isInteger(originalCc.publicationContextCoverage ?? relatorio?.avaliacao?.contextoPublicacao?.coverage)
      ? { publicationContextCoverage: inteiroNaoNegativo(originalCc.publicationContextCoverage ?? relatorio.avaliacao.contextoPublicacao.coverage) }
      : {}),
    scannersSummary: {
      gitleaks: projetarScannerCanonicoSeguro(originalCc.scannersSummary?.gitleaks, 'gitleaks', findings),
      ...(originalCc.scannersSummary?.['zunvio-segredos'] !== undefined
        ? { 'zunvio-segredos': projetarScannerCanonicoSeguro(originalCc.scannersSummary['zunvio-segredos'], 'zunvio-segredos', findings) }
        : {}),
      semgrep: projetarScannerCanonicoSeguro(originalCc.scannersSummary?.semgrep, 'semgrep', findings)
    },
    ...(originalCc.completeness !== undefined
      ? {
          completeness: {
            status: enumInterno(originalCc.completeness?.status, ENUM_COMPLETENESS_STATUS, 'UNKNOWN'),
            byScanner: {
              gitleaks: enumInterno(originalCc.completeness?.byScanner?.gitleaks, ENUM_COMPLETENESS_STATUS, 'UNKNOWN'),
              ...(originalCc.completeness?.byScanner?.['zunvio-segredos'] !== undefined
                ? { 'zunvio-segredos': enumInterno(originalCc.completeness.byScanner['zunvio-segredos'], ENUM_COMPLETENESS_STATUS, 'UNKNOWN') }
                : {}),
              semgrep: enumInterno(originalCc.completeness?.byScanner?.semgrep, ENUM_COMPLETENESS_STATUS, 'UNKNOWN')
            }
          }
        }
      : {}),
    findingsCount: findings.length,
    findings,
    exclusions: projetarColecaoLivre(originalCc.exclusions),
    limitations: projetarLimitacoesSeguras(originalCc.limitations),
    decision,
    ...(mapa ? { claimEvidenceMap: mapa } : {}),
    ...(originalCc.execution !== undefined ? { execution: projetarExecucaoSegura(originalCc.execution) } : {}),
    ...(Array.isArray(originalCc.humanReviews) ? { humanReviews: originalCc.humanReviews.map(projetarRevisaoHumanaSegura) } : {})
  };
  const canonicalHash = calcularHashCanonico(canonicalContent);
  // RF-08 (MASS-399): informativo, DELIBERADAMENTE fora de canonicalContent —
  // mesmo motivo do pack bruto (evidence-pack.mjs): dependenciasCve vem de uma
  // base de CVE viva, não é reproduzível ao longo do tempo para o mesmo
  // código. Selar isso sob o hash quebraria a garantia de reprodutibilidade
  // do canonicalHash que RF-09/notarização depende.
  const originalInformativos = relatorio?.informativeFindings;
  const informativeFindings = originalInformativos ? {
    comentariosPerigosos: projetarInformativoSeguro(originalInformativos.comentariosPerigosos),
    dependenciasCve: projetarInformativoSeguro(originalInformativos.dependenciasCve),
    frontendEnvExposure: projetarInformativoSeguro(originalInformativos.frontendEnvExposure)
  } : null;
  const integrityProof = {
    scope: fingerprintSeguro(relatorio?.integrityProof?.scope ?? relatorio?.target),
    algorithm: 'SHA-256',
    measurements: ['INICIO_EXECUCAO', 'FIM_EXECUCAO'],
    outsideTargetChanges: 'PERMITIDAS_E_ESPERADAS',
    initialDigest: digestSeguro(relatorio?.integrityProof?.initialDigest),
    finalDigest: digestSeguro(relatorio?.integrityProof?.finalDigest),
    immutable: relatorio?.integrityProof?.immutable === true,
    differences: projetarColecaoLivre(relatorio?.integrityProof?.differences)
  };
  const coverage = relatorio?.coverageAndResidualRisk || {};
  const gitleaksPublico = projetarScannerPublicoSeguro(
    relatorio?.scanners?.gitleaks,
    canonicalContent.scannersSummary.gitleaks
  );
  const semgrepPublico = projetarScannerPublicoSeguro(
    relatorio?.scanners?.semgrep,
    canonicalContent.scannersSummary.semgrep
  );
  // MASS-307 revisão: projeção em TRÊS estados a partir do outcome canônico selado.
  // Outcome desconhecido NÃO vira decisão de publicação: vira INVÁLIDO (falha fechada).
  const outcome = decision.outcome;
  const publicar = outcome === 'ACCEPT';
  const inconclusivo = outcome === 'UNPROVEN';
  const rejeitar = outcome === 'REJECT';
  const invalido = !publicar && !inconclusivo && !rejeitar;
  const portoesPublicos = decision.gates;
  const decisaoPublica = {
    codigo: publicar ? 'ACEITAR' : (inconclusivo ? 'INCONCLUSIVO' : (rejeitar ? 'NAO_ACEITAR' : 'INVALIDO')),
    decisaoPublicacao: publicar ? 'PUBLICAR' : (inconclusivo ? 'INCONCLUSIVO' : (rejeitar ? 'NAO_PUBLICAR' : 'INVALIDO')),
    rotulo: publicar ? 'PUBLICAR' : (inconclusivo ? 'INCONCLUSIVO' : (rejeitar ? 'NÃO PUBLICAR' : 'INVÁLIDO')),
    publicar,
    inconclusivo,
    invalido,
    mensagem: publicar ? 'DECISAO_ACEITAR' : (inconclusivo ? 'DECISAO_INCONCLUSIVO' : (rejeitar ? 'DECISAO_REJEITAR' : 'DECISAO_INVALIDA')),
    naturezaImpedimento: enumInterno(
      relatorio?.avaliacao?.decisao?.naturezaImpedimento,
      ENUM_NATUREZA,
      publicar ? 'NENHUM' : (inconclusivo || invalido ? 'LIMITE_ZUNVIO' : 'PROJETO_OU_CLIENTE')
    ),
    impedimentos: {
      bloqueiosMateriaisDetectados: projetarColecaoLivre(
        relatorio?.avaliacao?.decisao?.impedimentos?.reprovacoesProjeto
      ),
      semEvidenciaCliente: projetarColecaoLivre(relatorio?.avaliacao?.decisao?.impedimentos?.semEvidenciaCliente),
      foraCoberturaMotor: projetarColecaoLivre(relatorio?.avaliacao?.decisao?.impedimentos?.foraCoberturaMotor),
      falhasMotor: projetarColecaoLivre(relatorio?.avaliacao?.decisao?.impedimentos?.falhasMotor)
    },
    bloqueadores: projetarColecaoLivre(relatorio?.avaliacao?.decisao?.bloqueadores)
  };
  return {
    versao: VERSAO,
    outputProjection: {
      code: 'SAFE_FINGERPRINTED_V1',
      sourceCanonicalHash: digestSeguro(relatorio?.canonicalHash)
    },
    target: fingerprintSeguro(relatorio?.target),
    canonicalHash,
    canonicalContent,
    volatileMetadata: {
      timestamp: timestampVolatilSeguro(relatorio?.volatileMetadata?.timestamp),
      durationMs: numeroFinito(relatorio?.volatileMetadata?.durationMs),
      systemPlatform: fingerprintSeguro(relatorio?.volatileMetadata?.systemPlatform)
    },
    integrityProof,
    decision,
    ...(mapa ? { claimEvidenceMap: mapa } : {}),
    ...(informativeFindings ? { informativeFindings } : {}),
    coverageAndResidualRisk: {
      excludedPaths: projetarColecaoLivre(coverage.excludedPaths),
      unexecutedChecks: Array.isArray(coverage.unexecutedChecks)
        ? coverage.unexecutedChecks.map((check) => enumInterno(check, ENUM_CHECK, fingerprintSeguro(check)))
        : [],
      residualRiskStatement: fingerprintSeguro(coverage.residualRiskStatement)
    },
    delta: {
      ativo: relatorio?.delta?.ativo === true,
      ehRepositorioGit: relatorio?.delta?.ehRepositorioGit === true,
      baseRef: fingerprintOuNulo(relatorio?.delta?.baseRef),
      headRef: fingerprintOuNulo(relatorio?.delta?.headRef),
      arquivosAlterados: inteiroNaoNegativo(relatorio?.delta?.arquivosAlterados),
      blastRadius: relatorio?.delta?.blastRadius ? {
        linhasAdicionadas: inteiroNaoNegativo(relatorio.delta.blastRadius.linhasAdicionadas),
        linhasRemovidas: inteiroNaoNegativo(relatorio.delta.blastRadius.linhasRemovidas),
        totalChurn: inteiroNaoNegativo(relatorio.delta.blastRadius.totalChurn),
        pegadaMudanca: enumInterno(relatorio.delta.blastRadius.pegadaMudanca, ENUM_PEGADA),
        rotuloRisco: enumInterno(relatorio.delta.blastRadius.rotuloRisco, ENUM_RISCO),
        modulosAfetados: projetarColecaoLivre(relatorio.delta.blastRadius.modulosAfetados)
      } : null,
      resumoAchadosDelta: relatorio?.delta?.resumoAchadosDelta ? {
        totalAchadosNoDelta: inteiroNaoNegativo(relatorio.delta.resumoAchadosDelta.totalAchadosNoDelta),
        totalAchadosHistoricos: inteiroNaoNegativo(relatorio.delta.resumoAchadosDelta.totalAchadosHistoricos)
      } : null,
      arquivos: [],
      erro: relatorio?.delta?.erro ? 'DELTA_ERROR' : null
    },
    scanners: {
      gitleaks: gitleaksPublico,
      ...(canonicalContent.scannersSummary['zunvio-segredos'] !== undefined
        ? { 'zunvio-segredos': projetarScannerPublicoSeguro(relatorio?.scanners?.['zunvio-segredos'], canonicalContent.scannersSummary['zunvio-segredos']) }
        : {}),
      semgrep: semgrepPublico
    },
    totalAchados: findings.length,
    resumoSeveridade: Object.fromEntries(
      [...ENUM_SEVERIDADE].map((sev) => [sev, inteiroNaoNegativo(relatorio?.resumoSeveridade?.[sev])])
    ),
    resumoCategorias: Object.fromEntries(
      [...ENUM_CATEGORIA_ACHADO].map((categoria) => [
        categoria,
        inteiroNaoNegativo(relatorio?.resumoCategorias?.[categoria])
      ])
    ),
    achados: findings.map((achado, indice) => ({
      ...achado,
      id: achadoIdSeguro(relatorio?.achados?.[indice]?.id),
      // Hash interno do achado (não é texto externo): o contrato de ingestão
      // exige fingerprint por achado — MASS-318 item 6.
      fingerprint: achadoFingerprintSeguro(relatorio?.achados?.[indice]?.fingerprint),
      deltaInfo: relatorio?.achados?.[indice]?.deltaInfo?.noDelta === true ? { noDelta: true } : null
    })),
    timestamp: fingerprintSeguro(relatorio?.timestamp),
    duracaoTotalMs: numeroFinito(relatorio?.duracaoTotalMs),
    arquivosAnalisados: inteiroNaoNegativo(relatorio?.arquivosAnalisados),
    integridade: {
      inalterado: integrityProof.immutable,
      digestInicial: integrityProof.initialDigest,
      digestFinal: integrityProof.finalDigest,
      diferencas: integrityProof.differences
    },
    avaliacao: {
      score: {
        observado: decision.score,
        maximoPossivel: decision.maxPossibleScore,
        cobertura: decision.coverage
      },
      contextoPublicacao: {
        schemaVersion: '1.0.0',
        source: enumInterno(
          relatorio?.avaliacao?.contextoPublicacao?.source,
          new Set(['internal-target', 'inline-external', 'safe-discovery']),
          'safe-discovery'
        ),
        provided: relatorio?.avaliacao?.contextoPublicacao?.provided === true,
        valid: relatorio?.avaliacao?.contextoPublicacao?.valid === true,
        sufficient: relatorio?.avaliacao?.contextoPublicacao?.sufficient === true,
        coverage: inteiroNaoNegativo(relatorio?.avaliacao?.contextoPublicacao?.coverage),
        provenDimensions: Array.isArray(relatorio?.avaliacao?.contextoPublicacao?.provenDimensions)
          ? relatorio.avaliacao.contextoPublicacao.provenDimensions.filter((item) => DIMENSOES_VALIDAS.has(item))
          : [],
        unprovenDimensions: Array.isArray(relatorio?.avaliacao?.contextoPublicacao?.unprovenDimensions)
          ? relatorio.avaliacao.contextoPublicacao.unprovenDimensions.filter((item) => DIMENSOES_VALIDAS.has(item))
          : []
      },
      decisao: decisaoPublica,
      portoes: portoesPublicos
    }
  };
}

export function serializarJsonSeguro(valor) {
  const serializado = `${JSON.stringify(valor, null, 2)}\n`;
  if (serializado.split(/\r?\n/u).every((linha) => linha.length <= MAX_LINHA_JSON)) {
    return serializado;
  }
  return `${JSON.stringify({
    resultado: 'INVALIDO',
    codigo: 'SAIDA_JSON_EXCEDE_LIMITE',
    fingerprint: fingerprintSeguro(serializado)
  }, null, 2)}\n`;
}

function respostaVerifySegura({ resultado, rotulo, motivos = [] }, codigo) {
  return {
    resultado: enumInterno(resultado, new Set(Object.values(RESULTADO)), RESULTADO.INVALIDO),
    rotulo: resultado === RESULTADO.VALIDO ? rotulo : (resultado === RESULTADO.NAO_SUPORTADO ? 'NÃO SUPORTADO' : 'INVÁLIDO'),
    codigo,
    quantidadeMotivos: Array.isArray(motivos) ? motivos.length : 0,
    motivos: Array.isArray(motivos) ? motivos.map(fingerprintSeguro) : []
  };
}

// B4/P2: detecta chaves duplicadas no texto JSON cru, antes do JSON.parse (que
// as colapsaria silenciosamente). Compara as chaves APÓS decodificação JSON
// (escapes Unicode, barra, aspas, controles etc.), para que "\\u0076ersao" e
// "versao" sejam tratadas como a MESMA chave. Um receipt com chave duplicada é
// ambíguo e não confiável.
function detectarChavesDuplicadas(texto) {
  const duplicadas = [];
  const niveis = []; // pilha de Set por objeto
  let i = 0;
  const n = texto.length;
  const pularEspacos = () => { while (i < n && /\s/.test(texto[i])) i++; };
  // Lê uma string JSON (com aspas) e decodifica o conteúdo via JSON.parse, para
  // comparar chaves semanticamente (não pela grafia crua).
  const lerStringDecodificada = () => {
    let j = i + 1;
    while (j < n) {
      const c = texto[j];
      if (c === '\\') { j += 2; continue; }
      if (c === '"') { j++; break; }
      j++;
    }
    const literal = texto.slice(i, j);
    i = j;
    try {
      return JSON.parse(literal);
    } catch {
      return literal;
    }
  };
  while (i < n) {
    const c = texto[i];
    if (c === '"') {
      const chave = lerStringDecodificada();
      pularEspacos();
      if (texto[i] === ':' && niveis.length > 0) {
        const conjunto = niveis[niveis.length - 1];
        if (conjunto.has(chave)) duplicadas.push(chave);
        else conjunto.add(chave);
        i++; // consome ':'
      }
      continue;
    }
    if (c === '{') { niveis.push(new Set()); i++; continue; }
    if (c === '}') { niveis.pop(); i++; continue; }
    i++;
  }
  return duplicadas;
}

// Verifica um Score Receipt (Evidence Pack) a partir de um arquivo JSON, sem
// reexecutar scanners, sem rede e sem escrever em lugar algum. Saída é JSON
// { resultado, motivos }; código de saída 0=VALIDO, 1=INVALIDO, 2=NAO_SUPORTADO/uso.
function executarVerify(args, stdout) {
  const caminho = args[1];
  if (!caminho) {
    stdout(serializarJsonSeguro(respostaVerifySegura(
      { resultado: RESULTADO.INVALIDO, motivos: [] },
      'VERIFY_USO_INVALIDO'
    )));
    return 2;
  }
  let cru;
  try {
    cru = readFileSync(resolve(caminho), 'utf8');
  } catch {
    stdout(serializarJsonSeguro(respostaVerifySegura(
      { resultado: RESULTADO.INVALIDO, motivos: [] },
      'RECEIPT_INACESSIVEL'
    )));
    return 2;
  }
  const duplicadas = detectarChavesDuplicadas(cru);
  if (duplicadas.length > 0) {
    stdout(serializarJsonSeguro(respostaVerifySegura(
      { resultado: RESULTADO.INVALIDO, motivos: duplicadas },
      'JSON_CHAVE_DUPLICADA'
    )));
    return 1;
  }
  let receipt;
  try {
    receipt = JSON.parse(cru);
  } catch {
    // B6: erro de leitura vira código fixo — nunca ecoa error.message cru.
    stdout(serializarJsonSeguro(respostaVerifySegura(
      { resultado: RESULTADO.INVALIDO, motivos: [] },
      'JSON_INVALIDO'
    )));
    return 2;
  }
  const verificacao = verificarReceipt(receipt);
  const codigo = verificacao.resultado === RESULTADO.VALIDO
    ? 'RECEIPT_VALIDO'
    : verificacao.resultado === RESULTADO.NAO_SUPORTADO
      ? 'VERSAO_NAO_SUPORTADA'
      : 'RECEIPT_INVALIDO';
  stdout(serializarJsonSeguro(respostaVerifySegura(verificacao, codigo)));
  if (verificacao.resultado === RESULTADO.VALIDO) return 0;
  if (verificacao.resultado === RESULTADO.NAO_SUPORTADO) return 2;
  return 1;
}

function respostaNotarizeSegura(resultado, codigo) {
  return {
    status: resultado.status,
    codigo,
    canonicalHash: resultado.canonicalHash,
    algoritmo: resultado.algoritmo,
    geradoEm: resultado.geradoEm,
    provaArquivo: resultado.provaArquivo || null,
    erro: resultado.status === STATUS_NOTARIZACAO.SUCESSO ? null : (resultado.erro || null)
  };
}

// RF-09 (MASS-399): notariza o canonicalHash de um Evidence Pack já gerado
// (`zunvio ... --json > receipt.json`) via OpenTimestamps e salva o `.ots`
// resultante ao lado do receipt. Não reexecuta a análise nem recalcula o
// hash — lê exatamente o que já foi selado no arquivo.
async function executarNotarize(args, stdout) {
  const caminho = args[1];
  if (!caminho) {
    stdout(serializarJsonSeguro(respostaNotarizeSegura(
      { status: STATUS_NOTARIZACAO.HASH_INVALIDO, erro: 'Uso: zunvio notarize <receipt.json>' },
      'NOTARIZE_USO_INVALIDO'
    )));
    return 2;
  }

  const caminhoAbsoluto = resolve(caminho);
  let cru;
  try {
    cru = readFileSync(caminhoAbsoluto, 'utf8');
  } catch {
    stdout(serializarJsonSeguro(respostaNotarizeSegura(
      { status: STATUS_NOTARIZACAO.ERRO, erro: 'Receipt inacessível.' },
      'RECEIPT_INACESSIVEL'
    )));
    return 2;
  }

  const duplicadas = detectarChavesDuplicadas(cru);
  if (duplicadas.length > 0) {
    stdout(serializarJsonSeguro(respostaNotarizeSegura(
      { status: STATUS_NOTARIZACAO.ERRO, erro: 'Receipt com chave JSON duplicada.' },
      'JSON_CHAVE_DUPLICADA'
    )));
    return 1;
  }

  let receipt;
  try {
    receipt = JSON.parse(cru);
  } catch {
    // B6: erro de leitura vira código fixo — nunca ecoa error.message cru.
    stdout(serializarJsonSeguro(respostaNotarizeSegura(
      { status: STATUS_NOTARIZACAO.ERRO, erro: 'JSON inválido.' },
      'JSON_INVALIDO'
    )));
    return 2;
  }

  const resultado = await notarizarCanonicalHash(receipt?.canonicalHash);

  if (resultado.status !== STATUS_NOTARIZACAO.SUCESSO) {
    const codigo = resultado.status === STATUS_NOTARIZACAO.HASH_INVALIDO
      ? 'RECEIPT_SEM_HASH_CANONICO'
      : resultado.status === STATUS_NOTARIZACAO.INDISPONIVEL
        ? 'OTS_INDISPONIVEL'
        : 'NOTARIZACAO_FALHOU';
    stdout(serializarJsonSeguro(respostaNotarizeSegura(resultado, codigo)));
    return resultado.status === STATUS_NOTARIZACAO.HASH_INVALIDO
      || resultado.status === STATUS_NOTARIZACAO.INDISPONIVEL ? 2 : 1;
  }

  const caminhoProva = `${caminhoAbsoluto}.ots`;
  try {
    writeFileSync(caminhoProva, Buffer.from(resultado.provaBase64, 'base64'));
  } catch {
    stdout(serializarJsonSeguro(respostaNotarizeSegura(
      { status: STATUS_NOTARIZACAO.ERRO, erro: 'Notarização concluída, mas falhou ao salvar o .ots ao lado do receipt.' },
      'PROVA_NAO_SALVA'
    )));
    return 1;
  }

  stdout(serializarJsonSeguro(respostaNotarizeSegura(
    { ...resultado, provaArquivo: caminhoProva },
    'NOTARIZADO'
  )));
  return 0;
}

// Imprime o glossário reutilizável (MASS-103, comentário 9) — mesma fonte
// consumida pela seção "Entenda os termos" do relatório HTML
// (src/glossary/termos.mjs). Somente leitura, sem varredura nem rede.
function executarGlossario(stdout) {
  const linhas = ['', 'ZUNVIO — Glossário', '================================================================', ''];
  for (const item of TERMOS_GLOSSARIO) {
    linhas.push(item.termo);
    linhas.push(`  ${item.definicao}`);
    linhas.push('');
  }
  linhas.push('Relatório completo, histórico e acompanhamento: https://zunvio.com.br');
  stdout(`${linhas.join('\n')}\n`);
  return 0;
}

// Ordem de exibição do indicador de etapas (MASS-103, comentário 8). Rótulos
// refletem a ordem real de execução do orquestrador, não o exemplo conceitual
// (não vinculante) da issue.
const ETAPAS_PROGRESSO = [
  'Preparação e integridade',
  'Gitleaks',
  'Semgrep',
  'Contexto (contrato e evidências)',
  'Decisão'
];

export async function executarCli(args = [], io = {}, opcoesExtras = {}) {
  const stdout = io.stdout || ((msg) => process.stdout.write(msg));
  const stderr = io.stderr || ((msg) => process.stderr.write(msg));

  if (args[0] === 'verify') {
    return executarVerify(args, stdout);
  }

  if (args[0] === 'notarize') {
    return executarNotarize(args, stdout);
  }

  if (args[0] === 'glossario') {
    return executarGlossario(stdout);
  }

  // E2E mínimo: descrever o projeto (init) e registrar revisão humana (revisar).
  if (args[0] === 'init') {
    return executarInit(args, { stdout, perguntar: io.perguntar });
  }
  if (args[0] === 'revisar') {
    return executarRevisar(args, { stdout, stderr, perguntar: io.perguntar });
  }

  const parsed = parseCliArgs(args);

  if (parsed.help) {
    stdout(gerarTextoAjuda());
    return 0;
  }

  if (parsed.version) {
    stdout(`zunvio v${VERSAO}\n`);
    return 0;
  }

  // O indicador ao vivo só existe em TTY interativo real, nunca em --json,
  // pipe/redirecionamento, CI ou NO_COLOR — nesses casos permanece `null` e
  // nenhum código ANSI é escrito (comentário 8: "desligar automaticamente").
  const usarIndicador = Boolean(process.stdout.isTTY) && !parsed.json && !process.env.NO_COLOR;
  let indicador = null;

  try {
    if (usarIndicador) {
      indicador = criarIndicadorEtapas(ETAPAS_PROGRESSO);
    }

    // E2E mínimo (só no binário real, `persistir`): usa o que o `init` declarou (fora do repositório) quando não há
    // --contract/--evidence, e liga a análise de delta contra o commit anterior quando ele existe — sem delta nenhum
    // projeto alcança PUBLICAR (ficha do portão), e o usuário não deveria precisar saber de --diff.
    const persistir = opcoesExtras.persistir === true;
    const declarado = persistir ? contextoDeclarado(parsed.target) : { contrato: null, evidencias: null };
    const deltaAutomatico = persistir && !parsed.diff && temCommitAnterior(parsed.target);
    const { persistir: _p, ...opcoesMotor } = opcoesExtras;
    const relatorio = await executarAnaliseProjeto(parsed.target, {
      delta: {
        ativo: parsed.diff || deltaAutomatico,
        baseRef: parsed.baseRef || (deltaAutomatico ? 'HEAD~1' : null),
        headRef: parsed.headRef
      },
      caminhoContrato: parsed.caminhoContrato || declarado.contrato,
      caminhoEvidencias: parsed.caminhoEvidencias || declarado.evidencias,
      includeVendor: parsed.includeVendor === true,
      onEtapa: indicador
        ? (nome, estado) => (estado === 'concluida' ? indicador.concluir(nome) : indicador.iniciar(nome))
        : undefined,
      ...opcoesMotor
    });
    indicador?.finalizar();

    if (parsed.json) {
      stdout(serializarJsonSeguro(projetarRelatorioJsonSeguro(relatorio)));
    } else {
      let caminhoRelatorio = null;
      let evolucao = null;
      if (persistir) {
        try { caminhoRelatorio = gravarRelatorio(parsed.target, gerarRelatorioHtml(relatorio), parsed.caminhoRelatorio); } catch { caminhoRelatorio = null; }
        try { evolucao = registrarEvolucao(parsed.target, relatorio); } catch { evolucao = null; }
        try { registrarRevisaveis(parsed.target, relatorio); } catch {}
      }
      stdout(`${formatarRelatorioHumano(relatorio, { noBanner: parsed.noBanner === true, caminhoRelatorio })}\n`);
      if (evolucao) stdout(`${formatarEvolucao(evolucao, (t) => textoLegivelSeguro(t, 300))}\n\n`);
      if (persistir && !caminhoRelatorio) stdout('Relatório HTML não pôde ser gerado nesta análise.\n');
    }

    // MASS-307: código de saída em TRÊS estados canônicos.
    //   0 = PUBLICAR (pronto);
    //   1 = NAO_PUBLICAR (achado alto a revisar ou outro bloqueio material);
    //   2 = INCONCLUSIVO (sensor ausente/falha/timeout/truncamento/cobertura
    //       insuficiente/alvo fora de cobertura/integridade não comprovada).
    // O código 3 é reservado para erro operacional/uso (no catch abaixo).
    const decisaoPublicacao = relatorio.avaliacao?.decisao?.decisaoPublicacao;
    if (decisaoPublicacao === 'PUBLICAR') return 0;
    if (decisaoPublicacao === 'NAO_PUBLICAR') return 1;
    if (decisaoPublicacao === 'INCONCLUSIVO') return 2;
    // Fallback defensivo: sem decisão reconhecida, falha fechado como erro.
    return 3;
  } catch {
    // O indicador nunca pode ficar preso (cursor oculto, animação viva) no
    // caminho de erro — finalizar aqui também, idempotente.
    indicador?.finalizar();
    // B6: erro vira código fixo — nunca ecoa error.message cru (que poderia
    // conter target hostil, tokens e linhas sem limite).
    if (parsed.json) {
      stdout(serializarJsonSeguro({ erro: 'ERRO_ANALISE' }));
    } else {
      stderr('\n[ZUNVIO ERRO]: análise não concluída.\n');
    }
    return 3;
  }
}

function temCommitAnterior(alvo) {
  try {
    execFileSyncCli('git', ['-C', alvo, 'rev-parse', '--verify', '--quiet', 'HEAD~1^{commit}'], { stdio: 'ignore', timeout: 15000 });
    return true;
  } catch {
    return false;
  }
}
