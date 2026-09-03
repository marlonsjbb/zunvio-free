import { resolve } from 'node:path';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { executarAnaliseProjeto } from './orchestrator.mjs';
import packageJson from '../package.json' with { type: 'json' };
import { verificarReceipt, RESULTADO } from './receipt/verifier.mjs';
import { calcularHashCanonico } from './utils/canonical-json.mjs';

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

  const inicio = args[0] === 'analyze' ? 1 : 0;

  for (let i = inicio; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      help = true;
    } else if (arg === '--version' || arg === '-v') {
      version = true;
    } else if (arg === '--json') {
      json = true;
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
    caminhoEvidencias
  };
}

export function gerarTextoAjuda() {
  return `
ZUNVIO Score v${VERSAO} — Avaliação de Prontidão e Análise Estática Segura (Read-Only)

USO:
  zunvio analyze <projeto> [opções]
  zunvio [caminho-do-projeto] [opções]
  zunvio verify <receipt.json>
  node bin/zunvio.mjs [caminho-do-projeto] [opções]

OPÇÕES:
  -t, --target <dir>       Caminho do diretório local a analisar (padrão: '.')
  -c, --contract <arquivo> Caminho do arquivo JSON do contrato de publicação
  -e, --evidence <arquivo> Caminho do arquivo JSON com evidências adicionais
  -d, --diff               Habilita a análise de delta Git e cálculo de Blast Radius
  --base, --since <ref>    Referência Git base para o diff (ex: 'main', 'HEAD~1')
  --head <ref>             Referência Git de destino para o diff (padrão: 'HEAD')
  --json                   Exibe a saída em formato JSON estruturado
  -h, --help               Exibe esta mensagem de ajuda
  -v, --version            Exibe a versão do ZUNVIO

EXEMPLOS:
  zunvio analyze project-alpha
  zunvio analyze ./meu-projeto --contract ./zunvio-contract.json
  zunvio ./meu-projeto --evidence ./evidences.json --json
  zunvio .
  zunvio --diff --base origin/main
  zunvio verify ./score-receipt.json

DECISÃO (código de saída):
  0 = PUBLICAR      avaliação obrigatória concluída e nenhum bloqueador
  1 = NÃO PUBLICAR  bloqueador material comprovado (achado/reprovação/integridade)
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
      acao: 'Instale ou restaure o Gitleaks no ambiente da ferramenta e repita a análise.'
    })
  }),
  seguranca_estatica: Object.freeze({
    NAO_ATENDE: Object.freeze({
      impacto: 'Vulnerabilidade estática bloqueia a publicação.',
      acao: 'Corrija a regra Semgrep identificada (ver Detalhamento dos Achados) e repita a análise.'
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
      acao: 'Forneça a evidência/contrato de funcionamento e testes (--evidence / --contract) e repita a análise.'
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

function descreverAcao(portao) {
  const tabela = ACAO_POR_PORTAO[portao.id];
  let impacto = 'Requisito não atendido.';
  let acao = 'Resolva o requisito indicado e repita a análise.';
  if (tabela) {
    const chave = portao.estado === 'NAO_COMPROVADO' ? (portao.subcausa || '') : 'NAO_ATENDE';
    const desc = tabela[chave] || tabela.NAO_ATENDE;
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
const SUBCAUSAS_VALIDAS = new Set(['SEM_EVIDENCIA_DO_CLIENTE', 'FORA_DE_COBERTURA_DO_MOTOR', 'MOTOR_FALHOU']);
const ENUM_SEVERIDADE = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
const ENUM_PEGADA = new Set(['NENHUMA', 'LOCALIZADA', 'MODULAR', 'TRANSVERSAL']);
const ENUM_RISCO = new Set(['BAIXO', 'MEDIO', 'ALTO']);
const ENUM_STATUS = new Set(['SUCCESS', 'UNAVAILABLE', 'ERROR', 'TIMEOUT', 'BUFFER_OVERFLOW']);
const ENUM_NATUREZA = new Set(['NENHUM', 'LIMITE_ZUNVIO', 'MISTO', 'PROJETO_OU_CLIENTE']);
// MASS-307: estados canônicos de decisão de publicação (inclui INCONCLUSIVO).
const ENUM_DECISAO = new Set(['PUBLICAR', 'NAO_PUBLICAR', 'INCONCLUSIVO']);
const ENUM_BADGE = new Set(['ANALYZED', 'SCORE', 'VERIFIED']);
// B6: dimensões canônicas do contrato (enum interno) — nunca allowlist sintática.
const DIMENSOES_VALIDAS = new Set([
  'objetivoProduto', 'publicoUsuarios', 'jornadasCriticas', 'ambientePublicacao',
  'integracoesIndispensaveis', 'dadosTratados', 'requisitosSegurancaPrivacidade',
  'capacidadeDesempenho', 'requisitosLegaisRegulatorios', 'operacaoRollback',
  'criteriosInaceitaveis', 'vinculoRelease'
]);
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
    if (natureza === 'MISTO') return 'Há reprovações comprovadas do projeto e limitações do ZUNVIO.';
    return `Existem ${total} bloqueador(es) material(is) comprovado(s) que impedem a publicação.`;
  }
  // INVÁLIDO: decisão desconhecida/incompatível — nunca uma decisão de publicação.
  return 'DECISÃO DESCONHECIDA OU INVÁLIDA — FALHA FECHADA.';
}

export function formatarRelatorioHumano(relatorio) {
  // Primeira linha vazia: o banner nunca cola na última linha do
  // provisionamento (e a folha de marca pede respiro).
  const linhas = [''];
  const lim = (s) => String(s).slice(0, 400);
  // Banner na forma da folha de marca (terminal.png): o z de traço duplo,
  // transcrito do grid da referência ampliada (barras de contorno com _ e |,
  // duas diagonais paralelas descendo 2 colunas por linha, tampas de _
  // fechando os paralelogramos). Só ASCII puro (_ | /), sem macron: zero
  // dependência de fonte/codepage. Teal quando o terminal é interativo.
  const arteZ = [
    '    __________________',
    '  |_______________    |',
    '         _____  /    /',
    '       /    / /    /',
    '     /    / /____/',
    '   /    /____________',
    '  |___________________|'
  ];
  const comTeal = process.stdout.isTTY && !process.env.NO_COLOR;
  for (const linhaArte of arteZ) {
    linhas.push(comTeal ? `\u001b[36m${linhaArte}\u001b[0m` : linhaArte);
  }
  linhas.push('');
  linhas.push(`ZUNVIO CLI v${VERSAO}`);
  linhas.push('Evidence Pack v0.2.0');
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
  linhas.push(lim(`Arquivos Varredura:  ${numSeguro(relatorio.arquivosAnalisados)}`));

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
    linhas.push('----------------------------------------------------------------');
    linhas.push('ANALYSIS COMPLETE.');
    linhas.push(lim(`ZUNVIO SCORE · ${numSeguro(score.observado)}`));
    linhas.push(lim(`SCORE MÁXIMO · ${numSeguro(score.maximoPossivel)}`));
    // Cobertura por responsabilidade, cada conta na sua linha. O total
    // min(motores, contrato) existe só para o portão de PUBLICAR (interno,
    // regra inalterada): como manchete ele era um 0% perpétuo sem informação
    // em todo scan sem contrato, então saiu da vitrine (decisão de Marlon,
    // 2026-09-02).
    if (Number.isInteger(score.coberturaMotores)) {
      linhas.push(lim(`COBERTURA DOS MOTORES · ${numSeguro(score.coberturaMotores)}%`));
      const semContrato = !Number.isInteger(score.coberturaContrato) || score.coberturaContrato === 0;
      linhas.push(lim(semContrato
        ? 'CONTEXTO DO CONTRATO  · 0% (sem contrato de publicação; forneça com --contract)'
        : `CONTEXTO DO CONTRATO  · ${numSeguro(score.coberturaContrato)}%`));
    } else {
      linhas.push(lim(`COBERTURA · ${numSeguro(score.cobertura)}%`));
    }
    const rotulo = publicar ? 'PUBLICAR' : (inconclusivo ? 'INCONCLUSIVO' : (invalido ? 'INVÁLIDO' : 'NÃO PUBLICAR'));
    const sufixo = inconclusivo
      ? ' (avaliação incompleta; não é reprovação do projeto)'
      : invalido
        ? ' (decisão desconhecida/incompatível — falha fechada)'
        : '';
    linhas.push(`DECISÃO · ${rotulo}${sufixo}`);
    linhas.push(lim(`RESUMO · ${mensagemDerivada(decisaoPublicacao, natureza, totalBloqueadores)}`));

    // Impedimentos/Bloqueadores: apenas contagens (números) + títulos fixos.
    const grupos = decisao.impedimentos;
    const gruposRelatorio = grupos && typeof grupos === 'object' ? [
      ['Reprovações comprovadas do projeto', grupos.reprovacoesProjeto],
      ['Evidências sob responsabilidade do cliente', grupos.semEvidenciaCliente],
      ['Fora da cobertura atual do ZUNVIO', grupos.foraCoberturaMotor],
      ['Falhas operacionais dos motores ZUNVIO', grupos.falhasMotor]
    ] : [];
    const temGrupos = gruposRelatorio.some(([, itens]) => Array.isArray(itens) && itens.length > 0);
    if (temGrupos) {
      linhas.push('  Impedimentos e limites por responsabilidade:');
      for (const [titulo, itens] of gruposRelatorio) {
        const n = Array.isArray(itens) ? itens.length : 0;
        if (n > 0) linhas.push(lim(`  ${titulo}: ${n}`));
      }
    } else if (totalBloqueadores > 0) {
      linhas.push(lim(`  Bloqueadores: ${totalBloqueadores}`));
    }

    // Próximas ações: derivadas de campos estruturados dos gates.
    linhas.push('  Próximas ações:');
    if (publicar) {
      linhas.push('    Nenhum bloqueador. Estado limpo: pronto para publicar conforme contrato e evidências.');
    } else {
      const portoesBloqueantes = (relatorio.avaliacao.portoes || []).filter(
        (p) => p && p.obrigatorio === true && (p.estado === 'NAO_ATENDE' || p.estado === 'NAO_COMPROVADO')
      );
      let temAcao = false;
      for (const portao of portoesBloqueantes) {
        const { causa, impacto, acao } = descreverAcao(portao);
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
        linhas.push('      Ação:    Forneça as dimensões faltantes do contrato e repita a análise.');
        temAcao = true;
      }
      if (!temAcao) {
        linhas.push('    Bloqueio sem causa estruturada; consulte o Evidence Pack para detalhes.');
      }
    }
    // badges: imprime apenas o tipo (enum validado), nunca o texto livre.
    if (Array.isArray(relatorio.badges) && relatorio.badges.length > 0) {
      const tipos = relatorio.badges
        .map((b) => (b && typeof b.tipo === 'string' && ENUM_BADGE.has(b.tipo) ? b.tipo : null))
        .filter(Boolean);
      if (tipos.length > 0) linhas.push(lim(`BADGES · ${tipos.join(' | ')}`));
    }
  }

  if (relatorio.claimEvidenceMap) {
    const mapa = relatorio.claimEvidenceMap;
    linhas.push('----------------------------------------------------------------');
    linhas.push(lim(`CLAIMS · ATENDE ${numSeguro(mapa.summary.atende)} | NÃO ATENDE ${numSeguro(mapa.summary.naoAtende)} | NÃO COMPROVADO ${numSeguro(mapa.summary.naoComprovado)} | CONTEXTO ${numSeguro(mapa.coverage)}%`));
    // B6: dimensões de claim são enums internos (12 canônicas) — qualquer outra é
    // omitida (não ecoada como texto externo).
    const dimensoesSeguras = (claims) => (Array.isArray(claims) ? claims : [])
      .filter((c) => c && typeof c.dimension === 'string' && DIMENSOES_VALIDAS.has(c.dimension))
      .map((c) => c.dimension);
    const divergencias = dimensoesSeguras(mapa.claims.filter((c) => c && c.divergence === true));
    if (divergencias.length > 0) linhas.push(lim(`DIVERGÊNCIAS · ${divergencias.join(', ')}`));
    const faltantes = dimensoesSeguras(mapa.claims.filter((c) => c && c.status === 'NAO_COMPROVADO')).slice(0, 3);
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

  const git = relatorio.scanners.gitleaks;
  const statusGit = git.status === 'SUCCESS' || (typeof git.status !== 'string' && git.disponivel)
    ? `OK (${numSeguro(git.totalAchados)} achados)`
    : git.status === 'UNAVAILABLE' || !git.disponivel
      ? 'INDISPONÍVEL'
      : `FALHOU [${enumSeguro(git.status, ENUM_STATUS)}]`;
  linhas.push(`  - GitLeaks:  ${statusGit}`);

  const sem = relatorio.scanners.semgrep;
  const statusSemgrep = sem.status === 'SUCCESS' || (typeof sem.status !== 'string' && sem.disponivel)
    ? `OK (${numSeguro(sem.totalAchados)} achados)`
    : sem.status === 'UNAVAILABLE' || !sem.disponivel
      ? 'INDISPONÍVEL'
      : `FALHOU [${enumSeguro(sem.status, ENUM_STATUS)}]`;
  linhas.push(`  - Semgrep:   ${statusSemgrep}`);

  linhas.push('----------------------------------------------------------------');
  linhas.push(lim(`Total de Achados: ${numSeguro(relatorio.totalAchados)}`));
  const rs = relatorio.resumoSeveridade || {};
  linhas.push(lim(`  CRITICAL: ${numSeguro(rs.CRITICAL)} | HIGH: ${numSeguro(rs.HIGH)} | MEDIUM: ${numSeguro(rs.MEDIUM)} | LOW: ${numSeguro(rs.LOW)} | INFO: ${numSeguro(rs.INFO)}`));

  if (Array.isArray(relatorio.achados) && relatorio.achados.length > 0) {
    linhas.push('----------------------------------------------------------------');
    linhas.push('Detalhamento dos Achados:');
    // O dono precisa AGIR sobre o achado: arquivo:linha e regra reais, com
    // controles/escapes neutralizados (B6). O valor do segredo em si nunca é
    // impresso em lugar nenhum. Na projeção --json tudo segue fingerprintado.
    for (const a of relatorio.achados) {
      const tagDelta = a.deltaInfo?.noDelta ? ' [NOVO NO DELTA]' : '';
      linhas.push(lim(`  [${enumSeguro(a.severity, ENUM_SEVERIDADE)}] ${textoLegivelSeguro(a.filePath, 160)}:${numSeguro(a.startLine)}${tagDelta}`));
      linhas.push(lim(`    Regra:    ${textoLegivelSeguro(a.ruleId, 120)}`));
      linhas.push(lim(`    Id:       ${achadoIdSeguro(a.id)}`));
    }
  }

  linhas.push('----------------------------------------------------------------');
  linhas.push('Comprovação de Imutabilidade (Zero Alterações no Host):');
  linhas.push(lim(`  Digest SHA-256: ${hexSeguro(relatorio.integridade.digestFinal)}`));
  linhas.push(`  Integridade:    ${relatorio.integridade.inalterado === true ? 'INALTERADO (100% Read-Only Comprovado)' : 'VIOLAÇÃO DE INTEGRIDADE DETECTADA'}`);
  if (relatorio.canonicalHash) {
    linhas.push(lim(`  Evidence Pack:  ${hexSeguro(relatorio.canonicalHash)}`));
  }
  linhas.push('================================================================');
  linhas.push('Relatório completo, histórico e acompanhamento: https://zunvio.com.br\n');

  return linhas.join('\n');
}

const ENUM_GATE_ID = new Set(Object.keys(NOMES_PORTAO));
const ENUM_GATE_ESTADO = new Set(['ATENDE', 'NAO_ATENDE', 'NAO_COMPROVADO', 'NAO_APLICAVEL']);
const ENUM_OUTCOME = new Set(['ACCEPT', 'REJECT', 'UNPROVEN']);
const ENUM_COMPLETUDE = new Set(['CLEAN', 'WITH_FINDINGS', 'NOT_STARTED', 'FAILED']);
const ENUM_SENSOR = new Set(['gitleaks', 'semgrep']);
const ENUM_CHECK = new Set(['gitleaks-secret-detection', 'semgrep-sast-detection', 'git-delta-blast-radius']);
const MAX_LINHA_JSON = 400;

/**
 * Texto real legível para o relatório humano local: neutraliza controles C0/C1
 * (incluindo ESC, a via de injeção de terminal do cenário B6) e limita o
 * tamanho. NÃO substitui o fingerprint da projeção --json; vale só para o que
 * o dono do projeto vê no próprio terminal.
 */
function textoLegivelSeguro(valor, max = 200) {
  const semControles = String(valor ?? '').replace(/[\u0000-\u001f\u007f-\u009f]/g, '\uFFFD');
  return semControles.length > max ? `${semControles.slice(0, max)}(...)` : semControles;
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

function projetarAchadoSeguro(achado = {}) {
  return {
    scanner: enumInterno(achado.scanner, ENUM_SENSOR, 'gitleaks'),
    ruleId: fingerprintSeguro(achado.ruleId),
    severity: enumInterno(achado.severity, ENUM_SEVERIDADE, 'INFO'),
    filePath: fingerprintSeguro(achado.filePath),
    startLine: inteiroNaoNegativo(achado.startLine),
    endLine: inteiroNaoNegativo(achado.endLine),
    message: fingerprintSeguro(achado.message)
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
    completion
  };
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
    totalAchados: canonico.findingsCount,
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
    scannersSummary: {
      gitleaks: projetarScannerCanonicoSeguro(originalCc.scannersSummary?.gitleaks, 'gitleaks', findings),
      semgrep: projetarScannerCanonicoSeguro(originalCc.scannersSummary?.semgrep, 'semgrep', findings)
    },
    findingsCount: findings.length,
    findings,
    exclusions: projetarColecaoLivre(originalCc.exclusions),
    limitations: projetarColecaoLivre(originalCc.limitations),
    decision,
    ...(mapa ? { claimEvidenceMap: mapa } : {})
  };
  const canonicalHash = calcularHashCanonico(canonicalContent);
  const integrityProof = {
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
      reprovacoesProjeto: projetarColecaoLivre(relatorio?.avaliacao?.decisao?.impedimentos?.reprovacoesProjeto),
      semEvidenciaCliente: projetarColecaoLivre(relatorio?.avaliacao?.decisao?.impedimentos?.semEvidenciaCliente),
      foraCoberturaMotor: projetarColecaoLivre(relatorio?.avaliacao?.decisao?.impedimentos?.foraCoberturaMotor),
      falhasMotor: projetarColecaoLivre(relatorio?.avaliacao?.decisao?.impedimentos?.falhasMotor)
    },
    bloqueadores: projetarColecaoLivre(relatorio?.avaliacao?.decisao?.bloqueadores)
  };
  return {
    versao: '0.2.0',
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
    coverageAndResidualRisk: {
      excludedPaths: projetarColecaoLivre(coverage.excludedPaths),
      unexecutedChecks: Array.isArray(coverage.unexecutedChecks)
        ? coverage.unexecutedChecks.map((check) => enumInterno(check, ENUM_CHECK, fingerprintSeguro(check)))
        : [],
      residualRiskStatement: fingerprintSeguro(coverage.residualRiskStatement)
    },
    badges: Array.isArray(relatorio?.badges)
      ? relatorio.badges.map((badge) => ({ tipo: enumInterno(badge?.tipo, ENUM_BADGE, 'ANALYZED') }))
      : [],
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
    scanners: { gitleaks: gitleaksPublico, semgrep: semgrepPublico },
    totalAchados: findings.length,
    resumoSeveridade: Object.fromEntries(
      [...ENUM_SEVERIDADE].map((sev) => [sev, inteiroNaoNegativo(relatorio?.resumoSeveridade?.[sev])])
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

export async function executarCli(args = [], io = {}, opcoesExtras = {}) {
  const stdout = io.stdout || ((msg) => process.stdout.write(msg));
  const stderr = io.stderr || ((msg) => process.stderr.write(msg));

  if (args[0] === 'verify') {
    return executarVerify(args, stdout);
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

  try {
    const relatorio = await executarAnaliseProjeto(parsed.target, {
      delta: {
        ativo: parsed.diff,
        baseRef: parsed.baseRef,
        headRef: parsed.headRef
      },
      caminhoContrato: parsed.caminhoContrato,
      caminhoEvidencias: parsed.caminhoEvidencias,
      ...opcoesExtras
    });

    if (parsed.json) {
      stdout(serializarJsonSeguro(projetarRelatorioJsonSeguro(relatorio)));
    } else {
      stdout(`${formatarRelatorioHumano(relatorio)}\n`);
    }

    // MASS-307: código de saída em TRÊS estados canônicos.
    //   0 = PUBLICAR (pronto);
    //   1 = NAO_PUBLICAR (bloqueador material comprovado);
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
