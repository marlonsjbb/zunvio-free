// E2E mínimo do vibe coder (decisões do fundador, 26/09/2026): o que a CLI precisa, além da análise, para um usuário
// externo completar o ciclo sem conhecimento interno:
//   - pasta do projeto FORA do repositório analisado (~/.zunvio/projetos/<id>): declaração do `init`, última análise
//     (para a evolução) e relatórios HTML. O repositório só recebe o que é do projeto: `.zunvio-baseline.json`.
//   - `init`: perguntas em linguagem humana que produzem o contrato de publicação e a evidência declarada;
//   - `revisar`: registra uma revisão humana de um achado REVISAO_NECESSARIA (nunca RISCO_DEMONSTRADO);
//   - evolução: comparação com a análise anterior (achados novos/resolvidos/persistentes, pontuação, decisão, revisões).
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { homedir, userInfo } from 'node:os';
import { join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { execFileSync } from 'node:child_process';

export const NOME_BASELINE = '.zunvio-baseline.json';
const hash16 = (s) => createHash('sha256').update(s).digest('hex').slice(0, 16);

/** Pasta de dados da ferramenta (fora de qualquer projeto). ZUNVIO_HOME permite isolar (testes, perfis). */
export function diretorioDados() {
  return process.env.ZUNVIO_HOME ? resolve(process.env.ZUNVIO_HOME) : join(homedir(), '.zunvio');
}

/** Pasta do projeto analisado dentro da pasta de dados; o id é derivado do caminho real do projeto. */
export function diretorioDoProjeto(alvo) {
  let real = resolve(alvo);
  try { real = realpathSync(real); } catch {}
  const id = hash16(real.replace(/\\/g, '/').toLowerCase());
  return { id, caminho: join(diretorioDados(), 'projetos', id), raiz: real };
}

const lerJson = (f) => { try { return JSON.parse(readFileSync(f, 'utf8')); } catch { return null; } };
const gravarJson = (f, v) => writeFileSync(f, `${JSON.stringify(v, null, 2)}\n`);

/**
 * Caminhos do contexto declarado pelo `init` (contrato e evidência), quando existem. A declaração do `init` descreve o
 * projeto, não um commit: a cada análise ela é vinculada ao commit analisado (`vinculoRelease`) numa cópia na pasta
 * do projeto — o mesmo vínculo que o motor já faz quando não há contrato.
 */
export function contextoDeclarado(alvo) {
  const { caminho } = diretorioDoProjeto(alvo);
  const origem = join(caminho, 'contrato.json');
  const evidencias = join(caminho, 'evidencias.json');
  let contrato = null;
  const declarado = existsSync(origem) ? lerJson(origem) : null;
  if (declarado && declarado.dimensoes && typeof declarado.dimensoes === 'object') {
    let head = null;
    try { head = execFileSync('git', ['-C', alvo, 'rev-parse', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 15000 }).trim(); } catch {}
    if (/^[0-9a-f]{40}$/.test(head ?? '') && !declarado.dimensoes.vinculoRelease) {
      contrato = join(caminho, 'contrato-vinculado.json');
      gravarJson(contrato, { ...declarado, dimensoes: { ...declarado.dimensoes, vinculoRelease: head } });
    } else {
      contrato = origem;
    }
  }
  return { contrato, evidencias: existsSync(evidencias) ? evidencias : null };
}

// ---- Evolução entre análises ------------------------------------------------------------------------------------
const chaveEvolucao = (a) => (a.chaveRevisao ? `${a.scanner}:${a.chaveRevisao}` : `${a.scanner}:${a.id}`);

/** Resumo mínimo de uma análise para comparar com a próxima (sem conteúdo de código nem segredos). */
export function resumoParaHistorico(relatorio) {
  const achados = Array.isArray(relatorio.achados) ? relatorio.achados : [];
  return {
    versaoResumo: 1,
    quando: relatorio.timestamp ?? new Date().toISOString(),
    commit: relatorio.canonicalContent?.integrity?.releaseCommit ?? null,
    decisao: relatorio.avaliacao?.decisao?.decisaoPublicacao ?? null,
    pontuacao: Number.isInteger(relatorio.decision?.score) ? relatorio.decision.score : null,
    hash: relatorio.canonicalHash ?? null,
    achados: achados.map((a) => ({
      chave: chaveEvolucao(a),
      id: a.id,
      regra: a.ruleId,
      arquivo: a.filePath,
      linha: a.startLine,
      classe: a.significado?.classe ?? null,
      revisao: a.revisaoHumana?.estado ?? null
    })),
    revisoes: (relatorio.canonicalContent?.humanReviews || []).map((r) => ({ chave: r.chaveRevisao, estado: r.estado }))
  };
}

/** Compara a análise atual com a anterior. */
export function compararAnalises(anterior, atual) {
  const ant = new Map((anterior?.achados || []).map((a) => [a.chave, a]));
  const agr = new Map((atual.achados || []).map((a) => [a.chave, a]));
  const novos = [...agr.values()].filter((a) => !ant.has(a.chave));
  const resolvidos = [...ant.values()].filter((a) => !agr.has(a.chave));
  const persistentes = [...agr.values()].filter((a) => ant.has(a.chave));
  const estadoRev = (lista) => new Map((lista || []).map((r) => [r.chave, r.estado]));
  const rAnt = estadoRev(anterior?.revisoes);
  const rAgr = estadoRev(atual.revisoes);
  const revisoesPreservadas = [...rAgr].filter(([k, e]) => e === 'ACEITA' && rAnt.get(k) === 'ACEITA').length;
  const revisoesNovas = [...rAgr].filter(([k, e]) => e === 'ACEITA' && rAnt.get(k) !== 'ACEITA').length;
  const revisoesInvalidadas = [...rAgr].filter(([k, e]) => e !== 'ACEITA' && e !== 'SEM_ACHADO' && rAnt.get(k) === 'ACEITA').length;
  return {
    desde: anterior?.quando ?? null,
    novos, resolvidos, persistentes,
    pontuacao: { antes: anterior?.pontuacao ?? null, agora: atual.pontuacao },
    decisao: { antes: anterior?.decisao ?? null, agora: atual.decisao },
    revisoes: { preservadas: revisoesPreservadas, novas: revisoesNovas, invalidadas: revisoesInvalidadas }
  };
}

const ROTULO_DECISAO = { PUBLICAR: 'PUBLICAR', NAO_PUBLICAR: 'NÃO PUBLICAR', INCONCLUSIVO: 'INCONCLUSIVO' };

/** Texto da evolução para o terminal. */
export function formatarEvolucao(c, limpar = (s) => s) {
  const linhas = ['----------------------------------------------------------------', `Evolução desde a análise anterior (${limpar(String(c.desde ?? '?').slice(0, 16).replace('T', ' '))}):`];
  const dp = c.pontuacao.antes === null ? `${c.pontuacao.agora}` : `${c.pontuacao.antes} → ${c.pontuacao.agora}`;
  const dd = c.decisao.antes === null ? ROTULO_DECISAO[c.decisao.agora] : `${ROTULO_DECISAO[c.decisao.antes] ?? '?'} → ${ROTULO_DECISAO[c.decisao.agora] ?? '?'}`;
  linhas.push(`  Pontuação ZUNVIO: ${dp}   ·   Decisão: ${dd}`);
  linhas.push(`  Achados: ${c.resolvidos.length} resolvido(s) · ${c.novos.length} novo(s) · ${c.persistentes.length} persistente(s)`);
  for (const a of c.resolvidos.slice(0, 5)) linhas.push(limpar(`    resolvido: ${a.arquivo}:${a.linha} (${a.regra})`));
  for (const a of c.novos.slice(0, 5)) linhas.push(limpar(`    novo:      ${a.arquivo}:${a.linha} (${a.regra})`));
  const r = c.revisoes;
  if (r.preservadas + r.novas + r.invalidadas > 0) {
    linhas.push(`  Revisões humanas: ${r.novas} nova(s) aceita(s) · ${r.preservadas} preservada(s) · ${r.invalidadas} invalidada(s) (o código mudou ou virou risco demonstrado)`);
  }
  return linhas.join('\n');
}

/** Lê a análise anterior, grava a atual e devolve a comparação (null na primeira análise). */
export function registrarEvolucao(alvo, relatorio) {
  const { caminho } = diretorioDoProjeto(alvo);
  mkdirSync(caminho, { recursive: true });
  const arquivo = join(caminho, 'ultima-analise.json');
  const anterior = lerJson(arquivo);
  const atual = resumoParaHistorico(relatorio);
  gravarJson(arquivo, atual);
  return anterior ? compararAnalises(anterior, atual) : null;
}

// ---- Relatório HTML local ---------------------------------------------------------------------------------------
/** Grava o relatório HTML (representação do Evidence Pack) fora do projeto; devolve o caminho. */
export function gravarRelatorio(alvo, html, destino = null) {
  let arquivo = destino ? resolve(destino) : null;
  if (!arquivo) {
    const { caminho } = diretorioDoProjeto(alvo);
    const pasta = join(caminho, 'relatorios');
    mkdirSync(pasta, { recursive: true });
    arquivo = join(pasta, `relatorio-${new Date().toISOString().replace(/[:.]/g, '-')}-${process.pid}.html`);
  }
  writeFileSync(arquivo, html);
  return arquivo;
}

// ---- Perguntas (init / revisar) -----------------------------------------------------------------------------------
function perguntador(io) {
  if (io.perguntar) return io.perguntar;
  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: Boolean(process.stdin.isTTY) });
  const fila = [];
  let esperando = null;
  let fim = false;
  rl.on('line', (l) => { if (esperando) { const r = esperando; esperando = null; r(l); } else fila.push(l); });
  rl.on('close', () => { fim = true; if (esperando) { const r = esperando; esperando = null; r(''); } });
  const fn = (texto) => new Promise((ok) => {
    process.stdout.write(texto);
    if (fila.length) ok(fila.shift());
    else if (fim) ok('');
    else esperando = ok;
  });
  fn.fechar = () => rl.close();
  return fn;
}

const PERGUNTAS_INIT = [
  ['objetivoProduto', 'O que o seu projeto faz, em uma frase?', 'Ajuda a julgar o que é risco para ESTE produto.'],
  ['publicoUsuarios', 'Quem usa? (ex.: clientes finais, sua equipe, visitantes de um site)', 'Define quem seria afetado por uma falha.'],
  ['jornadasCriticas', 'Quais são as ações que não podem falhar? (ex.: login, pagamento, envio de formulário)', 'São as partes que você precisa ter testado.'],
  ['ambientePublicacao', 'Onde o projeto vai rodar? (ex.: Vercel, Lovable, Supabase, servidor próprio)', 'Muda quais riscos importam.'],
  ['integracoesIndispensaveis', 'De quais serviços externos ele depende? (ex.: Supabase, Stripe, OpenAI)', 'Integrações costumam guardar chaves e dados.'],
  ['dadosTratados', 'Que dados ele guarda ou recebe? (ex.: e-mail, dados de pagamento, mensagens)', 'Dados pessoais exigem mais cuidado.'],
  ['requisitosSegurancaPrivacidade', 'Como você protege esses dados? (ex.: login, regras de acesso no banco)', 'Registra o que você já cuidou.'],
  ['capacidadeDesempenho', 'Quanto uso você espera no começo? (ex.: dezenas de pessoas por dia)', 'Contexto de escala; não é medido pelo ZUNVIO.'],
  ['requisitosLegaisRegulatorios', 'Alguma lei ou regra se aplica? (ex.: LGPD; responda "nenhuma" se não souber de nenhuma)', 'Contexto legal declarado por você.'],
  ['operacaoRollback', 'Se a versão publicada der problema, como você volta atrás?', 'Ter um caminho de volta reduz o risco de publicar.'],
  ['criteriosInaceitaveis', 'O que NUNCA pode acontecer? (ex.: vazar dados de um cliente para outro)', 'Vira critério de bloqueio declarado.']
];

/**
 * `init`: descreve o projeto e declara como ele foi testado. Grava FORA do repositório (pasta do projeto no ZUNVIO):
 * a declaração é do responsável; o ZUNVIO não executa testes e o relatório mostra que é uma declaração.
 */
export async function executarInit(args, io = {}) {
  const out = io.stdout || ((m) => process.stdout.write(m));
  const alvo = args.find((a, i) => i > 0 && !a.startsWith('-')) || '.';
  const { caminho, raiz } = diretorioDoProjeto(alvo);
  const perguntar = perguntador(io);
  try {
    out('\nZUNVIO — descrever o projeto antes de publicar\n');
    out(`Projeto: ${raiz}\n\n`);
    out('Você vai responder algumas perguntas curtas. As respostas são uma DECLARAÇÃO sua: o ZUNVIO não executa\n');
    out('o seu projeto nem os seus testes. Elas ficam guardadas fora do repositório, entram no relatório como\n');
    out('"declarado pelo responsável" e permitem avaliar os portões de contexto e de funcionamento.\n\n');
    const dimensoes = {};
    for (const [campo, pergunta, porque] of PERGUNTAS_INIT) {
      out(`${pergunta}\n  (${porque})\n`);
      let r = String(await perguntar('> ')).trim();
      if (!r) r = 'Não informado pelo responsável.';
      dimensoes[campo] = r.slice(0, 500);
      out('\n');
    }
    out('Agora, sobre testes. O ZUNVIO só registra o que você declarar aqui.\n');
    const testou = String(await perguntar('Você testou as ações que não podem falhar nesta versão? (s/n) > ')).trim().toLowerCase().startsWith('s');
    let comoTestou = '';
    if (testou) comoTestou = String(await perguntar('Como testou? (ex.: "testei no preview login, pagamento e formulário"; "npm test: 12 passaram") > ')).trim();
    const temDoc = String(await perguntar('O projeto tem instruções de uso/manutenção (ex.: README)? (s/n) > ')).trim().toLowerCase().startsWith('s');
    const autor = (String(await perguntar('Seu nome (fica registrado como responsável pela declaração) > ')).replace(/\s+/g, ' ').trim() || autorPadrao()).slice(0, 120);

    mkdirSync(caminho, { recursive: true });
    gravarJson(join(caminho, 'contrato.json'), {
      versaoContrato: '1.0.0',
      id: `projeto-${diretorioDoProjeto(alvo).id}`,
      cliente: autor,
      perfil: 'declarado-no-init',
      dimensoes
    });
    gravarJson(join(caminho, 'evidencias.json'), {
      declaradoPor: autor,
      declaradoEm: new Date().toISOString(),
      funcionamento: {
        disponivel: testou,
        aprovado: testou,
        descricao: testou ? `Declaração do responsável (${autor}): ${comoTestou || 'testou as ações críticas'}.` : 'O responsável declarou que não testou as ações críticas.'
      },
      manutencaoDocumentacao: {
        disponivel: temDoc,
        aprovado: temDoc,
        descricao: temDoc ? `Declaração do responsável (${autor}): instruções de uso/manutenção presentes.` : 'O responsável declarou que não há instruções de uso/manutenção.'
      }
    });
    out('\nPronto. O que você declarou:\n');
    out(`  - descrição do projeto (${PERGUNTAS_INIT.length} respostas);\n`);
    out(`  - testes das ações críticas: ${testou ? 'declarados como feitos' : 'NÃO feitos — o portão de funcionamento não será atendido'};\n`);
    out(`  - instruções de uso/manutenção: ${temDoc ? 'declaradas' : 'não declaradas'}.\n`);
    out('O que ainda precisa ser comprovado pela análise: segredos, segurança do código, integridade e o vínculo com a versão.\n');
    out(`Guardado em: ${caminho}\n`);
    out('Próximo passo: npx zunvio-score\n\n');
    return 0;
  } finally {
    perguntar.fechar?.();
  }
}

function autorPadrao() {
  try { return execFileSync('git', ['config', 'user.name'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim() || userInfo().username; } catch {}
  try { return userInfo().username; } catch { return 'responsável'; }
}

function valorDeOpcao(args, nome) {
  const i = args.indexOf(nome);
  return i >= 0 && i + 1 < args.length ? args[i + 1] : null;
}

/**
 * `revisar <chave> [--justificativa "..."] [--autor "..."] [pasta]`: registra no `.zunvio-baseline.json` do projeto uma
 * revisão humana de um achado REVISAO_NECESSARIA da última análise. Nunca para RISCO_DEMONSTRADO.
 */
export async function executarRevisar(args, io = {}) {
  const out = io.stdout || ((m) => process.stdout.write(m));
  const err = io.stderr || ((m) => process.stderr.write(m));
  const chave = args[1];
  const posicionais = args.slice(2).filter((a, i, arr) => !a.startsWith('-') && !['--justificativa', '--autor'].includes(arr[i - 1]));
  const alvo = posicionais[0] || '.';
  if (!/^[0-9a-f]{16}$/.test(chave || '')) {
    err('Uso: npx zunvio-score revisar <chave> [--justificativa "..."] [pasta]\n  A chave aparece na análise, no item "Revisou e não é risco neste contexto?".\n');
    return 3;
  }
  const { caminho, raiz } = diretorioDoProjeto(alvo);
  const ultima = lerJson(join(caminho, 'ultima-analise-detalhe.json'));
  const achado = (ultima?.revisaveis || []).find((a) => a.chaveRevisao === chave);
  if (!achado) {
    err('Esta chave não está entre os itens que pedem revisão na última análise deste projeto. Rode "npx zunvio-score" e use a chave indicada no item.\n');
    return 3;
  }
  const perguntar = perguntador(io);
  try {
    let justificativa = valorDeOpcao(args, '--justificativa');
    if (!justificativa) {
      out(`\nItem: ${achado.arquivo}:${achado.linha} (${achado.regra})\n${achado.explicacao}\n\n`);
      out('Por que este trecho não é risco neste contexto? (mínimo 10 caracteres; fica registrado com o seu nome)\n');
      justificativa = String(await perguntar('> ')).trim();
    }
    if (!justificativa || justificativa.trim().length < 10) {
      err('Revisão não registrada: a justificativa precisa ter pelo menos 10 caracteres.\n');
      return 3;
    }
    const autor = valorDeOpcao(args, '--autor') || autorPadrao();
    const arquivoBaseline = join(raiz, NOME_BASELINE);
    const atual = existsSync(arquivoBaseline) ? lerJson(arquivoBaseline) : { entradas: [] };
    if (!atual || !Array.isArray(atual.entradas)) {
      err(`${NOME_BASELINE} existe mas não é válido; corrija-o antes de registrar revisões.\n`);
      return 3;
    }
    const entrada = {
      tipo: 'revisao',
      chaveRevisao: chave,
      contextoRevisao: achado.contextoRevisao,
      classificacaoOriginal: 'REVISAO_NECESSARIA',
      regra: achado.regra,
      arquivo: achado.arquivo,
      autor: String(autor).replace(/\s+/g, ' ').trim().slice(0, 120),
      data: new Date().toISOString().slice(0, 10),
      justificativa: justificativa.replace(/\s+/g, ' ').trim().slice(0, 1000)
    };
    atual.entradas = [...atual.entradas.filter((e) => !(e?.tipo === 'revisao' && e.chaveRevisao === chave)), entrada];
    gravarJson(arquivoBaseline, atual);
    out(`\nRevisão registrada em ${NOME_BASELINE} (arquivo do projeto; versione junto com o código).\n`);
    out('Ela vale enquanto este trecho e as linhas em volta não mudarem. Se mudarem, o item volta a pedir revisão.\n');
    out('Revisão humana não é prova de ausência de risco: o item continua no relatório, marcado como revisado por você.\n');
    out('Próximo passo: npx zunvio-score\n\n');
    return 0;
  } finally {
    perguntar.fechar?.();
  }
}

/** Guarda os itens revisáveis da última análise (para o `revisar` validar a chave e o contexto). */
export function registrarRevisaveis(alvo, relatorio) {
  const { caminho } = diretorioDoProjeto(alvo);
  mkdirSync(caminho, { recursive: true });
  const revisaveis = (relatorio.achados || [])
    .filter((a) => a.significado?.classe === 'REVISAO_NECESSARIA' && /^[0-9a-f]{16}$/.test(a.chaveRevisao ?? ''))
    .map((a) => ({ chaveRevisao: a.chaveRevisao, contextoRevisao: a.contextoRevisao, regra: a.ruleId, arquivo: a.filePath, linha: a.startLine, explicacao: a.significado?.explicacao ?? '' }));
  gravarJson(join(caminho, 'ultima-analise-detalhe.json'), { quando: new Date().toISOString(), revisaveis });
}
