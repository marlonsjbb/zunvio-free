// E2E mínimo: o que sustenta a decisão sem ser prova do ZUNVIO — declarações do responsável (init) que atenderam um
// portão e revisões humanas aceitas. Lido do próprio Evidence Pack (evidência selada do portão e humanReviews), para
// que o terminal e o relatório HTML digam a mesma coisa ao lado da decisão, e não só no detalhe técnico.

const PREFIXO_DECLARACAO = 'Declaração do responsável (';
const PORTOES_DECLARAVEIS = Object.freeze({
  funcionamento: 'Funcionamento e testes',
  manutencao_documentacao: 'Manutenção e documentação'
});

function portoesDoPack(pack) {
  const candidatos = [pack?.avaliacao?.portoes, pack?.canonicalContent?.decision?.gates, pack?.decision?.gates];
  return candidatos.find((g) => Array.isArray(g)) || [];
}

function autorDaDeclaracao(texto) {
  const resto = texto.slice(PREFIXO_DECLARACAO.length);
  const fim = resto.indexOf('):');
  return fim > 0 ? resto.slice(0, fim) : null;
}

/**
 * @returns {{ declaracoes: Array<{ portao: string, autor: string|null }>, revisoesAceitas: number, autoresRevisao: string[] }}
 */
export function apoiosDaDecisao(pack) {
  const declaracoes = [];
  for (const gate of portoesDoPack(pack)) {
    const nome = PORTOES_DECLARAVEIS[gate?.id];
    if (!nome || gate.estado !== 'ATENDE') continue;
    const texto = (Array.isArray(gate.evidencias) ? gate.evidencias : []).find((e) => typeof e === 'string' && e.startsWith(PREFIXO_DECLARACAO));
    if (texto) declaracoes.push({ portao: nome, autor: autorDaDeclaracao(texto) });
  }
  const aceitas = (Array.isArray(pack?.canonicalContent?.humanReviews) ? pack.canonicalContent.humanReviews : [])
    .filter((r) => r?.estado === 'ACEITA');
  const autoresRevisao = [...new Set(aceitas.map((r) => r.autor).filter((a) => typeof a === 'string' && a.trim()))];
  return { declaracoes, revisoesAceitas: aceitas.length, autoresRevisao };
}

export const TITULO_APOIOS = 'Esta decisão também se apoia no que foi declarado ou revisado por pessoas — não é prova do ZUNVIO:';

/** Linhas em linguagem simples; `limpar` neutraliza o texto livre (autor) do jeito de cada saída. */
export function descreverApoios(apoios, limpar = (t) => t) {
  const nota = { 'Funcionamento e testes': 'o ZUNVIO não executa o projeto nem os testes', 'Manutenção e documentação': 'o ZUNVIO não avalia o conteúdo das instruções' };
  const linhas = apoios.declaracoes.map((d) => `${d.portao}: declarado por ${d.autor ? limpar(d.autor) : 'o responsável'} (${nota[d.portao]}).`);
  if (apoios.revisoesAceitas > 0) {
    const por = apoios.autoresRevisao.length > 0 ? ` por ${apoios.autoresRevisao.map((a) => limpar(a)).join(', ')}` : '';
    linhas.push(`${apoios.revisoesAceitas} item(ns) do código aceitos em revisão humana${por} (revisão registrada; não é prova de ausência de risco).`);
  }
  return linhas;
}
