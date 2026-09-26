// E2E mínimo — REVISÃO HUMANA REGISTRÁVEL (decisão do fundador, 26/09/2026).
//
// Revisão humana é evidência ADICIONAL: não apaga o achado nem transforma incerteza em prova de segurança. Ela só
// vale para achados com significado REVISAO_NECESSARIA — nunca para RISCO_DEMONSTRADO — e fica presa a:
//   chaveRevisao    → identidade estável do achado SEM número de linha (regra, arquivo, texto normalizado do trecho e
//                     ordem entre trechos idênticos), para a revisão sobreviver a linhas inseridas acima;
//   contextoRevisao → hash do trecho e das 3 linhas vizinhas de cada lado. Mudou o contexto ⇒ a revisão fica
//                     OBSOLETA e o achado volta a bloquear até nova revisão.
// Estados de uma revisão registrada, calculados a cada análise:
//   ACEITA         → achado presente, REVISAO_NECESSARIA, mesmo contexto: deixa de bloquear (continua auditável);
//   OBSOLETA       → achado presente, contexto mudou: não vale (bloqueia);
//   NAO_APLICAVEL  → achado presente, mas não é REVISAO_NECESSARIA (ex.: virou RISCO_DEMONSTRADO): não vale;
//   SEM_ACHADO     → nenhum achado com essa chave nesta análise (corrigido ou movido): registrada, sem efeito.
import { createHash } from 'node:crypto';

export const VERSAO_MODELO_REVISAO = 'revisao-humana-1.0';
export const ESTADOS_REVISAO = Object.freeze({ ACEITA: 'ACEITA', OBSOLETA: 'OBSOLETA', NAO_APLICAVEL: 'NAO_APLICAVEL', SEM_ACHADO: 'SEM_ACHADO' });
const CLASSE_REVISAVEL = 'REVISAO_NECESSARIA';
const JANELA_CONTEXTO = 3;
const hash16 = (s) => createHash('sha256').update(s).digest('hex').slice(0, 16);
const normalizar = (s) => String(s ?? '').replace(/\s+/g, ' ').trim();

/**
 * Calcula chaveRevisao e contextoRevisao para uma lista de achados de um mesmo sensor, a partir do conteúdo dos
 * arquivos. Trechos idênticos (mesma regra, arquivo e texto) recebem ordem crescente pela linha.
 * @param {Array<object>} achados - achados normalizados (com scanner, ruleId, filePath, startLine, endLine)
 * @param {(filePath: string) => string|null} lerCodigo
 * @returns {Map<object, { chaveRevisao: string, contextoRevisao: string }>} só para achados com código legível
 */
export function calcularIdentidadesDeRevisao(achados, lerCodigo) {
  const saida = new Map();
  const bases = [];
  for (const a of achados) {
    const codigo = lerCodigo(a.filePath);
    if (typeof codigo !== 'string') continue;
    const linhas = codigo.split(/\r?\n/);
    const trecho = linhas.slice(a.startLine - 1, a.endLine).map(normalizar).join('\n');
    const vizinhanca = linhas.slice(Math.max(0, a.startLine - 1 - JANELA_CONTEXTO), a.endLine + JANELA_CONTEXTO).map(normalizar).join('\n');
    bases.push({ a, base: `${a.scanner}:${a.ruleId}:${a.filePath}:${trecho}`, vizinhanca });
  }
  const porId = (x, y) => (String(x.a.id ?? '') < String(y.a.id ?? '') ? -1 : String(x.a.id ?? '') > String(y.a.id ?? '') ? 1 : 0);
  bases.sort((x, y) => (x.base < y.base ? -1 : x.base > y.base ? 1 : (x.a.startLine - y.a.startLine) || porId(x, y)));
  const ordem = new Map();
  for (const { a, base, vizinhanca } of bases) {
    const n = ordem.get(base) ?? 0;
    ordem.set(base, n + 1);
    saida.set(a, { chaveRevisao: hash16(`${base}:${n}`), contextoRevisao: hash16(vizinhanca) });
  }
  return saida;
}

const texto = (v, min = 1) => typeof v === 'string' && v.trim().length >= min;

/** Entrada de revisão no `.zunvio-baseline.json` (tipo "revisao"). */
export function entradaDeRevisaoValida(e) {
  return Boolean(e && typeof e === 'object' && e.tipo === 'revisao'
    && /^[0-9a-f]{16}$/.test(e.chaveRevisao ?? '') && /^[0-9a-f]{16}$/.test(e.contextoRevisao ?? '')
    && e.classificacaoOriginal === CLASSE_REVISAVEL
    && texto(e.autor) && texto(e.data) && texto(e.justificativa, 10));
}

/**
 * Aplica as revisões registradas aos achados desta análise. Não altera o achado: devolve o estado de cada revisão e,
 * para cada achado com revisão ACEITA, a revisão que o sustenta.
 * @param {Array<object>} achados - achados com chaveRevisao/contextoRevisao/significado
 * @param {Array<object>} revisoes - entradas de revisão válidas
 * @returns {{ revisoes: Array<object>, aceitaPorAchado: Map<object, object> }}
 */
export function aplicarRevisoesHumanas(achados, revisoes) {
  const porChave = new Map(achados.filter((a) => a.chaveRevisao).map((a) => [a.chaveRevisao, a]));
  const aceitaPorAchado = new Map();
  const resultado = revisoes.map((r) => {
    const a = porChave.get(r.chaveRevisao);
    let estado;
    if (!a) estado = ESTADOS_REVISAO.SEM_ACHADO;
    else if (a.significado?.classe !== CLASSE_REVISAVEL) estado = ESTADOS_REVISAO.NAO_APLICAVEL;
    else if (a.contextoRevisao !== r.contextoRevisao) estado = ESTADOS_REVISAO.OBSOLETA;
    else estado = ESTADOS_REVISAO.ACEITA;
    const registro = Object.freeze({
      modelo: VERSAO_MODELO_REVISAO,
      chaveRevisao: r.chaveRevisao,
      contextoRevisao: r.contextoRevisao,
      classificacaoOriginal: r.classificacaoOriginal,
      ...(r.regra ? { regra: String(r.regra).slice(0, 120) } : {}),
      ...(r.arquivo ? { arquivo: String(r.arquivo).slice(0, 300) } : {}),
      autor: String(r.autor).slice(0, 120),
      data: String(r.data).slice(0, 40),
      justificativa: String(r.justificativa).slice(0, 1000),
      estado,
      ...(a ? { findingId: a.id, classificacaoAtual: a.significado?.classe ?? null, contextoAtual: a.contextoRevisao ?? null } : {})
    });
    if (estado === ESTADOS_REVISAO.ACEITA) aceitaPorAchado.set(a, registro);
    return registro;
  });
  return { revisoes: resultado, aceitaPorAchado };
}

/**
 * Coerência de uma revisão SELADA num achado canônico (validador e verificador): só pode deixar de bloquear um achado
 * REVISAO_NECESSARIA, com chave e contexto iguais aos do achado e os campos mínimos presentes.
 * @returns {string[]} problemas
 */
export function problemasDaRevisaoSelada(achadoCanonico) {
  const r = achadoCanonico?.revisaoHumana;
  if (r === undefined) return [];
  const p = [];
  if (!r || typeof r !== 'object') return ['revisaoHumana não é objeto'];
  if (r.estado !== ESTADOS_REVISAO.ACEITA) p.push('revisaoHumana selada no achado precisa estar ACEITA');
  if (achadoCanonico.significado?.classe !== CLASSE_REVISAVEL) p.push('revisaoHumana só vale para achado REVISAO_NECESSARIA (nunca RISCO_DEMONSTRADO)');
  if (r.classificacaoOriginal !== CLASSE_REVISAVEL) p.push('revisaoHumana.classificacaoOriginal precisa ser REVISAO_NECESSARIA');
  if (!/^[0-9a-f]{16}$/.test(achadoCanonico.chaveRevisao ?? '') || r.chaveRevisao !== achadoCanonico.chaveRevisao) p.push('revisaoHumana.chaveRevisao diverge da chave do achado');
  if (!/^[0-9a-f]{16}$/.test(achadoCanonico.contextoRevisao ?? '') || r.contextoRevisao !== achadoCanonico.contextoRevisao) p.push('revisaoHumana.contextoRevisao diverge do contexto do achado (revisão obsoleta)');
  if (!texto(r.autor) || !texto(r.data) || !texto(r.justificativa, 10)) p.push('revisaoHumana sem autor, data ou justificativa (mínimo 10 caracteres)');
  return p;
}
