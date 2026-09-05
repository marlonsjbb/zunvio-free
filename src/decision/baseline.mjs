import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const NOME_ARQUIVO_BASELINE = '.zunvio-baseline.json';

function entradaValida(entrada) {
  return Boolean(
    entrada &&
    typeof entrada === 'object' &&
    typeof entrada.fingerprint === 'string' && entrada.fingerprint.trim().length > 0 &&
    typeof entrada.autor === 'string' && entrada.autor.trim().length > 0 &&
    typeof entrada.data === 'string' && entrada.data.trim().length > 0 &&
    typeof entrada.justificativa === 'string' && entrada.justificativa.trim().length >= 10
  );
}

/**
 * Lê `.zunvio-baseline.json` na raiz do alvo. Ausência de arquivo é neutra (nada
 * suprimido); schema ou entrada inválida descarta a baseline inteira (fail-closed),
 * nunca aplica parcialmente uma baseline malformada.
 * @param {string} raizAlvoAbsoluta
 * @returns {{ entradas: Map<string, { autor: string, data: string, justificativa: string }>, erro: string | null }}
 */
export function carregarBaseline(raizAlvoAbsoluta) {
  const caminho = join(raizAlvoAbsoluta, NOME_ARQUIVO_BASELINE);
  if (!existsSync(caminho)) return { entradas: new Map(), erro: null };

  let bruto;
  try {
    bruto = JSON.parse(readFileSync(caminho, 'utf8'));
  } catch (err) {
    return { entradas: new Map(), erro: `${NOME_ARQUIVO_BASELINE} não é um JSON válido: ${err.message}` };
  }

  const listaEntradas = Array.isArray(bruto?.entradas) ? bruto.entradas : null;
  if (!listaEntradas) {
    return { entradas: new Map(), erro: `${NOME_ARQUIVO_BASELINE} precisa de um campo "entradas" (lista).` };
  }

  const entradas = new Map();
  for (const [indice, entrada] of listaEntradas.entries()) {
    if (!entradaValida(entrada)) {
      return {
        entradas: new Map(),
        erro: `${NOME_ARQUIVO_BASELINE}: entrada ${indice} inválida — exige fingerprint, autor, data e justificativa (mínimo 10 caracteres).`
      };
    }
    entradas.set(entrada.fingerprint, {
      autor: entrada.autor,
      data: entrada.data,
      justificativa: entrada.justificativa
    });
  }

  return { entradas, erro: null };
}

/**
 * Separa achados cobertos pela baseline (suprimidos, com evidência original
 * preservada) dos que continuam bloqueando normalmente. Achado fora da baseline
 * NUNCA é suprimido, mesmo que a baseline exista e tenha outras entradas.
 * @param {object[]} achados
 * @param {{ entradas: Map<string, object> }} baseline
 * @returns {{ achadosRestantes: object[], suprimidos: Array<{ achado: object, autor: string, data: string, justificativa: string }> }}
 */
export function aplicarBaseline(achados, baseline) {
  const achadosRestantes = [];
  const suprimidos = [];
  for (const achado of achados) {
    const entrada = baseline.entradas.get(achado.fingerprint);
    if (entrada) {
      suprimidos.push({ achado, autor: entrada.autor, data: entrada.data, justificativa: entrada.justificativa });
    } else {
      achadosRestantes.push(achado);
    }
  }
  return Object.freeze({ achadosRestantes, suprimidos: Object.freeze(suprimidos) });
}
