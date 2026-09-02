import { createHash } from 'node:crypto';

/**
 * Normaliza um valor para formato canônico determinístico (RFC 8785 JCS simplificado).
 * - Objetos têm suas chaves ordenadas lexicograficamente.
 * - Valores `undefined` e funções são omitidos.
 * - Números e strings são formatados de maneira padrão.
 * @param {any} valor
 * @returns {any}
 */
export function normalizarParaCanonico(valor) {
  if (valor === null || typeof valor !== 'object') {
    return valor;
  }

  if (Array.isArray(valor)) {
    return valor.map(normalizarParaCanonico);
  }

  const objetoOrdenado = {};
  const chaves = Object.keys(valor).sort();

  for (const chave of chaves) {
    const val = valor[chave];
    if (val !== undefined && typeof val !== 'function') {
      objetoOrdenado[chave] = normalizarParaCanonico(val);
    }
  }

  return objetoOrdenado;
}

/**
 * Serializa um objeto em string JSON canônica determinística.
 * @param {any} objeto
 * @returns {string}
 */
export function serializarJsonCanonico(objeto) {
  const normalizado = normalizarParaCanonico(objeto);
  return JSON.stringify(normalizado);
}

/**
 * Calcula o hash SHA-256 determinístico de um objeto serializado canonicamente.
 * @param {any} objeto
 * @returns {string} Hash SHA-256 em hexadecimal.
 */
export function calcularHashCanonico(objeto) {
  const jsonCanonico = serializarJsonCanonico(objeto);
  return createHash('sha256').update(jsonCanonico, 'utf8').digest('hex');
}
