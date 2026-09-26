/**
 * Utilitário de redação defensiva para mensagens, logs e evidências.
 * Impede que segredos detectados em código sejam vazados em claro nos relatórios.
 */

const PADROES_SEGREDO = [
  // Tokens GitHub / GitLab / Slack
  /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}/g,
  // GitHub fine-grained PAT (prefixo `github_pat_`) — B6
  /github_pat_[A-Za-z0-9_]{20,255}/g,
  // OpenAI / projeto (sk-proj- e sk- clássico) — B6
  /sk-proj-[A-Za-z0-9_\-]{20,255}/g,
  /sk-[A-Za-z0-9]{32,255}/g,
  /glpat-[A-Za-z0-9\-=_]{20,255}/g,
  /xox[baprs]-[A-Za-z0-9\-]{10,255}/g,
  // AWS Access Key ID e Secret
  /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/g,
  // Chaves Privadas (RSA, EC, OPENSSH)
  /-----BEGIN [A-Z ]+PRIVATE KEY-----[A-Za-z0-9+/=\s\r\n]+-----END [A-Z ]+PRIVATE KEY-----/g,
  // JWTs (Bearer / Basic)
  /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g,
  /Basic\s+[A-Za-z0-9+/=]{10,}/gi,
  /Bearer\s+[A-Za-z0-9._\-~+/=]{10,}/gi,
  // Pares chave=valor genéricos com cara de senha/token
  /(?:password|passwd|secret|api_key|apikey|token|auth_token)\s*[:=]\s*["']?([^"' \r\n]{6,})["']?/gi
];

/**
 * Redige strings contendo segredos conhecidos ou tokens sensíveis.
 * @param {string} texto - Texto bruto que pode conter segredos.
 * @param {string[]} [segredosAdicionais=[]] - Lista explícita de valores a redigir.
 * @returns {string} Texto redigido de forma segura.
 */
export function redigirTexto(texto, segredosAdicionais = []) {
  if (typeof texto !== 'string' || !texto) return '';

  let resultado = texto;

  // Redige valores explícitos conhecidos
  for (const segredo of segredosAdicionais) {
    if (typeof segredo === 'string' && segredo.length >= 4) {
      resultado = resultado.replaceAll(segredo, '[REDACTED]');
    }
  }

  // Redige padrões regex
  for (const padrao of PADROES_SEGREDO) {
    resultado = resultado.replace(padrao, (match) => {
      // Se for formato chave=valor, preserva a chave e redige o valor
      if (match.includes(':') || match.includes('=')) {
        const separador = match.includes(':') ? ':' : '=';
        const partes = match.split(separador);
        return `${partes[0]}${separador} [REDACTED]`;
      }
      return '[REDACTED]';
    });
  }

  return resultado;
}

// Conteúdo que nunca deve ser ecoado, nem redigido em parte — o valor inteiro
// é omitido, porque redação parcial de payload adversarial (HTML/injeção de
// prompt/execução) arrisca deixar um fragmento hostil sobrevivente. Cobre
// variantes com espaço, underscore ou hífen entre as palavras-chave (ex.:
// "ignore_previous_instructions" como identificador, não só como frase).
const CODEPONTO_NULO = String.fromCharCode(0);
const PADROES_HOSTIS = [
  /<\/?(?:script|iframe|object|embed|img|svg)\b/i,
  /\$\(/,
  /`/,
  /\$\{/,
  /(?:ignore|disregard|override)[\s_-]*(?:all[\s_-]*)?(?:previous|prior|system)[\s_-]*(?:instructions?|prompts?)/i,
  /(?:execute|run)[\s_-]*(?:this[\s_-]*)?(?:command|shell|code)/i,
  // PT-BR: mesmo vetor, ordem verbo+substantivo+modificador diferente do inglês
  // ("desconsidere as instruções anteriores", não "previous instructions").
  /(?:ignore|ignorar|desconsidere?|desconsiderar|despreze|desprezar|sobrescreva|sobrescrever)[\s_-]*(?:(?:todas?[\s_-]*)?(?:as|os)[\s_-]*)?(?:instru(?:[cç][aã]o|[cç][oõ]es)|prompts?|comandos?)[\s_-]*(?:anteriores?|pr[eé]vi[ao]s?|do[\s_-]*sistema)/i,
  /(?:execute|executar|rode|rodar)[\s_-]*(?:esse|este|essa|esta|[oa])?[\s_-]*(?:comando|shell|c[oó]digo)/i,
  new RegExp(CODEPONTO_NULO)
];

// C0/C1 (inclui ESC, vetor de injeção de terminal) + caracteres de controle
// bidirecional Unicode (RLO/LRO/PDF e isolates — vetor de disfarce de nome de
// arquivo/regra, ex. CVE-2021-42574 "Trojan Source"). Construído a partir de
// codepoints numéricos (nunca literais no fonte) para não introduzir no
// próprio arquivo os caracteres invisíveis que esta lista existe para
// neutralizar.
const FAIXAS_CONTROLE_E_BIDI = [
  [0x00, 0x1f], // C0
  [0x7f, 0x9f], // DEL + C1
  [0x200e, 0x200f], // LRM / RLM
  [0x202a, 0x202e], // LRE / RLE / PDF / LRO / RLO
  [0x2066, 0x2069] // LRI / RLI / FSI / PDI
];
const PADRAO_CONTROLE_E_BIDI = new RegExp(
  '[' + FAIXAS_CONTROLE_E_BIDI.map(([a, b]) => `\\u{${a.toString(16)}}-\\u{${b.toString(16)}}`).join('') + ']',
  'gu'
);
const SUBSTITUTO_CONTROLE = '�';

/**
 * Prepara texto de origem externa (caminho de arquivo, nome de regra, alvo
 * analisado) para exibição direta e legível num relatório — sem virar
 * fingerprint, mas sem permitir que segredo, controle de terminal, disfarce
 * bidirecional ou payload de injeção (HTML/prompt/shell) atravessem para a
 * tela. Payload hostil ou segredo detectado vira o texto inteiro omitido —
 * nunca uma redação parcial que poderia deixar um fragmento aproveitável.
 * @param {any} valor - Valor de origem externa/não confiável.
 * @param {number} [max=200] - Tamanho máximo do texto retornado.
 * @returns {string}
 */
export function textoSeguroParaExibicao(valor, max = 200) {
  const texto = String(valor ?? '');
  if (PADROES_HOSTIS.some((padrao) => padrao.test(texto))) return '[CONTEÚDO OMITIDO]';

  const redigido = redigirTexto(texto);
  if (redigido.includes('[REDACTED]')) return '[REDACTED]';

  const semControles = redigido.replace(PADRAO_CONTROLE_E_BIDI, SUBSTITUTO_CONTROLE);
  return semControles.length > max ? `${semControles.slice(0, max)}(...)` : semControles;
}

/**
 * Aplica redação defensiva recursiva em qualquer valor (objeto, array ou primitivo).
 * Garante que nenhum campo de saída escape à higienização de segredos.
 * @param {any} valor - Estrutura de dados a redigir.
 * @param {string[]} [segredosAdicionais=[]] - Lista explícita de valores a redigir.
 * @returns {any} Cópia higienizada com todas as strings redigidas.
 */
export function redigirObjeto(valor, segredosAdicionais = []) {
  if (valor === null || valor === undefined) return valor;

  if (typeof valor === 'string') {
    return redigirTexto(valor, segredosAdicionais);
  }

  if (Array.isArray(valor)) {
    return valor.map((item) => redigirObjeto(item, segredosAdicionais));
  }

  if (typeof valor === 'object') {
    const copia = {};
    for (const [chave, val] of Object.entries(valor)) {
      copia[chave] = redigirObjeto(val, segredosAdicionais);
    }
    return copia;
  }

  return valor;
}
