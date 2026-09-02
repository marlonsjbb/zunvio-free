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
