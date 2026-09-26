import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { calcularDigestCanonico } from '../models/sensor-identity.mjs';

// RF-08 camada 3 (MASS-399): detector de comentário perigoso (ex: `// TODO:
// bypass`). Informativo por decisão explícita — não é sensor canônico, não
// entra em SENSORES_CANONICOS/GATES_CANONICOS nem no fluxo de verify. Ver
// docs/checkpoints/MASS-399-preflight-rf08-09-11.md para o porquê.
//
// Regex, não semgrep: comentário é texto solto por natureza (não é sempre um
// nó de AST navegável de forma uniforme entre linguagens), e o objetivo aqui
// é detecção textual determinística, não análise de sintaxe.

export const ID_SENSOR = 'comentarios-perigosos';
export const VERSAO_REGRAS = '1.0.0';

// Extensões varridas: código-fonte comum onde comentário de desenvolvedor
// aparece. Não inclui binários, imagens, lockfiles (ruído garantido).
const EXTENSOES_VARRIDAS = new Set([
  '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx',
  '.py', '.rb', '.go', '.java', '.kt', '.php', '.c', '.cc', '.cpp', '.h', '.hpp',
  '.cs', '.rs', '.sh', '.yml', '.yaml'
]);

const REGRAS = Object.freeze([
  Object.freeze({
    id: 'zunvio-comment.bypass-marker',
    severity: 'HIGH',
    regex: /\b(TODO|FIXME|XXX|HACK)\b[^\n]{0,60}\bbypass\b/i,
    message: 'Comentário indica desvio deliberado de um controle (bypass) deixado no código.'
  }),
  Object.freeze({
    id: 'zunvio-comment.disable-security-control',
    severity: 'HIGH',
    regex: /\b(disable|desabilita|desativa)\w*[^\n]{0,40}\b(auth|autentica|security|seguranc|validat|valida|csrf|cors)\w*/i,
    message: 'Comentário indica desativação deliberada de um controle de segurança.'
  }),
  Object.freeze({
    id: 'zunvio-comment.skip-check',
    severity: 'MEDIUM',
    regex: /\b(skip|pula|ignora)\w*[^\n]{0,40}\b(auth|check|valida|security|seguranc|test|teste)\w*/i,
    message: 'Comentário indica que uma verificação foi deliberadamente pulada.'
  }),
  Object.freeze({
    id: 'zunvio-comment.backdoor-marker',
    severity: 'CRITICAL',
    regex: /\bbackdoor\b/i,
    message: 'Comentário menciona explicitamente um backdoor.'
  }),
  Object.freeze({
    id: 'zunvio-comment.hardcoded-secret-marker',
    severity: 'MEDIUM',
    regex: /\b(TODO|FIXME|XXX|HACK)\b[^\n]{0,60}\b(hardcoded|hard-coded|senha fixa|chave fixa)\b/i,
    message: 'Comentário reconhece um segredo/credencial fixado no código, pendente de remoção.'
  }),
  Object.freeze({
    id: 'zunvio-comment.insecure-acknowledged',
    severity: 'MEDIUM',
    regex: /\b(FIXME|XXX)\b[^\n]{0,60}\b(insecure|inseguro|vulnerav|vulneráv|vuln\b)/i,
    message: 'Comentário reconhece uma condição insegura ainda não corrigida.'
  })
]);

function extensao(caminho) {
  const m = /\.[^./\\]+$/.exec(caminho);
  return m ? m[0].toLowerCase() : '';
}

function ehLinhaDeComentario(linha) {
  const semEspacos = linha.trimStart();
  return semEspacos.startsWith('//')
    || semEspacos.startsWith('#')
    || semEspacos.startsWith('*')
    || semEspacos.startsWith('/*')
    || semEspacos.startsWith('--');
}

/**
 * Varre um inventário já materializado (mesmo padrão de gitleaks/semgrep: lê
 * a cópia read-only, nunca o alvo original) em busca de comentários que
 * reconhecem um desvio de segurança deliberado.
 *
 * @param {{ raiz: string, arquivosRelativos: string[] }} inventario
 * @returns {{ status: 'SUCCESS', achados: Array, duracaoMs: number, identidade: object }}
 */
export function executarScannerComentariosPerigosos(inventario) {
  const inicio = Date.now();
  const achados = [];

  for (const caminhoRelativo of inventario.arquivosRelativos) {
    if (!EXTENSOES_VARRIDAS.has(extensao(caminhoRelativo))) continue;

    let conteudo;
    try {
      conteudo = readFileSync(join(inventario.raiz, caminhoRelativo), 'utf8');
    } catch {
      continue;
    }

    const linhas = conteudo.split(/\r?\n/);
    for (let i = 0; i < linhas.length; i++) {
      const linha = linhas[i];
      if (!ehLinhaDeComentario(linha)) continue;

      for (const regra of REGRAS) {
        if (regra.regex.test(linha)) {
          achados.push({
            scanner: ID_SENSOR,
            ruleId: regra.id,
            severity: regra.severity,
            filePath: caminhoRelativo,
            startLine: i + 1,
            endLine: i + 1,
            message: regra.message
          });
          // Uma linha pode disparar mais de uma regra; todas são reportadas.
        }
      }
    }
  }

  achados.sort((a, b) => a.filePath.localeCompare(b.filePath) || a.startLine - b.startLine);

  const digestAchados = calcularDigestCanonico(achados);

  return {
    status: 'SUCCESS',
    achados,
    duracaoMs: Date.now() - inicio,
    identidade: {
      id: ID_SENSOR,
      versao: VERSAO_REGRAS,
      completion: achados.length > 0 ? 'WITH_FINDINGS' : 'CLEAN',
      findingsDigest: digestAchados
    }
  };
}
