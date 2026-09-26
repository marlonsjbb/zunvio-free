// LC-06 — ZUNVIO Secret Scanner (working tree).
//
// Não é um substituto genérico do Gitleaks: é o MENOR mecanismo que permite ao ZUNVIO PROVAR a cobertura do estado
// atual dos arquivos. Aplica as MESMAS 12 regras de segredos que já pertencem ao ZUNVIO (rules/gitleaks/gitleaks.toml,
// fonte única — o Gitleaks segue usando o mesmo arquivo no histórico) ao conteúdo INTEIRO de cada arquivo do
// inventário e registra, por arquivo, se ele foi analisado, excluído por política ou não inspecionado (e por quê).
//
// Por que não o Gitleaks no working tree (investigação LC-06, 26/09/2026): a 8.18.4 perde segredo que atravessa um
// múltiplo de 10.000 bytes do arquivo (caso real no B5); a 8.30.1 pula arquivo de texto pelo NOME (.browser.js,
// .target…, .zip.js; casos reais no B4/B5); ambas pulam compactados em silêncio e aceitam supressão pelo projeto
// (`gitleaks:allow`, `.gitleaksignore`); nenhuma informa quais arquivos leu.
//
// Propriedades (por construção):
//  - cada arquivo elegível é lido inteiro por este processo: bytes lidos = tamanho do arquivo no inventário;
//  - as 12 regras são aplicadas ao conteúdo completo (sem blocos, sem fronteira);
//  - nenhuma supressão controlada pelo projeto existe aqui (`gitleaks:allow`, `.gitleaksignore` não têm efeito);
//  - UTF-16 com BOM é decodificado; o resto é lido byte a byte (latin1: 1 byte = 1 caractere, nenhum byte perdido);
//  - conteúdo compactado (zip, docx, xlsx, gzip, pdf e contêineres equivalentes) NÃO é inspecionável lendo bytes:
//    é declarado NÃO ANALISADO com motivo, nunca "analisado";
//  - fontes woff/woff2 ficam FORA do universo por política explícita (decisão do fundador), listadas no pack.
// Limite declarado do modelo: texto UTF-16 SEM marca de ordem de bytes não é reconhecido como UTF-16.

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TIPO_EXCLUSAO } from '../scan-inventory.mjs';
import { digestDeLista, extensaoDe, MODELO_UNIVERSO, TETO_ARQUIVOS_AFETADOS } from '../models/expected-universe.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
export const CAMINHO_REGRAS_SEGREDOS = resolve(__dirname, '../../rules/gitleaks/gitleaks.toml');

export const ID_SCANNER_SEGREDOS = 'zunvio-segredos';
// Versão do MECANISMO (não das regras — essas têm o próprio hash). Muda quando muda o que é lido/como é lido.
export const VERSAO_SCANNER_SEGREDOS = '1.0.0';
export const MODELO_COBERTURA_SEGREDOS = 'lc06-1.0';

/** Formatos de fonte excluídos do universo por POLÍTICA (decisão do fundador, LC-06). Exclusão ≠ analisado. */
export const EXTENSOES_EXCLUIDAS_POR_POLITICA = Object.freeze(['.woff', '.woff2']);

/**
 * Conteúdo que ler bytes não inspeciona (compactado). Por extensão — os formatos demonstrados na investigação — e por
 * assinatura, para o mesmo conteúdo com outro nome e para contêineres equivalentes (7z, xz, bzip2, zstd, rar): chamar
 * de "analisado" um conteúdo compactado seria afirmar o que não foi inspecionado.
 */
export const EXTENSOES_NAO_INSPECIONADAS = Object.freeze({
  '.zip': 'zip', '.docx': 'zip', '.xlsx': 'zip', '.gz': 'gzip', '.gzip': 'gzip', '.pdf': 'pdf'
});
const ASSINATURAS_NAO_INSPECIONADAS = Object.freeze([
  ['504b0304', 'zip'], ['504b0506', 'zip'], ['504b0708', 'zip'], ['1f8b', 'gzip'], ['255044462d', 'pdf'],
  ['377abcaf271c', '7z'], ['fd377a585a00', 'xz'], ['425a68', 'bzip2'], ['28b52ffd', 'zstd'], ['526172211a07', 'rar']
]);

/** Motivo de não análise no modelo do universo (PL-02): "tipo de arquivo que a verificação não lê". */
const MOTIVO_NAO_INSPECIONADO = 'UNSUPPORTED_EXTENSION';

/**
 * Lê as regras do toml de segredos do ZUNVIO. Só o que o ruleset usa (id, description, regex): se aparecer qualquer
 * campo que mude a semântica (keywords, entropy, allowlist, secretGroup, path), falha fechado — o scanner não pode
 * aplicar uma regra diferente da que o Gitleaks aplica no histórico.
 */
export function carregarRegrasSegredos(caminho = CAMINHO_REGRAS_SEGREDOS) {
  const toml = readFileSync(caminho, 'utf8');
  const blocos = toml.split(/^\[\[rules\]\]\s*$/m).slice(1);
  const regras = blocos.map((bloco, i) => {
    const campos = {};
    for (const m of bloco.matchAll(/^([A-Za-z]+)\s*=\s*(?:'''([\s\S]*?)'''|"((?:[^"\\]|\\.)*)"|(\[[^\]]*\]))/gm)) {
      campos[m[1]] = m[2] ?? m[3] ?? m[4];
    }
    const extras = Object.keys(campos).filter((k) => !['id', 'description', 'regex', 'tags'].includes(k));
    if (extras.length) throw new Error(`regra ${i + 1} do ruleset de segredos usa campo não suportado pelo scanner próprio: ${extras.join(', ')}`);
    if (!campos.id || !campos.regex) throw new Error(`regra ${i + 1} do ruleset de segredos sem id ou regex`);
    // RE2 → JS: só o `(?i)` inicial (vira a flag i). Qualquer outra flag inline falha fechado.
    let fonte = campos.regex;
    let flags = 'g';
    if (fonte.startsWith('(?i)')) { fonte = fonte.slice(4); flags += 'i'; }
    if (/\(\?[a-zA-Z]/.test(fonte)) throw new Error(`regra ${campos.id}: flag inline não suportada`);
    return Object.freeze({ id: campos.id, description: campos.description || campos.id, re: new RegExp(fonte, flags) });
  });
  if (regras.length === 0) throw new Error('ruleset de segredos sem regras');
  return Object.freeze({ regras: Object.freeze(regras), hash: createHash('sha256').update(toml).digest('hex') });
}

function formatoNaoInspecionado(caminho, bytes) {
  const porExtensao = EXTENSOES_NAO_INSPECIONADAS[extensaoDe(caminho)];
  if (porExtensao) return { formato: porExtensao, deteccao: 'EXTENSAO' };
  const cabeca = bytes.subarray(0, 8).toString('hex');
  const porAssinatura = ASSINATURAS_NAO_INSPECIONADAS.find(([m]) => cabeca.startsWith(m));
  return porAssinatura ? { formato: porAssinatura[1], deteccao: 'ASSINATURA' } : null;
}

function decodificar(bytes) {
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) return { texto: bytes.subarray(2).toString('utf16le'), codificacao: 'utf16le' };
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    const c = Buffer.from(bytes.subarray(2, bytes.length - ((bytes.length - 2) % 2)));
    c.swap16();
    return { texto: c.toString('utf16le'), codificacao: 'utf16be' };
  }
  return { texto: bytes.toString('latin1'), codificacao: 'bytes' };
}

/**
 * Achados de UM conteúdo, no formato bruto do Gitleaks (mesmos campos e convenções de linha/coluna do 8.18.4:
 * coluna = posição do byte na linha + 1 na primeira linha e + 2 nas demais; segredo = 1º grupo de captura, ou o
 * trecho inteiro). Assim a deduplicação working tree × histórico (PER-207) e a normalização continuam as mesmas.
 */
export function varrerConteudo(texto, caminhoRelativo, regras) {
  const inicioDeLinha = [0];
  for (let i = texto.indexOf('\n'); i !== -1; i = texto.indexOf('\n', i + 1)) inicioDeLinha.push(i + 1);
  const linhaDe = (pos) => {
    let lo = 0; let hi = inicioDeLinha.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (inicioDeLinha[mid] <= pos) lo = mid; else hi = mid - 1; }
    return lo + 1;
  };
  const achados = [];
  for (const { id, description, re } of regras) {
    re.lastIndex = 0;
    for (let m; (m = re.exec(texto));) {
      if (m[0].length === 0) { re.lastIndex++; continue; }
      const startLine = linhaDe(m.index);
      const endLine = linhaDe(m.index + m[0].length - 1);
      const startColumn = m.index - inicioDeLinha[startLine - 1] + (startLine === 1 ? 1 : 2);
      achados.push({
        Description: description,
        StartLine: startLine,
        EndLine: endLine,
        StartColumn: startColumn,
        EndColumn: startColumn + m[0].length - 1,
        Match: m[0],
        Secret: m[1] ?? m[0],
        File: caminhoRelativo,
        RuleID: id,
        Fingerprint: `${caminhoRelativo}:${id}:${startLine}`
      });
    }
  }
  return achados;
}

/**
 * Varre o working tree a partir do inventário do ZUNVIO (a MESMA cópia que os outros sensores leem).
 * @param {object} inventario - criarInventarioScanner(): raiz, arquivosRelativos, tamanhos, exclusoes, errosLeitura,
 *   limiteOperacional, caminhosAlemDoLimite
 * @param {{ regras?: object }} [opcoes]
 * @returns {{ status: 'SUCCESS'|'ERROR', vazamentos: object[], cobertura: object|null, rulesetHash: string|null, erro: string|null, duracaoMs: number }}
 */
export function varrerArvoreSegredos(inventario, opcoes = {}) {
  const inicio = Date.now();
  let ruleset;
  try {
    ruleset = opcoes.regras || carregarRegrasSegredos();
  } catch (erro) {
    return { status: 'ERROR', vazamentos: [], cobertura: null, rulesetHash: null, erro: `Regras de segredos ilegíveis: ${erro.message}`, duracaoMs: Date.now() - inicio };
  }
  const vazamentos = [];
  const analisados = [];
  const excluidosPolitica = [];
  const naoAnalisados = []; // { path, reasons, formato?, deteccao? }
  const codificacoes = {};
  const tamanhos = inventario.tamanhos || {};
  let bytesLidos = 0;
  for (const caminho of [...inventario.arquivosRelativos].sort()) {
    if (EXTENSOES_EXCLUIDAS_POR_POLITICA.includes(extensaoDe(caminho))) { excluidosPolitica.push(caminho); continue; }
    let bytes;
    try {
      bytes = readFileSync(join(inventario.raiz, caminho));
    } catch {
      naoAnalisados.push({ path: caminho, reasons: ['READ_ERROR'] });
      continue;
    }
    // O inventário mediu o tamanho ao copiar; ler outra quantidade de bytes é não saber o que foi lido.
    if (Number.isInteger(tamanhos[caminho]) && tamanhos[caminho] !== bytes.length) {
      naoAnalisados.push({ path: caminho, reasons: ['READ_ERROR'] });
      continue;
    }
    const naoInspecionado = formatoNaoInspecionado(caminho, bytes);
    if (naoInspecionado) {
      naoAnalisados.push({ path: caminho, reasons: [MOTIVO_NAO_INSPECIONADO], ...naoInspecionado });
      continue;
    }
    const { texto, codificacao } = decodificar(bytes);
    codificacoes[codificacao] = (codificacoes[codificacao] || 0) + 1;
    bytesLidos += bytes.length;
    vazamentos.push(...varrerConteudo(texto, caminho, ruleset.regras));
    analisados.push(caminho);
  }
  return {
    status: 'SUCCESS',
    vazamentos,
    cobertura: montarCobertura({ inventario, analisados, excluidosPolitica, naoAnalisados, codificacoes, bytesLidos }),
    rulesetHash: ruleset.hash,
    erro: null,
    duracaoMs: Date.now() - inicio
  };
}

function porTipo(exclusoes) {
  const contagem = {};
  for (const e of exclusoes) contagem[e] = (contagem[e] || 0) + 1;
  return contagem;
}

/**
 * Universo do sensor de segredos (modelo PL-02: esperado × analisado × não analisado + motivo) e o detalhe auditável
 * que só o pack guarda (política, formatos não inspecionados, codificações).
 */
function montarCobertura({ inventario, analisados, excluidosPolitica, naoAnalisados, codificacoes, bytesLidos }) {
  const exclusoes = inventario.exclusoes || [];
  const politicaInventario = exclusoes.filter((e) => e?.tipo !== TIPO_EXCLUSAO.LIMITE_TAMANHO_ARQUIVO);
  const fontesEnviadas = excluidosPolitica.length; // fontes que estavam entre os arquivos enviados
  // Uma lacuna por caminho (o mesmo caminho pode vir de duas fontes: ex. erro de leitura além do limite).
  const porCaminho = new Map();
  const lacuna = (path, motivo, extra = {}) => {
    const atual = porCaminho.get(path) || { path, reasons: [] };
    if (!atual.reasons.includes(motivo)) atual.reasons.push(motivo);
    porCaminho.set(path, { ...atual, ...extra, reasons: atual.reasons.sort() });
  };
  for (const a of naoAnalisados) for (const m of a.reasons) lacuna(a.path, m, a.formato ? { formato: a.formato, deteccao: a.deteccao } : {});
  // Além do limite operacional do inventário: TODO arquivo é elegível para segredos.
  const alem = inventario.caminhosAlemDoLimite || [];
  for (const caminho of alem) {
    if (EXTENSOES_EXCLUIDAS_POR_POLITICA.includes(extensaoDe(caminho))) { excluidosPolitica.push(caminho); continue; }
    lacuna(caminho, 'OPERATIONAL_LIMIT');
  }
  for (const ex of exclusoes) {
    if (ex?.tipo !== TIPO_EXCLUSAO.LIMITE_TAMANHO_ARQUIVO) continue;
    if (EXTENSOES_EXCLUIDAS_POR_POLITICA.includes(extensaoDe(ex.caminho))) { excluidosPolitica.push(ex.caminho); continue; }
    lacuna(ex.caminho, 'OPERATIONAL_LIMIT');
  }
  for (const er of inventario.errosLeitura || []) {
    if (typeof er?.caminho === 'string') lacuna(er.caminho, 'READ_ERROR');
  }
  const lacunas = [...porCaminho.values()].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const byReason = {};
  for (const a of lacunas) for (const m of a.reasons) byReason[m] = (byReason[m] || 0) + 1;
  const tiposPolitica = porTipo(politicaInventario.map((e) => e?.tipo || 'OUTRA'));
  if (excluidosPolitica.length > 0) tiposPolitica.OUTRA = (tiposPolitica.OUTRA || 0) + excluidosPolitica.length;
  // O universo só é determinado quando o inventário conseguiu contar tudo (PL-01) e registrar os caminhos além do limite.
  const determinado = inventario.limiteOperacional?.universoDeterminado !== false
    && alem.length === (inventario.limiteOperacional?.arquivos || 0);
  const universe = determinado ? {
    model: MODELO_UNIVERSO,
    coverage: { languages: [], expectedExtensions: [], includesNodeShebangWithoutExtension: false, source: 'ALL_FILES_SENT' },
    boundary: {
      filesSent: inventario.arquivosRelativos.length - fontesEnviadas,
      policyExclusions: politicaInventario.length + excluidosPolitica.length,
      policyExclusionsByKind: tiposPolitica,
      operationalLimitExclusions: exclusoes.length - politicaInventario.length + (inventario.limiteOperacional?.arquivos || 0),
      readErrors: (inventario.errosLeitura || []).length
    },
    expected: analisados.length + lacunas.length,
    analyzed: analisados.length,
    partiallyAnalyzed: 0,
    notAnalyzed: lacunas.length,
    scannedOutsideExpected: 0,
    byReason: Object.fromEntries(Object.keys(byReason).sort().map((k) => [k, byReason[k]])),
    notAnalyzedDigest: digestDeLista(lacunas.map((a) => `${a.path}\t${a.reasons.join(',')}`)),
    scannedDigest: digestDeLista(analisados)
  } : null;
  const naoInspecionados = lacunas.filter((a) => a.formato);
  const politicaOrdenada = [...excluidosPolitica].sort();
  return {
    universe,
    lacunas,
    detalhe: {
      model: MODELO_COBERTURA_SEGREDOS,
      bytesRead: bytesLidos,
      encodings: Object.fromEntries(Object.keys(codificacoes).sort().map((k) => [k, codificacoes[k]])),
      policyExclusions: {
        extensions: [...EXTENSOES_EXCLUIDAS_POR_POLITICA],
        count: politicaOrdenada.length,
        files: politicaOrdenada.slice(0, TETO_ARQUIVOS_AFETADOS),
        digest: digestDeLista(politicaOrdenada)
      },
      notInspected: {
        count: naoInspecionados.length,
        files: naoInspecionados.slice(0, TETO_ARQUIVOS_AFETADOS).map((a) => ({ path: a.path, format: a.formato, detection: a.deteccao })),
        digest: digestDeLista(naoInspecionados.map((a) => `${a.path}\t${a.formato}\t${a.deteccao}`))
      },
      universeDetermined: determinado
    }
  };
}
