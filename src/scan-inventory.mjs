import { createHash } from 'node:crypto';
import {
  closeSync,
  copyFileSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  readSync,
  rmSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, extname, join, relative } from 'node:path';
import { LIMITES_DEFENSIVOS_PADRAO } from './utils/integrity.mjs';

// MASS-399 AJ-01B (decisão de política #12420): dist/build/coverage saíram
// desta lista. O nome do diretório, isoladamente, não é prova de que o
// conteúdo é gerado — AJ-01 reproduziu que isso permitia esconder um
// segredo ou padrão perigoso real de propósito. node_modules (dependência
// vendorizada, identidade própria via manifest) e .git (metadados internos,
// não código) mantêm o tratamento contratado, fora do escopo deste
// incremento.
export const DIRETORIOS_EXCLUIDOS_SCANNER = Object.freeze([
  'node_modules',
  '.git'
]);

const DIRETORIOS_EXCLUIDOS = new Set(DIRETORIOS_EXCLUIDOS_SCANNER);
const MANIFESTS_CONHECIDOS = new Set([
  'package.json',
  'npm-shrinkwrap.json',
  'composer.json',
  'pyproject.toml',
  'cargo.toml',
  'go.mod',
  'go.sum',
  'gemfile',
  'pipfile'
]);

export function ehManifestOuLockfile(caminho) {
  const nome = basename(String(caminho || '')).toLowerCase();
  return MANIFESTS_CONHECIDOS.has(nome)
    || nome.endsWith('.lock')
    || nome.endsWith('.lockb')
    || /(?:^|[-.])lock\.(?:json|ya?ml)$/u.test(nome);
}

export function caminhoPermitidoNoInventario(caminho, { includeVendor = false } = {}) {
  if (ehManifestOuLockfile(caminho)) return true;
  const segmentos = String(caminho || '')
    .replace(/\\/g, '/')
    .split('/')
    .filter(Boolean)
    .map((segmento) => segmento.toLowerCase());
  if (segmentos.includes('.git')) return false;
  // MASS-399 AJ-01B: dist/build/coverage não são mais descartados aqui. Esta
  // função também filtra achados do Gitleaks vindos da passada de HISTÓRICO
  // (git log sobre o repositório real, não a cópia filtrada) — um segredo
  // commitado de propósito numa pasta com esse nome não pode ser descartado
  // silenciosamente depois de detectado.
  if (segmentos.includes('node_modules')) return includeVendor;
  return true;
}

/**
 * PL-02: tipo estruturado de cada exclusão do inventário (o texto de `motivo` continua o mesmo). O universo esperado
 * usa o tipo: exclusão de POLÍTICA fica declarada como fronteira; exclusão por LIMITE OPERACIONAL do ZUNVIO (arquivo
 * acima do limite individual) é arquivo esperado que não foi analisado.
 */
export const TIPO_EXCLUSAO = Object.freeze({
  DIRETORIO_POLITICA: 'DIRETORIO_POLITICA',
  LINK_SIMBOLICO: 'LINK_SIMBOLICO',
  LIMITE_TAMANHO_ARQUIVO: 'LIMITE_TAMANHO_ARQUIVO'
});

// Shebang do Node (e runtimes compatíveis): o Semgrep reconhece arquivo SEM extensão como JavaScript por ele
// (observado no B4 da Bancada v1). Só a primeira linha é lida, e só de arquivo sem extensão.
// Revisão r3: aceita também `env -S node …` e flags do env antes do interpretador (o Semgrep 1.176.0 analisa esses).
export const SHEBANG_NODE = /^#!\s*(?:\S*\/)?(?:env\s+(?:-\S+\s+)*)?(?:node|nodejs)(?:\s|$)/;
export function primeiraLinha(caminho) {
  let fd;
  try {
    fd = openSync(caminho, 'r');
    const buffer = Buffer.alloc(256);
    const lidos = readSync(fd, buffer, 0, 256, 0);
    return buffer.subarray(0, lidos).toString('utf8').split(/\r?\n/)[0];
  } catch {
    // Revisão r7: null = não foi possível ler (distinto de "sem shebang").
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function motivoExclusao(nomeDiretorio) {
  if (nomeDiretorio === 'node_modules') return 'Dependências vendorizadas excluídas por padrão; manifests e lockfiles foram preservados';
  return 'Metadados internos do Git excluídos; manifests e lockfiles foram preservados';
}

/**
 * PL-01: teto da CONTAGEM de arquivos além do limite operacional (só metadados: lstat, sem cópia nem leitura).
 * Não é um limite de análise: a análise continua limitada a `MAX_ARQUIVOS`/`MAX_TAMANHO_TOTAL_BYTES`. Serve para
 * que o universo esperado continue determinável acima do limite; passou dele, o universo é declarado indeterminado.
 */
export const MAX_ARQUIVOS_CONTAGEM = 200000;

/** PL-01 (revisão r1): teto de leituras de 1ª linha (256 bytes) de arquivos sem extensão além do limite operacional. */
export const MAX_LEITURAS_SHEBANG_ALEM = 5000;

/** PL-01: extensões JavaScript/TypeScript guardadas da parte além do limite (candidatas ao universo esperado). */
const EXTENSOES_JS_TS = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts']);

/**
 * Materializa fora do alvo um inventário determinístico para os motores. O alvo
 * permanece somente leitura; a cópia temporária é removida assim que os scans
 * terminam.
 */
export function criarInventarioScanner(raizAlvo, opcoes = {}) {
  const includeVendor = opcoes.includeVendor === true;
  const limites = opcoes.limites || {};
  const maxArquivos = limites.maxArquivos || LIMITES_DEFENSIVOS_PADRAO.MAX_ARQUIVOS;
  const maxProfundidade = limites.maxProfundidade || LIMITES_DEFENSIVOS_PADRAO.MAX_PROFUNDIDADE;
  const maxTamanhoArquivo = limites.maxTamanhoArquivoBytes || LIMITES_DEFENSIVOS_PADRAO.MAX_TAMANHO_ARQUIVO_BYTES;
  const maxTamanhoTotal = limites.maxTamanhoTotalBytes || LIMITES_DEFENSIVOS_PADRAO.MAX_TAMANHO_TOTAL_BYTES;
  const raizTemporaria = mkdtempSync(join(tmpdir(), 'zunvio-inventory-'));
  const exclusoes = [];
  const arquivosRelativos = [];
  const errosLeitura = [];
  // PL-02: tamanho de cada arquivo enviado e arquivos sem extensão com shebang do Node (universo esperado).
  const tamanhos = Object.create(null);
  const shebangNode = [];
  let bytesTotais = 0;
  // PL-01: acima do limite operacional o inventário NÃO aborta. Envia até o limite atual (ordem determinística do
  // percurso), conta o resto e declara. Os limites de análise não mudam.
  const alemDoLimite = [];
  // LC-06: para o sensor de segredos TODO arquivo é elegível — guarda o caminho de cada arquivo além do limite.
  const caminhosAlemDoLimite = [];
  const limite = { atingido: false, motivo: null, arquivos: 0, bytes: 0, universoDeterminado: true, motivoIndeterminado: null };
  let arquivosVistos = 0;
  const maxContagem = limites.maxArquivosContagem || MAX_ARQUIVOS_CONTAGEM;
  // Revisão r1 (M3): além do limite, a leitura da 1ª linha de arquivo sem extensão (shebang do Node) tem teto próprio —
  // passou dele, não se sabe se os demais são scripts Node: o universo esperado é declarado indeterminado (honesto),
  // em vez de gastar I/O sem limite.
  const maxLeiturasShebang = limites.maxLeiturasShebangAlem || MAX_LEITURAS_SHEBANG_ALEM;
  let leiturasShebangAlem = 0;

  function registrarAlemDoLimite(absoluto, caminhoRelativo, stats) {
    limite.arquivos += 1;
    caminhosAlemDoLimite.push(caminhoRelativo);
    limite.bytes += stats.size;
    const ext = extname(caminhoRelativo).toLowerCase();
    if (EXTENSOES_JS_TS.has(ext)) {
      alemDoLimite.push({ caminho: caminhoRelativo, bytes: stats.size });
    } else if (ext === '') {
      leiturasShebangAlem += 1;
      if (leiturasShebangAlem > maxLeiturasShebang) {
        limite.universoDeterminado = false;
        limite.motivoIndeterminado = limite.motivoIndeterminado || 'LEITURAS';
        return;
      }
      const linha = primeiraLinha(absoluto);
      if (linha === null) errosLeitura.push({ caminho: caminhoRelativo, erro: 'Falha ao ler a primeira linha de arquivo sem extensão além do limite operacional' });
      else if (SHEBANG_NODE.test(linha)) { alemDoLimite.push({ caminho: caminhoRelativo, bytes: stats.size }); shebangNode.push(caminhoRelativo); }
    }
  }

  function listarDiretorio(atual) {
    let entradas;
    try {
      entradas = readdirSync(atual, { withFileTypes: true })
        .sort((a, b) => a.name.localeCompare(b.name));
    } catch (erro) {
      const caminho = relative(raizAlvo, atual).replace(/\\/g, '/') || '.';
      errosLeitura.push({ caminho, erro: `Falha ao listar diretório: ${erro.message}` });
      return [];
    }
    return entradas;
  }

  function obterStats(absoluto) {
    const caminhoRelativo = relative(raizAlvo, absoluto).replace(/\\/g, '/');
    try {
      return lstatSync(absoluto);
    } catch (erro) {
      errosLeitura.push({ caminho: caminhoRelativo, erro: `Falha ao ler lstat: ${erro.message}` });
      return null;
    }
  }

  function incluirArquivo(absoluto, stats) {
    const caminhoRelativo = relative(raizAlvo, absoluto).replace(/\\/g, '/');
    if (stats.size > maxTamanhoArquivo) {
      exclusoes.push({
        caminho: caminhoRelativo,
        motivo: `Arquivo excede limite de tamanho individual (${stats.size} bytes > ${maxTamanhoArquivo} bytes)`,
        tipo: TIPO_EXCLUSAO.LIMITE_TAMANHO_ARQUIVO,
        bytes: stats.size
      });
      // PL-02 (revisão r2): o shebang é lido do ORIGINAL (só 256 bytes) mesmo quando o arquivo não é enviado, para
      // que um script Node sem extensão acima do limite entre no universo esperado como OPERATIONAL_LIMIT.
      if (extname(caminhoRelativo) === '') {
        const linha = primeiraLinha(absoluto);
        // Revisão r7: sem conseguir ler a 1ª linha, não se sabe se é script Node — vira erro de leitura declarado
        // (READ_ERROR no universo), nunca um sumiço silencioso.
        if (linha === null) errosLeitura.push({ caminho: caminhoRelativo, erro: 'Falha ao ler a primeira linha de arquivo sem extensão acima do limite de tamanho' });
        else if (SHEBANG_NODE.test(linha)) shebangNode.push(caminhoRelativo);
      }
      return;
    }
    // PL-01: atingido um limite, nada mais é enviado (corte determinístico); o resto é contado e declarado.
    if (!limite.atingido && arquivosRelativos.length >= maxArquivos) {
      limite.atingido = true;
      limite.motivo = `Quantidade de arquivos do projeto passa do limite operacional (${maxArquivos} arquivos)`;
    }
    if (!limite.atingido && bytesTotais + stats.size > maxTamanhoTotal) {
      limite.atingido = true;
      limite.motivo = `Tamanho total do projeto passa do limite operacional (${maxTamanhoTotal} bytes)`;
    }
    if (limite.atingido) {
      registrarAlemDoLimite(absoluto, caminhoRelativo, stats);
      return;
    }

    const destino = join(raizTemporaria, caminhoRelativo);
    mkdirSync(dirname(destino), { recursive: true });
    copyFileSync(absoluto, destino);
    arquivosRelativos.push(caminhoRelativo);
    tamanhos[caminhoRelativo] = stats.size;
    if (extname(caminhoRelativo) === '' && SHEBANG_NODE.test(primeiraLinha(destino) ?? '')) shebangNode.push(caminhoRelativo);
    bytesTotais += stats.size;
  }

  function preservarManifestosDiretos(diretorio) {
    for (const entrada of listarDiretorio(diretorio)) {
      const absoluto = join(diretorio, entrada.name);
      const caminhoRelativo = relative(raizAlvo, absoluto).replace(/\\/g, '/');
      const stats = obterStats(absoluto);
      if (!stats) continue;
      if (stats.isSymbolicLink()) {
        exclusoes.push({ caminho: caminhoRelativo, motivo: 'Link simbólico ou junção ignorado por segurança', tipo: TIPO_EXCLUSAO.LINK_SIMBOLICO });
        continue;
      }
      if (stats.isFile() && ehManifestOuLockfile(caminhoRelativo)) incluirArquivo(absoluto, stats);
    }
  }

  function preservarManifestosDePacotes(diretorioNodeModules) {
    preservarManifestosDiretos(diretorioNodeModules);
    for (const entrada of listarDiretorio(diretorioNodeModules)) {
      const absoluto = join(diretorioNodeModules, entrada.name);
      const stats = obterStats(absoluto);
      if (!stats || stats.isSymbolicLink() || !stats.isDirectory()) continue;

      if (!entrada.name.startsWith('@')) {
        preservarManifestosDiretos(absoluto);
        continue;
      }

      // Pacotes npm com escopo têm um nível estrutural adicional:
      // node_modules/@escopo/pacote/package.json.
      for (const pacote of listarDiretorio(absoluto)) {
        const diretorioPacote = join(absoluto, pacote.name);
        const statsPacote = obterStats(diretorioPacote);
        if (statsPacote?.isDirectory() && !statsPacote.isSymbolicLink()) {
          preservarManifestosDiretos(diretorioPacote);
        }
      }
    }
  }

  function explorar(atual, profundidade) {
    if (!limite.universoDeterminado) return;
    if (profundidade > maxProfundidade) {
      // PL-01: a subárvore não é percorrida, então o universo esperado não é determinável.
      limite.atingido = true;
      limite.motivo = limite.motivo || `Profundidade do projeto passa do limite operacional (${maxProfundidade} níveis)`;
      limite.universoDeterminado = false;
      limite.motivoIndeterminado = 'PROFUNDIDADE';
      return;
    }

    for (const entrada of listarDiretorio(atual)) {
      const absoluto = join(atual, entrada.name);
      const caminhoRelativo = relative(raizAlvo, absoluto).replace(/\\/g, '/');
      const stats = obterStats(absoluto);
      if (!stats) continue;

      if (stats.isSymbolicLink()) {
        exclusoes.push({ caminho: caminhoRelativo, motivo: 'Link simbólico ou junção ignorado por segurança', tipo: TIPO_EXCLUSAO.LINK_SIMBOLICO });
        continue;
      }

      if (stats.isDirectory()) {
        const nomeDiretorio = entrada.name.toLowerCase();
        const diretorioExcluido = DIRETORIOS_EXCLUIDOS.has(nomeDiretorio)
          && !(nomeDiretorio === 'node_modules' && includeVendor);
        if (diretorioExcluido) {
          exclusoes.push({ caminho: caminhoRelativo, motivo: motivoExclusao(nomeDiretorio), tipo: TIPO_EXCLUSAO.DIRETORIO_POLITICA });
          if (nomeDiretorio === 'node_modules') preservarManifestosDePacotes(absoluto);
          else preservarManifestosDiretos(absoluto);
          continue;
        }
        explorar(absoluto, profundidade + 1);
        // Revisão r1 (M4): universo já indeterminado encerra a varredura também no diretório pai.
        if (!limite.universoDeterminado) return;
        continue;
      }

      if (stats.isFile()) {
        arquivosVistos += 1;
        if (arquivosVistos > maxContagem) {
          // PL-01: nem a contagem cabe no teto — o universo esperado não é determinável.
          limite.atingido = true;
          limite.motivo = limite.motivo || `Quantidade de arquivos do projeto passa do limite operacional (${maxArquivos} arquivos)`;
          limite.universoDeterminado = false;
          limite.motivoIndeterminado = 'CONTAGEM';
          return;
        }
        incluirArquivo(absoluto, stats);
      }
      if (!limite.universoDeterminado) return;
    }
  }

  try {
    explorar(raizAlvo, 1);
    arquivosRelativos.sort();
    const hasher = createHash('sha256');
    for (const caminhoRelativo of arquivosRelativos) {
      const conteudo = readFileSync(join(raizTemporaria, caminhoRelativo));
      const digestArquivo = createHash('sha256').update(conteudo).digest('hex');
      hasher.update(`${caminhoRelativo}:${digestArquivo}\n`);
    }
    return {
      raiz: raizTemporaria,
      arquivosRelativos,
      contagemArquivos: arquivosRelativos.length,
      digest: hasher.digest('hex'),
      bytesTotais,
      exclusoes,
      errosLeitura,
      tamanhos,
      shebangNode: shebangNode.sort(),
      // PL-01: o que ficou de fora por limite operacional do inventário (JS/TS e shebang do Node guardados por caminho;
      // o resto só contado) e se o universo esperado continua determinável.
      alemDoLimite,
      caminhosAlemDoLimite: caminhosAlemDoLimite.sort(),
      limiteOperacional: Object.freeze({
        ...limite,
        limites: Object.freeze({ maxArquivos, maxTamanhoTotalBytes: maxTamanhoTotal, maxProfundidade, maxArquivosContagem: maxContagem })
      }),
      limpar() {
        rmSync(raizTemporaria, { recursive: true, force: true });
      }
    };
  } catch (erro) {
    rmSync(raizTemporaria, { recursive: true, force: true });
    throw erro;
  }
}
