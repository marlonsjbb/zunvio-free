import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, lstatSync, realpathSync, existsSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

export const LIMITES_DEFENSIVOS_PADRAO = Object.freeze({
  MAX_ARQUIVOS: 10_000,
  MAX_PROFUNDIDADE: 20,
  MAX_TAMANHO_ARQUIVO_BYTES: 50 * 1024 * 1024, // 50MB
  MAX_TAMANHO_TOTAL_BYTES: 500 * 1024 * 1024,   // 500MB
});

/**
 * Valida o diretório-alvo assegurando que não é um symlink na raiz e que existe fisicamente.
 * @param {string} dirPath - Caminho informado.
 * @returns {string} Caminho canônico resolvido pelo realpath.
 */
export function validarDiretorioAlvo(dirPath) {
  if (!dirPath || typeof dirPath !== 'string') {
    throw new Error('Caminho do diretório de análise é obrigatório.');
  }

  const caminhoAbsoluto = resolve(dirPath);
  if (!existsSync(caminhoAbsoluto)) {
    throw new Error(`Diretório de análise não encontrado: '${caminhoAbsoluto}'`);
  }

  let lstats;
  try {
    lstats = lstatSync(caminhoAbsoluto);
  } catch (err) {
    throw new Error(`Diretório de análise não encontrado: '${caminhoAbsoluto}'. Erro: ${err.message}`);
  }

  if (lstats.isSymbolicLink()) {
    throw new Error(`Violação de contenção: o diretório-raiz de análise '${caminhoAbsoluto}' é um link simbólico, o que é proibido por segurança.`);
  }

  if (!lstats.isDirectory()) {
    throw new Error(`O caminho informado não é um diretório regular: '${caminhoAbsoluto}'`);
  }

  // Resolve caminho real canônico
  return realpathSync(caminhoAbsoluto);
}

/**
 * Coleta todos os arquivos regulares de um diretório de forma determinística e recursiva com limites defensivos.
 * @param {string} raizReal - Caminho canônico resolvido pelo realpath.
 * @param {object} [opcoes={}]
 * @param {string[]} [opcoes.ignorar=['.git', 'node_modules']]
 * @param {number} [opcoes.maxArquivos=10000]
 * @param {number} [opcoes.maxProfundidade=20]
 * @param {number} [opcoes.maxTamanhoArquivoBytes=52428800]
 * @param {number} [opcoes.maxTamanhoTotalBytes=524288000]
 * @returns {{ arquivos: string[], exclusoes: Array<{ caminho: string, motivo: string }>, errosLeitura: Array<{ caminho: string, erro: string }>, bytesTotais: number, limitesExcedidos: boolean, motivoLimite: string | null }}
 */
export function listarArquivosRecursivo(raizReal, opcoes = {}) {
  const ignorar = opcoes.ignorar || ['.git', 'node_modules'];
  const maxArquivos = opcoes.maxArquivos || LIMITES_DEFENSIVOS_PADRAO.MAX_ARQUIVOS;
  const maxProfundidade = opcoes.maxProfundidade || LIMITES_DEFENSIVOS_PADRAO.MAX_PROFUNDIDADE;
  const maxTamanhoArquivo = opcoes.maxTamanhoArquivoBytes || LIMITES_DEFENSIVOS_PADRAO.MAX_TAMANHO_ARQUIVO_BYTES;
  const maxTamanhoTotal = opcoes.maxTamanhoTotalBytes || LIMITES_DEFENSIVOS_PADRAO.MAX_TAMANHO_TOTAL_BYTES;

  const arquivos = [];
  const exclusoes = [];
  const errosLeitura = [];
  let bytesTotais = 0;
  let limitesExcedidos = false;
  let motivoLimite = null;

  function explorar(atual, profundidade) {
    if (limitesExcedidos) return;

    if (profundidade > maxProfundidade) {
      limitesExcedidos = true;
      motivoLimite = `Limite de profundidade (${maxProfundidade} níveis) excedido em: ${atual}`;
      return;
    }

    let itens;
    try {
      itens = readdirSync(atual).sort();
    } catch (err) {
      const rel = relative(raizReal, atual).replace(/\\/g, '/');
      errosLeitura.push({ caminho: rel || '.', erro: `Falha ao listar diretório: ${err.message}` });
      return;
    }

    for (const item of itens) {
      if (limitesExcedidos) break;

      const caminhoCompleto = join(atual, item);
      const caminhoRelativo = relative(raizReal, caminhoCompleto).replace(/\\/g, '/');

      if (ignorar.includes(item)) {
        exclusoes.push({ caminho: caminhoRelativo, motivo: 'Diretório ignorado por padrão (.git / node_modules)' });
        continue;
      }

      let stats;
      try {
        stats = lstatSync(caminhoCompleto);
      } catch (err) {
        errosLeitura.push({ caminho: caminhoRelativo, erro: `Falha ao ler lstat: ${err.message}` });
        continue;
      }

      // Ignora links simbólicos e junctions (evita loops circulares e escapes fora da raiz)
      if (stats.isSymbolicLink()) {
        exclusoes.push({ caminho: caminhoRelativo, motivo: 'Link simbólico ou junção ignorado por segurança' });
        continue;
      }

      if (stats.isDirectory()) {
        explorar(caminhoCompleto, profundidade + 1);
      } else if (stats.isFile()) {
        // Validação defensiva de contenção
        const rel = relative(raizReal, caminhoCompleto);
        if (rel.startsWith('..')) {
          exclusoes.push({ caminho: caminhoRelativo, motivo: 'Arquivo fora dos limites do diretório-raiz' });
          continue;
        }

        if (stats.size > maxTamanhoArquivo) {
          exclusoes.push({
            caminho: caminhoRelativo,
            motivo: `Arquivo excede limite de tamanho individual (${stats.size} bytes > ${maxTamanhoArquivo} bytes)`
          });
          continue;
        }

        if (bytesTotais + stats.size > maxTamanhoTotal) {
          limitesExcedidos = true;
          motivoLimite = `Tamanho total acumulado do projeto excedeu o limite defensivo (${maxTamanhoTotal} bytes)`;
          break;
        }

        if (arquivos.length >= maxArquivos) {
          limitesExcedidos = true;
          motivoLimite = `Quantidade de arquivos no projeto excedeu o limite defensivo (${maxArquivos} arquivos)`;
          break;
        }

        bytesTotais += stats.size;
        arquivos.push(caminhoCompleto);
      }
    }
  }

  explorar(raizReal, 1);

  return {
    arquivos,
    exclusoes,
    errosLeitura,
    bytesTotais,
    limitesExcedidos,
    motivoLimite
  };
}

/**
 * Calcula o hash determinístico SHA-256 do conteúdo de um diretório e declara exclusões auditáveis.
 * @param {string} dirPath - Diretório a ser calculado.
 * @param {object} [opcoes={}]
 * @returns {{ digest: string, contagemArquivos: number, bytesTotais: number, arquivos: Map<string, string>, exclusoes: Array<{ caminho: string, motivo: string }>, errosLeitura: Array<{ caminho: string, erro: string }>, limitesExcedidos: boolean, motivoLimite: string | null }}
 */
export function calcularDigestDiretorio(dirPath, opcoes = {}) {
  const raizReal = validarDiretorioAlvo(dirPath);
  const { arquivos: caminhosAbsolutos, exclusoes, errosLeitura, bytesTotais, limitesExcedidos, motivoLimite } =
    listarArquivosRecursivo(raizReal, opcoes);

  const mapaArquivos = new Map();
  const merkleHasher = createHash('sha256');

  for (const caminhoAbsoluto of caminhosAbsolutos) {
    const caminhoRelativo = relative(raizReal, caminhoAbsoluto).replace(/\\/g, '/');
    let conteudo;
    try {
      conteudo = readFileSync(caminhoAbsoluto);
    } catch (err) {
      errosLeitura.push({ caminho: caminhoRelativo, erro: `Falha na leitura física do arquivo: ${err.message}` });
      continue;
    }
    const hashConteudo = createHash('sha256').update(conteudo).digest('hex');
    mapaArquivos.set(caminhoRelativo, hashConteudo);
    merkleHasher.update(`${caminhoRelativo}:${hashConteudo}\n`);
  }

  const digest = merkleHasher.digest('hex');
  return {
    digest,
    contagemArquivos: mapaArquivos.size,
    bytesTotais,
    arquivos: mapaArquivos,
    exclusoes,
    errosLeitura,
    limitesExcedidos,
    motivoLimite
  };
}

/**
 * Comprova que um diretório permaneceu 100% inalterado comparando seu digest antes e depois.
 * @param {string} dirPath - Caminho do diretório.
 * @param {string} digestInicial - Digest calculado antes da operação.
 * @returns {{ inalterado: boolean, digestInicial: string, digestFinal: string, diferencas: string[] }}
 */
export function verificarImutabilidade(dirPath, digestInicial) {
  const { digest: digestFinal } = calcularDigestDiretorio(dirPath);
  const inalterado = digestInicial === digestFinal;

  return {
    inalterado,
    digestInicial,
    digestFinal,
    diferencas: inalterado ? [] : ['O conteúdo ou estrutura do diretório foi alterado']
  };
}
