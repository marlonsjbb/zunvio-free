import { relative, resolve } from 'node:path';
import { executarProcessoSeguro } from '../utils/process-runner.mjs';

/**
 * Valida a sintaxe básica de uma referência Git antes de qualquer execução.
 * Rejeita referências que comecem com '-', contenham espaços ou caracteres de controle.
 * @param {string} ref - Nome da branch, tag, commit ou expressão de ref.
 * @returns {boolean} True se a sintaxe for aceitável.
 */
export function validarSintaxeRef(ref) {
  if (!ref || typeof ref !== 'string') return false;
  const limpo = ref.trim();
  if (!limpo) return false;
  // Rejeita qualquer ref que comece com '-' (evita injeção de opções no CLI)
  if (limpo.startsWith('-')) return false;
  // Rejeita espaços, quebras de linha ou caracteres de controle
  if (/[\s\x00-\x1F\x7F]/.test(limpo)) return false;
  // Rejeita caracteres perigosos como aspas, ponto e vírgula, pipes ou crases
  if (/["';`$|&<>]/.test(limpo)) return false;
  return true;
}

/**
 * Resolve com segurança uma referência Git para um commit SHA completo de 40 dígitos.
 * Falha de forma fechada retornando null se a ref for inválida, inexistente ou ambígua.
 * @param {string} raizProjeto - Caminho absoluto do repositório.
 * @param {string} ref - Referência a resolver (ex: 'HEAD', 'main', 'HEAD~1').
 * @param {Function} [runner=executarProcessoSeguro] - Função de execução de subprocessos.
 * @returns {string | null} SHA completo de 40 caracteres ou null se falhar.
 */
export function resolverRefParaSha(raizProjeto, ref, runner = executarProcessoSeguro) {
  if (!validarSintaxeRef(ref)) return null;

  const resultado = runner(
    'git',
    [
      '-C',
      raizProjeto,
      '-c',
      'core.quotepath=false',
      'rev-parse',
      '--verify',
      '--quiet',
      '--end-of-options',
      `${ref}^{commit}`
    ],
    { timeout: 5000 }
  );

  if (resultado.status !== 'SUCCESS' || resultado.exitCode !== 0) {
    return null;
  }

  const sha = (resultado.stdout || '').trim();
  if (/^[0-9a-f]{40}$/i.test(sha)) {
    return sha.toLowerCase();
  }

  return null;
}

/**
 * Sanitiza e normaliza um caminho de arquivo extraído do diff.
 * Rejeita caminhos maliciosos ou tentativas de escape fora do projeto (ex: '../').
 * @param {string} rawPath - Caminho bruto extraído do diff.
 * @param {string} raizProjeto - Caminho da raiz do projeto.
 * @returns {string | null} Caminho canônico relativo seguro ou null se inválido.
 */
export function normalizarCaminhoDiff(rawPath, raizProjeto) {
  if (!rawPath || typeof rawPath !== 'string') return null;

  // Remove aspas caso o git tenha envolvido o caminho com espaços em aspas
  let limpo = rawPath.trim();
  if (limpo.startsWith('"') && limpo.endsWith('"')) {
    limpo = limpo.slice(1, -1);
  }

  // Remove prefixos padrão do git diff 'a/' ou 'b/'
  if (limpo.startsWith('a/') || limpo.startsWith('b/')) {
    limpo = limpo.slice(2);
  }

  limpo = limpo.replace(/\\/g, '/');

  // Proteção contra path traversal e caminhos absolutos forjados
  if (limpo.includes('..') || limpo.startsWith('/') || /^[A-Za-z]:/.test(limpo)) {
    return null;
  }

  if (raizProjeto) {
    const abs = resolve(raizProjeto, limpo);
    const rel = relative(resolve(raizProjeto), abs).replace(/\\/g, '/');
    if (rel.startsWith('..') || /^[A-Za-z]:/.test(rel)) {
      return null;
    }
    return rel;
  }

  return limpo;
}

/**
 * Faz o parsing de uma string de unified diff do Git.
 * @param {string} diffString - Saída bruta do git diff.
 * @param {string} [raizProjeto='.'] - Raiz do projeto para validação de caminhos.
 * @returns {Array<object>} Lista estruturada de arquivos alterados e seus intervalos de linhas.
 */
export function parsearGitDiff(diffString, raizProjeto = '.') {
  if (!diffString || typeof diffString !== 'string' || !diffString.trim()) {
    return [];
  }

  const blocos = diffString.split(/^diff --git /m).filter(Boolean);
  const arquivos = [];

  for (const bloco of blocos) {
    const linhas = bloco.split(/\r?\n/);
    if (linhas.length === 0) continue;

    const cabecalho = linhas[0];
    const matchCabecalho = cabecalho.match(/(?:a\/|")(.*?)(?:"|\s)+(?:b\/|")(.*?)(?:"|$)/);

    let caminhoAntigo = null;
    let caminhoNovo = null;

    if (matchCabecalho) {
      caminhoAntigo = normalizarCaminhoDiff(matchCabecalho[1], raizProjeto);
      caminhoNovo = normalizarCaminhoDiff(matchCabecalho[2], raizProjeto);
    }

    let tipo = 'MODIFIED';
    let ehBinario = false;
    let linhasAdicionadas = 0;
    let linhasRemovidas = 0;
    const intervalosLinhas = [];

    // Analisa metadados do cabeçalho do arquivo
    for (let i = 1; i < linhas.length; i++) {
      const linha = linhas[i];
      if (linha.startsWith('@@')) break; // Início dos hunks

      if (linha.startsWith('new file mode')) {
        tipo = 'ADDED';
      } else if (linha.startsWith('deleted file mode')) {
        tipo = 'DELETED';
      } else if (linha.startsWith('rename from')) {
        tipo = 'RENAMED';
        const raw = linha.replace(/^rename from\s+/, '');
        caminhoAntigo = normalizarCaminhoDiff(raw, raizProjeto);
      } else if (linha.startsWith('rename to')) {
        const raw = linha.replace(/^rename to\s+/, '');
        caminhoNovo = normalizarCaminhoDiff(raw, raizProjeto);
      } else if (linha.startsWith('Binary files') || linha.startsWith('GIT binary patch')) {
        tipo = 'BINARY';
        ehBinario = true;
      }
    }

    // Se for renomeação e o destino for inválido/rejeitado, descarta completamente sem fallback
    if (tipo === 'RENAMED' && !caminhoNovo) {
      continue;
    }

    // Processa os hunks de linhas
    if (!ehBinario) {
      for (const linha of linhas) {
        if (linha.startsWith('@@')) {
          // Formato: @@ -oldStart,oldCount +newStart,newCount @@
          const matchHunk = linha.match(/@@\s+-(?:(\d+)(?:,(\d+))?)\s+\+(?:(\d+)(?:,(\d+))?)\s+@@/);
          if (matchHunk) {
            const newStart = parseInt(matchHunk[3], 10);
            const newCount = matchHunk[4] !== undefined ? parseInt(matchHunk[4], 10) : 1;

            if (newCount > 0) {
              intervalosLinhas.push({
                inicio: newStart,
                fim: newStart + newCount - 1
              });
            }
          }
        } else if (linha.startsWith('+') && !linha.startsWith('+++')) {
          linhasAdicionadas++;
        } else if (linha.startsWith('-') && !linha.startsWith('---')) {
          linhasRemovidas++;
        }
      }
    }

    const caminhoFinal = tipo === 'DELETED' ? caminhoAntigo : (caminhoNovo || caminhoAntigo);

    if (caminhoFinal) {
      arquivos.push(Object.freeze({
        caminho: caminhoFinal,
        caminhoAntigo: tipo === 'RENAMED' ? caminhoAntigo : null,
        tipo,
        ehBinario,
        linhasAdicionadas,
        linhasRemovidas,
        totalMudancas: linhasAdicionadas + linhasRemovidas,
        intervalosLinhas: Object.freeze(intervalosLinhas)
      }));
    }
  }

  return Object.freeze(arquivos);
}

/**
 * Obtém com segurança o diff do Git sem usar shell, external diff ou textconv.
 * Valida e resolve previamente as referências para SHAs completos antes de invocar o diff.
 * @param {string} caminhoProjeto - Caminho do projeto no disco.
 * @param {object} [opcoes={}]
 * @param {string} [opcoes.baseRef] - Referência base (ex: 'HEAD~1', 'main').
 * @param {string} [opcoes.headRef] - Referência de destino (ex: 'HEAD').
 * @param {Function} [opcoes.runner=executarProcessoSeguro] - Injeção de executor para testes.
 * @returns {Promise<{ disponivel: boolean, ehRepositorioGit: boolean, diffBruto: string, arquivosDelta: Array<object>, erro: string | null }>}
 */
export async function obterDiffGit(caminhoProjeto, opcoes = {}) {
  const runner = opcoes.runner || executarProcessoSeguro;
  const raizAbsoluta = resolve(caminhoProjeto);

  // 1. Verifica se o Git existe e se o diretório é um repositório Git
  const checagemRepo = runner(
    'git',
    ['-C', raizAbsoluta, '-c', 'core.quotepath=false', 'rev-parse', '--is-inside-work-tree'],
    { timeout: 5000 }
  );

  if (checagemRepo.status === 'UNAVAILABLE') {
    return {
      disponivel: false,
      ehRepositorioGit: false,
      diffBruto: '',
      arquivosDelta: [],
      erro: 'Binário git não encontrado no PATH.'
    };
  }

  if (checagemRepo.status !== 'SUCCESS' || checagemRepo.exitCode !== 0) {
    return {
      disponivel: false,
      ehRepositorioGit: false,
      diffBruto: '',
      arquivosDelta: [],
      erro: 'O diretório informado não é um repositório Git válido.'
    };
  }

  // 2. Validação e Resolução Estrita de Refs para SHAs
  let baseSha = null;
  let headSha = null;

  if (opcoes.baseRef) {
    baseSha = resolverRefParaSha(raizAbsoluta, opcoes.baseRef, runner);
    if (!baseSha) {
      return {
        disponivel: false,
        ehRepositorioGit: true,
        diffBruto: '',
        arquivosDelta: [],
        erro: `Referência base inválida ou inexistente: '${opcoes.baseRef}'`
      };
    }
  }

  if (opcoes.headRef) {
    headSha = resolverRefParaSha(raizAbsoluta, opcoes.headRef, runner);
    if (!headSha) {
      return {
        disponivel: false,
        ehRepositorioGit: true,
        diffBruto: '',
        arquivosDelta: [],
        erro: `Referência head inválida ou inexistente: '${opcoes.headRef}'`
      };
    }
  }

  // 3. Monta os argumentos de diff de forma segura com SHAs resolvidos e separador '--'
  const argsDiff = [
    '-C', raizAbsoluta,
    '-c', 'core.quotepath=false',
    '--no-pager',
    'diff',
    '--no-ext-diff',
    '--no-textconv',
    '--no-color',
    '-U0'
  ];

  if (baseSha && headSha) {
    argsDiff.push(baseSha, headSha, '--');
  } else if (baseSha) {
    argsDiff.push(baseSha, '--');
  } else {
    const defaultHeadSha = resolverRefParaSha(raizAbsoluta, 'HEAD', runner);
    if (defaultHeadSha) {
      argsDiff.push(defaultHeadSha, '--');
    } else {
      argsDiff.push('HEAD', '--');
    }
  }

  const resDiff = runner('git', argsDiff, {
    timeout: opcoes.timeout || 15000
  });

  if (resDiff.status !== 'SUCCESS' || (resDiff.exitCode !== 0 && resDiff.exitCode !== 1)) {
    return {
      disponivel: false,
      ehRepositorioGit: true,
      diffBruto: '',
      arquivosDelta: [],
      erro: `Falha ao executar git diff: ${resDiff.stderr || 'Código de saída diferente de zero'}`
    };
  }

  const diffBruto = resDiff.stdout || '';
  const arquivosDelta = parsearGitDiff(diffBruto, raizAbsoluta);

  return {
    disponivel: true,
    ehRepositorioGit: true,
    diffBruto,
    arquivosDelta,
    erro: null
  };
}
