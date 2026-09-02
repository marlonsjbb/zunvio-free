/**
 * Extrai o módulo ou diretório raiz correspondente ao caminho do arquivo.
 * @param {string} caminho - Caminho relativo do arquivo.
 * @returns {string} Identificador do módulo/componente.
 */
export function extrairModulo(caminho) {
  if (!caminho || typeof caminho !== 'string') return '(raiz)';
  const partes = caminho.replace(/\\/g, '/').split('/');
  if (partes.length <= 1) return '(raiz)';
  // Se for 'src/algo', considera 'src/algo' como módulo
  if (partes[0] === 'src' && partes.length > 2) {
    return `${partes[0]}/${partes[1]}`;
  }
  return partes[0];
}

/**
 * Calcula o raio de impacto estrutural (Blast Radius) conservador do delta Git.
 * @param {Array<object>} arquivosDelta - Lista de arquivos do diff gerados por parsearGitDiff.
 * @returns {object} Métricas estruturadas de blast radius e pegada de risco.
 */
export function calcularBlastRadius(arquivosDelta = []) {
  if (!Array.isArray(arquivosDelta) || arquivosDelta.length === 0) {
    return Object.freeze({
      arquivosAfetados: 0,
      linhasAdicionadas: 0,
      linhasRemovidas: 0,
      totalChurn: 0,
      modulosAfetados: [],
      totalModulos: 0,
      arquivosBinarios: 0,
      pegadaMudanca: 'NENHUMA',
      rotuloRisco: 'BAIXO'
    });
  }

  let linhasAdicionadas = 0;
  let linhasRemovidas = 0;
  let arquivosBinarios = 0;
  const modulosSet = new Set();

  for (const arq of arquivosDelta) {
    linhasAdicionadas += arq.linhasAdicionadas || 0;
    linhasRemovidas += arq.linhasRemovidas || 0;
    if (arq.ehBinario) arquivosBinarios++;
    modulosSet.add(extrairModulo(arq.caminho));
  }

  const arquivosAfetados = arquivosDelta.length;
  const totalChurn = linhasAdicionadas + linhasRemovidas;
  const modulosAfetados = Array.from(modulosSet).sort();
  const totalModulos = modulosAfetados.length;

  // Classificação conservadora de pegada estrutural
  let pegadaMudanca = 'LOCALIZADA';
  if (arquivosAfetados > 5 || totalModulos > 2) {
    pegadaMudanca = 'TRANSVERSAL';
  } else if (arquivosAfetados > 2 || totalModulos > 1) {
    pegadaMudanca = 'MODULAR';
  }

  // Rótulo conservador de risco da mudança
  let rotuloRisco = 'BAIXO';
  if (totalChurn > 300 || pegadaMudanca === 'TRANSVERSAL') {
    rotuloRisco = 'ALTO';
  } else if (totalChurn > 50 || pegadaMudanca === 'MODULAR') {
    rotuloRisco = 'MEDIO';
  }

  return Object.freeze({
    arquivosAfetados,
    linhasAdicionadas,
    linhasRemovidas,
    totalChurn,
    modulosAfetados: Object.freeze(modulosAfetados),
    totalModulos,
    arquivosBinarios,
    pegadaMudanca,
    rotuloRisco
  });
}

/**
 * Verifica se um intervalo de linhas intercepta os intervalos de linhas tocados no diff.
 * @param {number} startLine
 * @param {number} endLine
 * @param {Array<{ inicio: number, fim: number }>} intervalosDelta
 * @returns {boolean}
 */
function linhaInterceptaDelta(startLine, endLine, intervalosDelta = []) {
  if (!Array.isArray(intervalosDelta) || intervalosDelta.length === 0) return false;
  for (const intervalo of intervalosDelta) {
    if (startLine <= intervalo.fim && endLine >= intervalo.inicio) {
      return true;
    }
  }
  return false;
}

/**
 * Indica se as coordenadas (arquivo + faixa de linha) de um achado descrevem a
 * versão **atual** do arquivo no working tree — e portanto podem ser correlacionadas
 * com o delta corrente — ou se pertencem a um commit do histórico Git.
 *
 * Um achado do Gitleaks varrido no histórico (`rawDetails.origem === 'historico'`)
 * tem `startLine`/`endLine` relativos ao arquivo **como estava no commit de origem**
 * (`rawDetails.commit`). Esse arquivo pode ter sido renomeado, movido, removido e
 * recriado, ou ter ganhado/perdido linhas antes daquela posição — então bater com o
 * número da linha que o diff de hoje toca é coincidência, não prova de que o segredo
 * foi (re)introduzido nesta versão.
 *
 * `working-tree` e `working-tree+historico` já foram confirmados contra o conteúdo de
 * `HEAD` por `deduplicarAchadosGitleaks` (fusão só com prova de igualdade de trecho),
 * logo suas coordenadas valem para o arquivo atual. Achados sem proveniência de
 * commit (ex.: Semgrep, que varre apenas o working tree) também descrevem a versão
 * atual.
 *
 * @param {object} achado
 * @returns {boolean}
 */
function coordenadasDaVersaoAtual(achado) {
  const raw = achado && achado.rawDetails ? achado.rawDetails : null;
  const origem = raw ? raw.origem : undefined;
  if (origem === 'historico') return false;
  if (origem === 'working-tree' || origem === 'working-tree+historico') return true;
  // Sem `origem` explícita: a presença de um commit indica coordenadas históricas;
  // caso contrário, é um achado de working tree (Semgrep, ou Gitleaks sem metadado
  // de proveniência).
  return !(raw && raw.commit);
}

/**
 * Correlaciona a lista de achados de segurança normalizados com os arquivos e linhas tocados pelo delta.
 *
 * A correlação só marca um achado como presente no delta (`deltaInfo.noDelta`, tag
 * `[NOVO NO DELTA]` na CLI) quando suas coordenadas descrevem a versão atual do
 * arquivo (ver `coordenadasDaVersaoAtual`). Um achado de histórico (`rawDetails.origem
 * === 'historico'`) nunca é considerado novo no delta por mera coincidência de
 * arquivo/linha, nem quando o arquivo aparece como `ADDED` (removido e recriado): as
 * coordenadas dele pertencem ao commit de origem, não ao arquivo de hoje. Nesses
 * casos ele é classificado conservadoramente como histórico (PER-207 / P2 Codex `e19efba`).
 *
 * @param {Array<object>} achados - Lista de achados normalizados do ZUNVIO.
 * @param {Array<object>} arquivosDelta - Lista de arquivos do diff.
 * @returns {{ achadosCorrelacionados: Array<object>, resumoDelta: object }}
 */
export function correlacionarAchadosComDelta(achados = [], arquivosDelta = []) {
  if (!Array.isArray(achados)) {
    return {
      achadosCorrelacionados: [],
      resumoDelta: { totalAchadosNoDelta: 0, totalAchadosNoArquivoModificado: 0, totalAchadosHistoricos: 0 }
    };
  }

  const mapaDelta = new Map();
  for (const arq of arquivosDelta || []) {
    if (arq && arq.caminho) {
      mapaDelta.set(arq.caminho.replace(/\\/g, '/'), arq);
    }
  }

  let totalAchadosNoDelta = 0;
  let totalAchadosNoArquivoModificado = 0;
  let totalAchadosHistoricos = 0;

  const achadosCorrelacionados = achados.map((achado) => {
    const caminhoNorm = (achado.filePath || '').replace(/\\/g, '/');
    const arqDelta = mapaDelta.get(caminhoNorm);
    const coordAtuais = coordenadasDaVersaoAtual(achado);

    let noDelta = false;
    let noArquivoModificado = false;

    // Só correlaciona com o delta o achado cujas coordenadas descrevem a versão
    // atual do arquivo. Achado de histórico carrega arquivo/linha do commit de
    // origem — coincidir com o path/linha do diff de hoje (inclusive um arquivo
    // `ADDED` por ter sido recriado) NÃO prova reintrodução nesta versão, então
    // ele fica classificado como histórico (PER-207 / P2 Codex `e19efba`).
    if (arqDelta && coordAtuais) {
      noArquivoModificado = true;
      if (arqDelta.tipo === 'ADDED') {
        noDelta = true;
      } else {
        noDelta = linhaInterceptaDelta(achado.startLine, achado.endLine, arqDelta.intervalosLinhas);
      }
    }

    if (noDelta) {
      totalAchadosNoDelta++;
    } else {
      totalAchadosHistoricos++;
    }

    if (noArquivoModificado) {
      totalAchadosNoArquivoModificado++;
    }

    return Object.freeze({
      ...achado,
      deltaInfo: Object.freeze({
        noDelta,
        noArquivoModificado,
        noHistorico: !noDelta
      })
    });
  });

  return Object.freeze({
    achadosCorrelacionados: Object.freeze(achadosCorrelacionados),
    resumoDelta: Object.freeze({
      totalAchadosNoDelta,
      totalAchadosNoArquivoModificado,
      totalAchadosHistoricos
    })
  });
}
