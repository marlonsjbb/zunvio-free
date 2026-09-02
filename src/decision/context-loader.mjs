import { existsSync, lstatSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute, join, relative, resolve } from 'node:path';
import { resolverRefParaSha } from '../delta/diff-parser.mjs';
import {
  DIMENSOES_CONTRATO,
  VERSAO_CONTRATO_PUBLICACAO,
  validarContratoPublicacao
} from './contract-validator.mjs';

const NOME_CONTRATO = 'zunvio-contract.json';
const LIMITE_CONTRATO_BYTES = 1024 * 1024;

/**
 * Tenta carregar e parsear um arquivo JSON de forma segura.
 * @param {string} caminhoCompleto
 * @returns {object | null}
 */
export function carregarJsonSeguro(caminhoCompleto) {
  if (!caminhoCompleto || !existsSync(caminhoCompleto)) return null;
  try {
    const conteudo = readFileSync(caminhoCompleto, 'utf8');
    return JSON.parse(conteudo);
  } catch {
    return null;
  }
}

/**
 * Determina se um arquivo reside dentro do diretório-alvo não confiável.
 * @param {string} caminhoArquivo
 * @param {string} targetDir
 * @returns {boolean}
 */
function estaDentroDoAlvo(caminhoArquivo, targetDir) {
  try {
    const targetReal = realpathSync(targetDir);
    const arquivoReal = realpathSync(caminhoArquivo);
    const rel = relative(targetReal, arquivoReal);
    return !rel.startsWith('..') && !isAbsolute(rel);
  } catch {
    return false;
  }
}

function caminhoDentroDoAlvo(caminhoArquivo, targetReal) {
  const rel = relative(targetReal, caminhoArquivo);
  return rel === '' || (!rel.startsWith('..') && !isAbsolute(rel));
}

function carregarContratoJson(caminhoCompleto, { targetReal, permitirForaDoAlvo = false } = {}) {
  try {
    const infoLink = lstatSync(caminhoCompleto);
    if (infoLink.isSymbolicLink()) {
      return { erro: 'Contrato rejeitado: symlink não é permitido para leitura de contrato.' };
    }
    const caminhoReal = realpathSync(caminhoCompleto);
    if (!permitirForaDoAlvo && targetReal && !caminhoDentroDoAlvo(caminhoReal, targetReal)) {
      return { erro: 'Contrato rejeitado: symlink intermediário escapa do workspace analisado.' };
    }
    const info = statSync(caminhoCompleto);
    if (!info.isFile()) {
      return { erro: 'Contrato rejeitado: o caminho não aponta para arquivo regular.' };
    }
    if (info.size > LIMITE_CONTRATO_BYTES) {
      return { erro: `Contrato rejeitado: arquivo excede o limite de ${LIMITE_CONTRATO_BYTES} bytes.` };
    }
    return { valor: JSON.parse(readFileSync(caminhoCompleto, 'utf8')) };
  } catch (erro) {
    if (erro?.name === 'SyntaxError') {
      return { erro: 'Contrato inválido: JSON malformado.' };
    }
    return { erro: 'Contrato indisponível: não foi possível ler o arquivo solicitado.' };
  }
}

function resultadoComErroContrato(erro, origem, { fornecido = true } = {}) {
  const dimensoesFaltantes = Object.freeze([...DIMENSOES_CONTRATO]);
  return Object.freeze({
    valido: false,
    confiavel: false,
    suficiente: false,
    versaoContrato: VERSAO_CONTRATO_PUBLICACAO,
    fornecido,
    origem,
    autorizaExcecoes: false,
    erros: Object.freeze([erro]),
    dimensoesPresentes: Object.freeze([]),
    dimensoesFaltantes,
    coberturaContexto: Object.freeze({
      comprovadas: Object.freeze([]),
      naoComprovadas: dimensoesFaltantes,
      total: DIMENSOES_CONTRATO.length,
      percentual: 0
    }),
    contratoNormalizado: null,
    motivo: erro
  });
}

function finalizarContrato(validacao, { origem, fornecido, autorizaExcecoes, descobertaSegura = false }) {
  const normalizado = validacao.contratoNormalizado || {};
  return Object.freeze({
    ...normalizado,
    ...validacao,
    confiavel: validacao.valido,
    origem,
    fornecido,
    autorizaExcecoes: Boolean(autorizaExcecoes && validacao.valido && validacao.suficiente),
    descobertaSegura,
    motivo: validacao.valido
      ? 'Contrato de publicação validado e normalizado.'
      : validacao.erros[validacao.erros.length - 1]
  });
}

function descobrirContratoSeguro(contexto) {
  const dimensoes = {};
  if (typeof contexto.commitReal === 'string' && /^[0-9a-f]{40}$/i.test(contexto.commitReal)) {
    dimensoes.vinculoRelease = Object.freeze({ commitSha: contexto.commitReal.toLowerCase() });
  }
  return {
    versaoContrato: VERSAO_CONTRATO_PUBLICACAO,
    dimensoes
  };
}

/**
 * Resolve o contrato de publicação para o projeto analisado.
 * Um arquivo local é conteúdo contextual não confiável, mas pode ser validado e usado como dado.
 * Apenas contrato externo explicitamente autorizado pode conceder exceções a portões.
 * @param {string} targetDir
 * @param {object} [opcoes={}]
 * @param {object} [contexto={}]
 * @returns {object}
 */
export function resolverContratoPublicacao(targetDir, opcoes = {}, contexto = {}) {
  const targetReal = realpathSync(targetDir);

  if (opcoes.contrato && typeof opcoes.contrato === 'object') {
    const {
      origem: origemDeclarada,
      naoConfiavel: _naoConfiavel,
      autorizaExcecoes: _autorizaExcecoes,
      ...contratoBruto
    } = opcoes.contrato;
    const interno = origemDeclarada === 'internal-target';
    return finalizarContrato(validarContratoPublicacao(contratoBruto, contexto), {
      origem: interno ? 'internal-target' : 'inline-external',
      fornecido: true,
      autorizaExcecoes: !interno
    });
  }

  let caminhoContrato;
  let origem;
  let explicitamenteExterno = false;
  if (opcoes.caminhoContrato !== null && opcoes.caminhoContrato !== undefined) {
    if (typeof opcoes.caminhoContrato !== 'string' || !opcoes.caminhoContrato.trim()) {
      return resultadoComErroContrato('Caminho de contrato inválido: esperado string não vazia.', 'explicit-file');
    }
    const informado = opcoes.caminhoContrato.trim();
    if (isAbsolute(informado)) {
      caminhoContrato = resolve(informado);
      let caminhoClassificacao = caminhoContrato;
      try {
        caminhoClassificacao = realpathSync(caminhoContrato);
      } catch {}
      explicitamenteExterno = !caminhoDentroDoAlvo(caminhoClassificacao, targetReal);
    } else {
      caminhoContrato = resolve(targetReal, informado);
      if (!caminhoDentroDoAlvo(caminhoContrato, targetReal)) {
        return resultadoComErroContrato('Contrato rejeitado: caminho relativo escapa do workspace analisado.', 'explicit-file');
      }
    }
    origem = explicitamenteExterno ? 'external-file' : 'internal-target';
  } else {
    caminhoContrato = join(targetReal, NOME_CONTRATO);
    origem = 'internal-target';
    if (!existsSync(caminhoContrato)) {
      const descoberto = descobrirContratoSeguro(contexto);
      return finalizarContrato(validarContratoPublicacao(descoberto, contexto), {
        origem: 'safe-discovery',
        fornecido: false,
        autorizaExcecoes: false,
        descobertaSegura: true
      });
    }
  }

  const carregamento = carregarContratoJson(caminhoContrato, {
    targetReal,
    permitirForaDoAlvo: explicitamenteExterno
  });
  if (carregamento.erro) {
    return resultadoComErroContrato(carregamento.erro, origem);
  }

  return finalizarContrato(validarContratoPublicacao(carregamento.valor, contexto), {
    origem,
    fornecido: true,
    autorizaExcecoes: explicitamenteExterno
  });
}

/**
 * Resolve e valida as evidências externas e proveniência criptográfica do release.
 * @param {string} targetDir
 * @param {object} [opcoes={}]
 * @param {string | null} [commitReal=null]
 * @returns {object}
 */
export function resolverEvidenciasProjeto(targetDir, opcoes = {}, commitReal = null) {
  let evidencias = {};
  let ehInterno = false;

  if (opcoes.evidencias && typeof opcoes.evidencias === 'object') {
    evidencias = { ...opcoes.evidencias };
    ehInterno = Boolean(opcoes.evidencias.origem === 'internal-target');
  } else if (opcoes.caminhoEvidencias) {
    const caminhoResolvido = resolve(opcoes.caminhoEvidencias);
    const carregadas = carregarJsonSeguro(caminhoResolvido);
    if (carregadas) {
      evidencias = { ...carregadas };
    }
    ehInterno = estaDentroDoAlvo(caminhoResolvido, targetDir);
  }

  // Se as evidências vierem de arquivo interno do projeto, não podem comprovar funcionamento ou atestar publicação
  if (ehInterno) {
    evidencias = {
      ...evidencias,
      origem: 'internal-target',
      naoConfiavel: true,
      funcionamento: {
        disponivel: false,
        aprovado: false,
        descricao: 'Evidência interna do projeto não confiável; requer atestação ou execução externa controlada.'
      }
    };
  }

  // Resolução e validação estrita da Proveniência Git
  const shaDetectado = commitReal || (function () {
    try {
      return resolverRefParaSha(targetDir, 'HEAD');
    } catch {
      return null;
    }
  })();

  if (evidencias.proveniencia) {
    const provDeclarada = evidencias.proveniencia;
    const shaDeclarado = provDeclarada.commitSha || provDeclarada.sha || provDeclarada.commit;

    if (shaDeclarado) {
      if (!shaDetectado) {
        evidencias.proveniencia = {
          disponivel: true,
          aprovado: false,
          divergente: true,
          descricao: `Proveniência inválida: alvo não é repositório Git auditável para comprovar o commit declarado (${shaDeclarado}).`
        };
      } else if (shaDeclarado.toLowerCase() !== shaDetectado.toLowerCase()) {
        evidencias.proveniencia = {
          disponivel: true,
          aprovado: false,
          divergente: true,
          commitShaDeclarado: shaDeclarado,
          commitShaReal: shaDetectado,
          descricao: `Falsificação ou desvio de proveniência: commit declarado (${shaDeclarado}) diverge do commit real analisado (${shaDetectado}).`
        };
      } else {
        evidencias.proveniencia = {
          disponivel: true,
          aprovado: true,
          commitSha: shaDetectado,
          descricao: `Vínculo de release auditado e comprovado: commit ${shaDetectado}`
        };
      }
    }
  } else if (shaDetectado) {
    // Autodescoberta legítima do commit real do repositório local
    evidencias.proveniencia = {
      disponivel: true,
      aprovado: true,
      commitSha: shaDetectado,
      descricao: `Vínculo de release auditado via Git local: commit ${shaDetectado}`
    };
  }

  return evidencias;
}
