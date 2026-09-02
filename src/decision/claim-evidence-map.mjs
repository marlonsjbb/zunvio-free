import schemaClaimEvidenceMap from '../schema/claim-evidence-map-v1.schema.json' with { type: 'json' };
import { serializarJsonCanonico } from '../utils/canonical-json.mjs';
import { redigirTexto } from '../utils/redactor.mjs';
import { DIMENSOES_CONTRATO } from './contract-validator.mjs';

export const VERSAO_MAPA_CLAIM_EVIDENCE = '1.0.0';
export const SCHEMA_MAPA_CLAIM_EVIDENCE = Object.freeze(schemaClaimEvidenceMap);

const STATUS = Object.freeze({
  ATENDE: 'ATENDE',
  NAO_ATENDE: 'NAO_ATENDE',
  NAO_COMPROVADO: 'NAO_COMPROVADO'
});

const FONTES_CONCLUSAO = new Set([
  'NO_DECLARED_CLAIM',
  'DECLARATION_ONLY',
  'EXTERNAL_CLAIM_EVIDENCE',
  'GIT_PROVENANCE',
  'UNTRUSTED_EVIDENCE'
]);

const PADROES_HOSTIS = [
  /<\/?(?:script|iframe|object|embed)\b/i,
  /\$\(/,
  /`/,
  /\$\{/,
  /(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|prior|system)\s+(?:instructions?|prompts?)/i,
  /(?:execute|run)\s+(?:this\s+)?(?:command|shell|code)/i,
  /\u0000/
];

function ehObjetoPlano(valor) {
  if (!valor || typeof valor !== 'object' || Array.isArray(valor)) return false;
  const proto = Object.getPrototypeOf(valor);
  return proto === Object.prototype || proto === null;
}

function temChavesExatas(valor, chaves) {
  return ehObjetoPlano(valor)
    && serializarJsonCanonico(Object.keys(valor).sort()) === serializarJsonCanonico([...chaves].sort());
}

function textoLimitadoOuNulo(valor, maximo) {
  return valor === null
    || (typeof valor === 'string' && Array.from(valor).length <= maximo);
}

function congelarProfundamente(valor) {
  if (!valor || typeof valor !== 'object' || Object.isFrozen(valor)) return valor;
  for (const item of Object.values(valor)) congelarProfundamente(item);
  return Object.freeze(valor);
}

function ehJsonSeguro(valor, profundidade = 0) {
  if (profundidade > 20) return false;
  if (valor === null || typeof valor === 'boolean' || typeof valor === 'string') return true;
  if (typeof valor === 'number') return Number.isFinite(valor);
  if (Array.isArray(valor)) return valor.every((item) => ehJsonSeguro(item, profundidade + 1));
  if (!ehObjetoPlano(valor)) return false;
  return Object.values(valor).every((item) => ehJsonSeguro(item, profundidade + 1));
}

function normalizarValor(valor) {
  if (typeof valor === 'string') return valor.trim();
  if (valor === null || typeof valor !== 'object') return valor;
  if (Array.isArray(valor)) return valor.map(normalizarValor);
  return Object.fromEntries(
    Object.keys(valor)
      .sort()
      .map((chave) => [chave, normalizarValor(valor[chave])])
  );
}

function limitarTexto(texto, maximo = 160) {
  return Array.from(texto).slice(0, maximo).join('');
}

function resumoSeguro(valor, { dimensao } = {}) {
  if (dimensao === 'vinculoRelease') {
    const sha = extrairSha(valor);
    if (sha) return `commit ${sha}`;
  }

  if (typeof valor === 'string') {
    if (PADROES_HOSTIS.some((padrao) => padrao.test(valor))) return '[CONTEÚDO OMITIDO]';
    const redigido = redigirTexto(valor).replace(/[\r\n\t]+/g, ' ').replace(/\s+/g, ' ').trim();
    if (redigido.includes('[REDACTED]')) return '[REDACTED]';
    return limitarTexto(redigido);
  }
  if (Array.isArray(valor)) return `lista declarada/observada (${valor.length} itens)`;
  if (ehObjetoPlano(valor)) return `objeto declarado/observado (${Object.keys(valor).length} campos)`;
  if (typeof valor === 'boolean') return valor ? 'booleano verdadeiro' : 'booleano falso';
  if (typeof valor === 'number' && Number.isFinite(valor)) return 'valor numérico declarado/observado';
  return null;
}

function extrairSha(valor) {
  const candidato = ehObjetoPlano(valor)
    ? (valor.commitSha || valor.sha || valor.commit)
    : valor;
  return typeof candidato === 'string' && /^[a-f0-9]{40}$/i.test(candidato.trim())
    ? candidato.trim().toLowerCase()
    : null;
}

function extrairShaGit(proveniencia) {
  if (!ehObjetoPlano(proveniencia)) return null;
  return extrairSha(
    proveniencia.commitShaReal || proveniencia.commitSha || proveniencia.shaReal || proveniencia.sha
  );
}

function resultadoNaoComprovado({ dimensao, declarado, resumoClaim, fonte, minimo, evidencia = null }) {
  return {
    dimension: dimensao,
    claim: { declared: declarado, summary: resumoClaim },
    evidence: evidencia || { observed: false, reference: null, summary: null },
    status: STATUS.NAO_COMPROVADO,
    coverage: 0,
    conclusionSource: fonte,
    divergence: null,
    minimumMissing: minimo
  };
}

function mapearDimensao(dimensao, contrato, evidencias) {
  const dimensoes = ehObjetoPlano(contrato?.dimensoesNormalizadas)
    ? contrato.dimensoesNormalizadas
    : {};
  const declarado = contrato?.fornecido === true && Object.hasOwn(dimensoes, dimensao);
  const valorDeclarado = declarado ? dimensoes[dimensao] : undefined;
  const resumoClaim = declarado ? resumoSeguro(valorDeclarado, { dimensao }) : null;

  if (!declarado) {
    return resultadoNaoComprovado({
      dimensao,
      declarado: false,
      resumoClaim: null,
      fonte: 'NO_DECLARED_CLAIM',
      minimo: 'Declarar a dimensão no Contrato de Publicação v1.'
    });
  }

  if (dimensao === 'vinculoRelease') {
    const shaDeclarado = extrairSha(valorDeclarado);
    const shaObservado = extrairShaGit(evidencias?.proveniencia);
    if (shaDeclarado && shaObservado) {
      const divergence = shaDeclarado !== shaObservado;
      return {
        dimension: dimensao,
        claim: { declared: true, summary: resumoClaim },
        evidence: { observed: true, reference: 'git:HEAD', summary: `commit ${shaObservado}` },
        status: divergence ? STATUS.NAO_ATENDE : STATUS.ATENDE,
        coverage: 100,
        conclusionSource: 'GIT_PROVENANCE',
        divergence,
        minimumMissing: null
      };
    }
  }

  const evidenciaClaim = ehObjetoPlano(evidencias?.claims)
    ? evidencias.claims[dimensao]
    : null;
  if (evidencias?.naoConfiavel === true && evidenciaClaim !== undefined && evidenciaClaim !== null) {
    return resultadoNaoComprovado({
      dimensao,
      declarado: true,
      resumoClaim,
      fonte: 'UNTRUSTED_EVIDENCE',
      minimo: 'Fornecer evidência externa controlada para a dimensão.'
    });
  }
  if (!ehObjetoPlano(evidenciaClaim) || evidenciaClaim.disponivel !== true) {
    return resultadoNaoComprovado({
      dimensao,
      declarado: true,
      resumoClaim,
      fonte: 'DECLARATION_ONLY',
      minimo: 'Fornecer evidência externa aprovada com valorObservado para a dimensão.'
    });
  }

  const temValorObservado = Object.hasOwn(evidenciaClaim, 'valorObservado')
    && ehJsonSeguro(evidenciaClaim.valorObservado);
  const evidencia = {
    observed: temValorObservado || evidenciaClaim.aprovado === false,
    reference: `claims.${dimensao}`,
    summary: temValorObservado
      ? resumoSeguro(evidenciaClaim.valorObservado, { dimensao })
      : (evidenciaClaim.aprovado === false ? 'Evidência externa reprovada.' : null)
  };

  if (evidenciaClaim.aprovado === false) {
    const divergence = temValorObservado
      ? serializarJsonCanonico(normalizarValor(valorDeclarado))
        !== serializarJsonCanonico(normalizarValor(evidenciaClaim.valorObservado))
      : null;
    return {
      dimension: dimensao,
      claim: { declared: true, summary: resumoClaim },
      evidence: evidencia,
      status: STATUS.NAO_ATENDE,
      coverage: 100,
      conclusionSource: 'EXTERNAL_CLAIM_EVIDENCE',
      divergence,
      minimumMissing: null
    };
  }

  if (evidenciaClaim.aprovado !== true || !temValorObservado) {
    return resultadoNaoComprovado({
      dimensao,
      declarado: true,
      resumoClaim,
      fonte: 'DECLARATION_ONLY',
      minimo: 'Informar valorObservado em uma evidência externa aprovada.',
      evidencia
    });
  }

  const divergence = serializarJsonCanonico(normalizarValor(valorDeclarado))
    !== serializarJsonCanonico(normalizarValor(evidenciaClaim.valorObservado));
  return {
    dimension: dimensao,
    claim: { declared: true, summary: resumoClaim },
    evidence: evidencia,
    status: divergence ? STATUS.NAO_ATENDE : STATUS.ATENDE,
    coverage: 100,
    conclusionSource: 'EXTERNAL_CLAIM_EVIDENCE',
    divergence,
    minimumMissing: null
  };
}

export function construirMapaClaimEvidence({ contrato = {}, evidencias = {} } = {}) {
  const claims = DIMENSOES_CONTRATO.map((dimensao) => mapearDimensao(dimensao, contrato, evidencias));
  const summary = {
    atende: claims.filter((item) => item.status === STATUS.ATENDE).length,
    naoAtende: claims.filter((item) => item.status === STATUS.NAO_ATENDE).length,
    naoComprovado: claims.filter((item) => item.status === STATUS.NAO_COMPROVADO).length
  };
  const conclusivos = summary.atende + summary.naoAtende;
  const mapa = {
    schemaVersion: VERSAO_MAPA_CLAIM_EVIDENCE,
    totalClaims: DIMENSOES_CONTRATO.length,
    coverage: Math.floor((conclusivos * 100) / DIMENSOES_CONTRATO.length),
    summary,
    claims
  };
  const validacao = validarMapaClaimEvidence(mapa);
  if (!validacao.valido) {
    throw new Error(`Claim-to-Evidence Map inválido: ${validacao.erros.join('; ')}`);
  }
  return congelarProfundamente(mapa);
}

export function validarMapaClaimEvidence(mapa) {
  const erros = [];
  if (!ehObjetoPlano(mapa)) return { valido: false, erros: ['Mapa deve ser um objeto não nulo.'] };
  if (!temChavesExatas(mapa, ['schemaVersion', 'totalClaims', 'coverage', 'summary', 'claims'])) {
    erros.push('Mapa deve conter somente os campos definidos pelo schema v1.');
  }
  if (mapa.schemaVersion !== VERSAO_MAPA_CLAIM_EVIDENCE) erros.push('schemaVersion inválida.');
  if (mapa.totalClaims !== DIMENSOES_CONTRATO.length) erros.push('totalClaims deve ser 12.');
  if (!Number.isInteger(mapa.coverage) || mapa.coverage < 0 || mapa.coverage > 100) erros.push('coverage deve ser inteiro entre 0 e 100.');
  if (!Array.isArray(mapa.claims) || mapa.claims.length !== DIMENSOES_CONTRATO.length) {
    erros.push('claims deve conter exatamente as 12 dimensões canônicas.');
    return { valido: false, erros };
  }

  const contagem = { atende: 0, naoAtende: 0, naoComprovado: 0 };
  if (!temChavesExatas(mapa.summary, ['atende', 'naoAtende', 'naoComprovado'])
    || !['atende', 'naoAtende', 'naoComprovado'].every((chave) => (
      Number.isInteger(mapa.summary[chave]) && mapa.summary[chave] >= 0 && mapa.summary[chave] <= 12
    ))) {
    erros.push('summary deve conter somente as três contagens inteiras do schema v1.');
  }
  for (const [indice, item] of mapa.claims.entries()) {
    if (!ehObjetoPlano(item)) {
      erros.push(`claims[${indice}] deve ser objeto.`);
      continue;
    }
    if (!temChavesExatas(item, [
      'dimension',
      'claim',
      'evidence',
      'status',
      'coverage',
      'conclusionSource',
      'divergence',
      'minimumMissing'
    ])) erros.push(`claims[${indice}] contém campos fora do schema v1.`);
    if (item.dimension !== DIMENSOES_CONTRATO[indice]) erros.push(`claims[${indice}] está fora da ordem canônica.`);
    if (!temChavesExatas(item.claim, ['declared', 'summary'])
      || typeof item.claim.declared !== 'boolean'
      || !textoLimitadoOuNulo(item.claim.summary, 160)) {
      erros.push(`claims[${indice}].claim inválido.`);
    }
    if (!temChavesExatas(item.evidence, ['observed', 'reference', 'summary'])
      || typeof item.evidence.observed !== 'boolean'
      || !textoLimitadoOuNulo(item.evidence.reference, 80)
      || !textoLimitadoOuNulo(item.evidence.summary, 160)) {
      erros.push(`claims[${indice}].evidence inválido.`);
    }
    if (!Object.values(STATUS).includes(item.status)) erros.push(`claims[${indice}].status inválido.`);
    if (!FONTES_CONCLUSAO.has(item.conclusionSource)) erros.push(`claims[${indice}].conclusionSource inválida.`);
    if (!(typeof item.divergence === 'boolean' || item.divergence === null)) erros.push(`claims[${indice}].divergence inválida.`);
    if (!textoLimitadoOuNulo(item.minimumMissing, 200)) erros.push(`claims[${indice}].minimumMissing inválido.`);
    if (item.claim?.declared === false && (
      item.claim.summary !== null
      || item.status !== STATUS.NAO_COMPROVADO
      || item.conclusionSource !== 'NO_DECLARED_CLAIM'
    )) erros.push(`claims[${indice}] sem declaração deve falhar fechado.`);
    if (item.claim?.declared === true && (typeof item.claim.summary !== 'string' || !item.claim.summary)) {
      erros.push(`claims[${indice}] declarada exige resumo seguro.`);
    }
    if (item.evidence?.observed === true && (
      typeof item.evidence.reference !== 'string'
      || !item.evidence.reference
      || typeof item.evidence.summary !== 'string'
      || !item.evidence.summary
    )) erros.push(`claims[${indice}] com evidência observada exige referência e resumo seguros.`);
    if (item.divergence === true && item.status !== STATUS.NAO_ATENDE) {
      erros.push(`claims[${indice}] divergente deve usar NÃO ATENDE.`);
    }
    if (item.status === STATUS.NAO_COMPROVADO) {
      contagem.naoComprovado += 1;
      if (item.coverage !== 0 || !item.minimumMissing || item.divergence !== null) erros.push(`claims[${indice}] NÃO COMPROVADO exige coverage 0, divergence nula e minimumMissing.`);
      if (!['NO_DECLARED_CLAIM', 'DECLARATION_ONLY', 'UNTRUSTED_EVIDENCE'].includes(item.conclusionSource)) {
        erros.push(`claims[${indice}] NÃO COMPROVADO usa origem de conclusão inválida.`);
      }
    } else {
      if (item.status === STATUS.ATENDE) contagem.atende += 1;
      if (item.status === STATUS.NAO_ATENDE) contagem.naoAtende += 1;
      if (item.coverage !== 100 || item.minimumMissing !== null) erros.push(`claims[${indice}] conclusivo exige coverage 100 e minimumMissing nulo.`);
      if (!['EXTERNAL_CLAIM_EVIDENCE', 'GIT_PROVENANCE'].includes(item.conclusionSource)) {
        erros.push(`claims[${indice}] conclusivo usa origem de conclusão inválida.`);
      }
    }
  }

  if (!ehObjetoPlano(mapa.summary)
    || mapa.summary.atende !== contagem.atende
    || mapa.summary.naoAtende !== contagem.naoAtende
    || mapa.summary.naoComprovado !== contagem.naoComprovado) {
    erros.push('summary diverge das conclusões por claim.');
  }
  const coberturaEsperada = Math.floor(((contagem.atende + contagem.naoAtende) * 100) / DIMENSOES_CONTRATO.length);
  if (mapa.coverage !== coberturaEsperada) erros.push('coverage agregado diverge das coberturas por claim.');
  return { valido: erros.length === 0, erros };
}
