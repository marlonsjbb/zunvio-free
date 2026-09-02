import schemaContratoPublicacao from '../schema/zunvio-contract-v1.schema.json' with { type: 'json' };

export const VERSAO_CONTRATO_PUBLICACAO = '1.0.0';
export const SCHEMA_CONTRATO_PUBLICACAO = Object.freeze(schemaContratoPublicacao);

export const DIMENSOES_CONTRATO = Object.freeze([
  'objetivoProduto',
  'publicoUsuarios',
  'jornadasCriticas',
  'ambientePublicacao',
  'integracoesIndispensaveis',
  'dadosTratados',
  'requisitosSegurancaPrivacidade',
  'capacidadeDesempenho',
  'requisitosLegaisRegulatorios',
  'operacaoRollback',
  'criteriosInaceitaveis',
  'vinculoRelease'
]);

const MAPA_ALIAS_DIMENSOES = Object.freeze({
  objetivoProduto: ['objetivo_produto', 'productGoal', 'objetivo'],
  publicoUsuarios: ['publico_usuarios', 'targetAudience', 'publico'],
  jornadasCriticas: ['jornadas_criticas', 'criticalJourneys', 'jornadas'],
  ambientePublicacao: ['ambiente_publicacao', 'deploymentEnvironment', 'ambiente'],
  integracoesIndispensaveis: ['integracoes_indispensaveis', 'essentialIntegrations', 'integracoes'],
  dadosTratados: ['dados_tratados', 'dataClassification', 'dados'],
  requisitosSegurancaPrivacidade: ['requisitos_seguranca_privacidade', 'securityRequirements', 'seguranca'],
  capacidadeDesempenho: ['capacidade_desempenho', 'performanceRequirements', 'desempenho'],
  requisitosLegaisRegulatorios: ['requisitos_legais_regulatorios', 'complianceRequirements', 'conformidade'],
  operacaoRollback: ['operacao_rollback', 'operationalRollback', 'rollback'],
  criteriosInaceitaveis: ['criterios_inaceitaveis', 'unacceptableConditions', 'bloqueadoresInaceitaveis'],
  vinculoRelease: ['vinculo_release', 'releaseBinding', 'release', 'commitSha']
});

const CAMPOS_VERSAO = Object.freeze(['versaoContrato', 'contractVersion', 'versao']);
const CAMPOS_METADADOS = Object.freeze([
  'id',
  'cliente',
  'clienteId',
  'perfil',
  'excecoesAutorizadas',
  'permiteExcecao',
  'dimensoes'
]);
const CAMPOS_DIMENSAO = Object.freeze([
  ...DIMENSOES_CONTRATO,
  ...Object.values(MAPA_ALIAS_DIMENSOES).flat()
]);
const CAMPOS_TOPO_PERMITIDOS = new Set([
  ...CAMPOS_VERSAO,
  ...CAMPOS_METADADOS,
  ...CAMPOS_DIMENSAO
]);
const CAMPOS_DIMENSOES_PERMITIDOS = new Set(CAMPOS_DIMENSAO);

function nomeCampoSeguro(campo) {
  return /^[A-Za-z0-9_-]{1,80}$/.test(campo) ? campo : '[campo não exibido]';
}

function ehObjetoPlano(valor) {
  if (!valor || typeof valor !== 'object' || Array.isArray(valor)) return false;
  const proto = Object.getPrototypeOf(valor);
  return proto === Object.prototype || proto === null;
}

function congelarProfundamente(valor) {
  if (!valor || typeof valor !== 'object' || Object.isFrozen(valor)) return valor;
  for (const item of Object.values(valor)) congelarProfundamente(item);
  return Object.freeze(valor);
}

function normalizarDado(valor) {
  if (typeof valor === 'string') return valor.trim();
  if (valor === null || typeof valor !== 'object') return valor;
  if (Array.isArray(valor)) return valor.map(normalizarDado);
  return Object.fromEntries(
    Object.keys(valor)
      .sort()
      .map((chave) => [chave, normalizarDado(valor[chave])])
  );
}

function dadoJsonValido(valor, profundidade = 0) {
  if (profundidade > 20) return false;
  if (valor === null || typeof valor === 'boolean' || typeof valor === 'string') return true;
  if (typeof valor === 'number') return Number.isFinite(valor);
  if (Array.isArray(valor)) return valor.every((item) => dadoJsonValido(item, profundidade + 1));
  if (!ehObjetoPlano(valor)) return false;
  return Object.values(valor).every((item) => dadoJsonValido(item, profundidade + 1));
}

function contemInformacao(valor) {
  if (typeof valor === 'string') return valor.trim().length > 0;
  if (typeof valor === 'number' || typeof valor === 'boolean') return true;
  if (Array.isArray(valor)) return valor.some(contemInformacao);
  if (ehObjetoPlano(valor)) return Object.values(valor).some(contemInformacao);
  return false;
}

function valorDimensaoPreenchido(valor) {
  if (!dadoJsonValido(valor)) return false;
  if (typeof valor !== 'string' && !Array.isArray(valor) && !ehObjetoPlano(valor)) return false;
  return contemInformacao(valor);
}

function extrairValorDimensao(objeto, dimensaoPrincipal, erros) {
  const candidatos = [dimensaoPrincipal, ...(MAPA_ALIAS_DIMENSOES[dimensaoPrincipal] || [])]
    .filter((campo) => Object.hasOwn(objeto, campo));

  if (candidatos.length > 1) {
    erros.push(`Campo ambíguo: "dimensoes.${dimensaoPrincipal}" foi informado por mais de uma chave (${candidatos.sort().join(', ')}).`);
    return undefined;
  }
  return candidatos.length === 1 ? objeto[candidatos[0]] : undefined;
}

function coberturaDasDimensoes(dimensoesPresentes, dimensoesFaltantes) {
  const total = DIMENSOES_CONTRATO.length;
  return Object.freeze({
    comprovadas: Object.freeze([...dimensoesPresentes]),
    naoComprovadas: Object.freeze([...dimensoesFaltantes]),
    total,
    percentual: Math.floor((dimensoesPresentes.length * 100) / total)
  });
}

function validarMetadados(contrato, erros) {
  for (const campo of ['id', 'cliente', 'clienteId', 'perfil']) {
    if (Object.hasOwn(contrato, campo) && (typeof contrato[campo] !== 'string' || !contrato[campo].trim())) {
      erros.push(`Tipo inválido em "${campo}": esperado string não vazia.`);
    }
  }

  if (Object.hasOwn(contrato, 'excecoesAutorizadas')) {
    const valor = contrato.excecoesAutorizadas;
    if (!Array.isArray(valor) || valor.some((item) => typeof item !== 'string' || !item.trim())) {
      erros.push('Tipo inválido em "excecoesAutorizadas": esperado array de strings não vazias.');
    }
  }

  if (Object.hasOwn(contrato, 'permiteExcecao')) {
    const valor = contrato.permiteExcecao;
    if (!ehObjetoPlano(valor) || Object.values(valor).some((item) => typeof item !== 'boolean')) {
      erros.push('Tipo inválido em "permiteExcecao": esperado objeto com valores booleanos.');
    }
  }
}

/**
 * Valida e normaliza deterministicamente as 12 dimensões do Contrato de Publicação v1.
 * O schema formal é estrito; o layout plano legado e aliases conhecidos são aceitos e
 * normalizados para preservar compatibilidade sem aceitar campos silenciosamente.
 */
export function validarContratoPublicacao(contrato, opcoesContexto = {}) {
  const erros = [];

  if (!ehObjetoPlano(contrato)) {
    const dimensoesFaltantes = [...DIMENSOES_CONTRATO];
    return Object.freeze({
      valido: false,
      confiavel: false,
      suficiente: false,
      erros: Object.freeze(['Contrato de publicação inválido: esperado objeto JSON não nulo.']),
      dimensoesPresentes: Object.freeze([]),
      dimensoesFaltantes: Object.freeze(dimensoesFaltantes),
      dimensoesNormalizadas: Object.freeze({}),
      coberturaContexto: coberturaDasDimensoes([], dimensoesFaltantes),
      contratoNormalizado: null
    });
  }

  const camposDesconhecidos = Object.keys(contrato)
    .filter((campo) => !CAMPOS_TOPO_PERMITIDOS.has(campo))
    .sort();
  for (const campo of camposDesconhecidos) {
    erros.push(`Campo desconhecido: "${nomeCampoSeguro(campo)}".`);
  }

  const camposVersaoPresentes = CAMPOS_VERSAO.filter((campo) => Object.hasOwn(contrato, campo));
  if (camposVersaoPresentes.length === 0) {
    erros.push('Campo obrigatório ausente: "versaoContrato".');
  } else if (camposVersaoPresentes.length > 1) {
    erros.push(`Campo ambíguo: versão informada por mais de uma chave (${camposVersaoPresentes.sort().join(', ')}).`);
  }
  const versaoContrato = camposVersaoPresentes.length === 1 ? contrato[camposVersaoPresentes[0]] : undefined;
  if (versaoContrato !== undefined && typeof versaoContrato !== 'string') {
    erros.push('Tipo inválido em "versaoContrato": esperado string.');
  } else if (typeof versaoContrato === 'string' && versaoContrato !== VERSAO_CONTRATO_PUBLICACAO) {
    erros.push(`Versão incompatível em "versaoContrato": suportada "${VERSAO_CONTRATO_PUBLICACAO}".`);
  }

  validarMetadados(contrato, erros);

  const usaDimensoesAninhadas = Object.hasOwn(contrato, 'dimensoes');
  const dimensoesNoTopo = CAMPOS_DIMENSAO.filter((campo) => Object.hasOwn(contrato, campo));
  if (usaDimensoesAninhadas && dimensoesNoTopo.length > 0) {
    erros.push('Layout ambíguo: use "dimensoes" ou campos de dimensão no topo, nunca ambos.');
  }

  const dimensoesObj = usaDimensoesAninhadas ? contrato.dimensoes : contrato;
  if (usaDimensoesAninhadas && !ehObjetoPlano(dimensoesObj)) {
    erros.push('Tipo inválido em "dimensoes": esperado objeto.');
  }

  if (ehObjetoPlano(dimensoesObj) && usaDimensoesAninhadas) {
    const desconhecidos = Object.keys(dimensoesObj)
      .filter((campo) => !CAMPOS_DIMENSOES_PERMITIDOS.has(campo))
      .sort();
    for (const campo of desconhecidos) {
      erros.push(`Campo desconhecido: "dimensoes.${nomeCampoSeguro(campo)}".`);
    }
  }

  const dimensoesPresentes = [];
  const dimensoesFaltantes = [];
  const dimensoesNormalizadas = {};
  for (const dimensao of DIMENSOES_CONTRATO) {
    const valor = ehObjetoPlano(dimensoesObj)
      ? extrairValorDimensao(dimensoesObj, dimensao, erros)
      : undefined;
    if (valor === undefined || valor === null || valor === '' || (Array.isArray(valor) && valor.length === 0)) {
      dimensoesFaltantes.push(dimensao);
      continue;
    }
    if (!valorDimensaoPreenchido(valor)) {
      erros.push(`Tipo inválido em "dimensoes.${dimensao}": esperado string, array ou objeto JSON não vazio.`);
      dimensoesFaltantes.push(dimensao);
      continue;
    }
    dimensoesPresentes.push(dimensao);
    dimensoesNormalizadas[dimensao] = normalizarDado(valor);
  }

  if (dimensoesFaltantes.length > 0) {
    erros.push(`Contrato insuficiente: campos mínimos não comprovados [${dimensoesFaltantes.join(', ')}].`);
  }

  const vinculoDeclarado = dimensoesNormalizadas.vinculoRelease;
  let commitDeclarado = ehObjetoPlano(vinculoDeclarado)
    ? (vinculoDeclarado.commitSha || vinculoDeclarado.sha || vinculoDeclarado.commit)
    : (typeof vinculoDeclarado === 'string' && /^[0-9a-f]{40}$/i.test(vinculoDeclarado) ? vinculoDeclarado : null);

  if (commitDeclarado !== null && commitDeclarado !== undefined && (
    typeof commitDeclarado !== 'string' || !/^[0-9a-f]{40}$/i.test(commitDeclarado)
  )) {
    erros.push('Formato inválido em "dimensoes.vinculoRelease.commitSha": esperado SHA Git hexadecimal de 40 caracteres.');
    commitDeclarado = null;
  }

  if (opcoesContexto.commitReal && commitDeclarado && typeof commitDeclarado === 'string') {
    if (commitDeclarado.toLowerCase() !== opcoesContexto.commitReal.toLowerCase()) {
      erros.push(`Divergência em "dimensoes.vinculoRelease": commit declarado (${commitDeclarado}) difere do commit analisado (${opcoesContexto.commitReal}).`);
    }
  }

  const suficiente = dimensoesFaltantes.length === 0;
  const valido = erros.length === 0;
  congelarProfundamente(dimensoesNormalizadas);
  const contratoNormalizado = valido ? congelarProfundamente({
    versaoContrato: VERSAO_CONTRATO_PUBLICACAO,
    ...(typeof contrato.id === 'string' ? { id: contrato.id.trim() } : {}),
    ...(typeof (contrato.cliente || contrato.clienteId) === 'string'
      ? { cliente: (contrato.cliente || contrato.clienteId).trim() }
      : {}),
    ...(typeof contrato.perfil === 'string' ? { perfil: contrato.perfil.trim() } : {}),
    excecoesAutorizadas: Array.isArray(contrato.excecoesAutorizadas)
      ? [...new Set(contrato.excecoesAutorizadas.map((item) => item.trim()))].sort()
      : [],
    permiteExcecao: ehObjetoPlano(contrato.permiteExcecao)
      ? Object.fromEntries(Object.entries(contrato.permiteExcecao).sort(([a], [b]) => a.localeCompare(b)))
      : {},
    dimensoes: dimensoesNormalizadas
  }) : null;

  return Object.freeze({
    valido,
    confiavel: true,
    suficiente,
    erros: Object.freeze(erros),
    dimensoesPresentes: Object.freeze(dimensoesPresentes),
    dimensoesFaltantes: Object.freeze(dimensoesFaltantes),
    dimensoesNormalizadas,
    coberturaContexto: coberturaDasDimensoes(dimensoesPresentes, dimensoesFaltantes),
    contratoNormalizado
  });
}
