export const ESTADOS_PORTAO = Object.freeze({
  ATENDE: 'ATENDE',
  NAO_ATENDE: 'NAO_ATENDE',
  NAO_COMPROVADO: 'NAO_COMPROVADO',
  NAO_APLICAVEL: 'NAO_APLICAVEL'
});

export const SUBCAUSAS_NAO_COMPROVADO = Object.freeze({
  SEM_EVIDENCIA_DO_CLIENTE: 'SEM_EVIDENCIA_DO_CLIENTE',
  FORA_DE_COBERTURA_DO_MOTOR: 'FORA_DE_COBERTURA_DO_MOTOR',
  MOTOR_FALHOU: 'MOTOR_FALHOU'
});

// MASS-307: estados canônicos da decisão de publicação (terceiro estado INCONCLUSIVO).
// - PUBLICAR: avaliação obrigatória concluída, cobertura mínima atendida e nenhum bloqueador.
// - NAO_PUBLICAR: bloqueador material comprovado (achado, evidência reprovada,
//   divergência de proveniência ou integridade violada) — há prova de reprovação.
// - INCONCLUSIVO: sensor ausente, falha operacional, timeout, truncamento, cobertura
//   insuficiente, alvo fora de cobertura, evidência do cliente ausente ou integridade
//   não comprovada — NÃO há prova de reprovação, mas também não há prova de atendimento.
export const DECISAO_PUBLICACAO = Object.freeze({
  PUBLICAR: 'PUBLICAR',
  NAO_PUBLICAR: 'NAO_PUBLICAR',
  INCONCLUSIVO: 'INCONCLUSIVO'
});

export const CODIGO_DECISAO = Object.freeze({
  ACEITAR: 'ACEITAR',
  NAO_ACEITAR: 'NAO_ACEITAR',
  INCONCLUSIVO: 'INCONCLUSIVO'
});

// Mapeamento canônico decisão -> outcome selado no Evidence Pack (canonicalHash).
export const OUTCOME_CANONICO = Object.freeze({
  ACCEPT: 'ACCEPT',
  REJECT: 'REJECT',
  UNPROVEN: 'UNPROVEN'
});

// Peso total dos portões OBRIGATÓRIOS: segredos (25) + seguranca_estatica (25) +
// funcionamento (20) + integridade (10) + proveniencia_auditabilidade (10) = 90.
// PUBLICAR exige avaliação obrigatória conclusiva; abaixo disso a decisão é INCONCLUSIVO.
export const COBERTURA_MINIMA_PUBLICACAO = 90;

const SUBCAUSAS_VALIDAS = new Set(Object.values(SUBCAUSAS_NAO_COMPROVADO));

function validarJustificativaContextual(justificativa) {
  return typeof justificativa === 'string' && justificativa.trim().length >= 10;
}

function criarPortao({
  id,
  nome,
  peso,
  estado,
  motivo,
  evidencias = [],
  bloqueadores = [],
  obrigatorio = true,
  subcausa = null
}) {
  if (estado === ESTADOS_PORTAO.NAO_COMPROVADO && !SUBCAUSAS_VALIDAS.has(subcausa)) {
    throw new Error(`Portão NÃO COMPROVADO exige subcausa válida: ${id}`);
  }
  if (estado !== ESTADOS_PORTAO.NAO_COMPROVADO && subcausa !== null) {
    throw new Error(`Subcausa só pode ser usada em portão NÃO COMPROVADO: ${id}`);
  }

  const portao = {
    id,
    nome,
    peso,
    estado,
    obrigatorio,
    evidencias: Object.freeze(evidencias),
    bloqueadores: Object.freeze(bloqueadores),
    motivo
  };
  if (estado === ESTADOS_PORTAO.NAO_COMPROVADO) {
    portao.subcausa = subcausa;
  }
  return Object.freeze(portao);
}

function avaliarScanner({ id, nome, peso, scanner }) {
  if (!scanner?.disponivel || scanner.status !== 'SUCCESS') {
    return criarPortao({
      id,
      nome,
      peso,
      estado: ESTADOS_PORTAO.NAO_COMPROVADO,
      obrigatorio: true,
      subcausa: SUBCAUSAS_NAO_COMPROVADO.MOTOR_FALHOU,
      bloqueadores: [`Sensor obrigatório "${nome}" não produziu evidência verificável.`],
      motivo: scanner?.erro || 'Sensor indisponível; a evidência não pôde ser produzida.'
    });
  }
  if (scanner.totalAchados > 0) {
    return criarPortao({
      id,
      nome,
      peso,
      estado: ESTADOS_PORTAO.NAO_ATENDE,
      obrigatorio: true,
      evidencias: [`${scanner.totalAchados} achado(s) detectado(s).`],
      bloqueadores: [`Achado de segurança no sensor "${nome}" exige correção antes da publicação.`],
      motivo: 'O sensor encontrou evidências incompatíveis com a publicação.'
    });
  }
  return criarPortao({
    id,
    nome,
    peso,
    estado: ESTADOS_PORTAO.ATENDE,
    obrigatorio: true,
    evidencias: ['Sensor executado com sucesso e sem achados.'],
    motivo: 'A evidência disponível atende ao portão.'
  });
}

function avaliarEvidencia({
  id,
  nome,
  peso,
  evidencia,
  obrigatorio = false,
  bloqueador = false,
  contrato = {},
  subcausaAusencia = SUBCAUSAS_NAO_COMPROVADO.SEM_EVIDENCIA_DO_CLIENTE,
  subcausaIndisponivel = SUBCAUSAS_NAO_COMPROVADO.SEM_EVIDENCIA_DO_CLIENTE
}) {
  const ehObrigatorio = obrigatorio || bloqueador;

  // Erro operacional sempre invalida a evidência, independentemente de flags
  // contraditórias recebidas do motor.
  if (evidencia?.erroOperacional) {
    return criarPortao({
      id,
      nome,
      peso,
      estado: ESTADOS_PORTAO.NAO_COMPROVADO,
      obrigatorio: ehObrigatorio,
      subcausa: SUBCAUSAS_NAO_COMPROVADO.MOTOR_FALHOU,
      bloqueadores: ehObrigatorio ? [`Portão obrigatório "${nome}" não foi comprovado: ${evidencia.descricao}`] : [],
      motivo: evidencia.descricao
    });
  }

  // 1. Tratamento de NÃO APLICÁVEL
  if (evidencia?.naoAplicavel) {
    const justificativa = evidencia.justificativa || evidencia.motivo || evidencia.descricao;
    const temJustificativaValida = validarJustificativaContextual(justificativa);

    if (!temJustificativaValida) {
      return criarPortao({
        id,
        nome,
        peso,
        estado: ESTADOS_PORTAO.NAO_COMPROVADO,
        obrigatorio: ehObrigatorio,
        subcausa: SUBCAUSAS_NAO_COMPROVADO.SEM_EVIDENCIA_DO_CLIENTE,
        bloqueadores: ehObrigatorio
          ? [`Declaração de NÃO APLICÁVEL para "${nome}" rejeitada: exige justificativa contextual auditável (mínimo 10 caracteres).`]
          : [],
        motivo: 'Declaração de NÃO APLICÁVEL sem justificativa contextual válida.'
      });
    }

    // Regra de Segurança Zero-Trust:
    // Exceções em portões obrigatórios exigem um contrato externo válido, confiável e suficiente
    const contratoValidoEConfiavel = Boolean(
      contrato &&
      typeof contrato === 'object' &&
      contrato.valido === true &&
      contrato.suficiente === true &&
      contrato.confiavel === true &&
      contrato.autorizaExcecoes === true
    );

    const excecaoAutorizada = Boolean(
      contratoValidoEConfiavel &&
      (contrato.permiteExcecao?.[id] === true ||
       (Array.isArray(contrato.excecoesAutorizadas) && contrato.excecoesAutorizadas.includes(id)))
    );

    if (ehObrigatorio && !excecaoAutorizada) {
      return criarPortao({
        id,
        nome,
        peso,
        estado: ESTADOS_PORTAO.NAO_COMPROVADO,
        obrigatorio: true,
        subcausa: SUBCAUSAS_NAO_COMPROVADO.SEM_EVIDENCIA_DO_CLIENTE,
        bloqueadores: [`Tentativa não autorizada de desativar o portão obrigatório "${nome}" como NÃO APLICÁVEL sem exceção em contrato externo válido e suficiente.`],
        motivo: 'Portão obrigatório não pode ser desativado como NÃO APLICÁVEL sem autorização de contrato externo confiável.'
      });
    }

    return criarPortao({
      id,
      nome,
      peso,
      estado: ESTADOS_PORTAO.NAO_APLICAVEL,
      obrigatorio: false,
      evidencias: [`Dimensão declarada NÃO APLICÁVEL: ${justificativa}`],
      motivo: `Requisito contextual justificado: ${justificativa}`
    });
  }

  // 2. Evidência Ausente / Não Disponível
  if (!evidencia?.disponivel) {
    const descricao = evidencia?.descricao || 'Nenhuma evidência verificável foi fornecida.';
    const subcausa = evidencia == null ? subcausaAusencia : subcausaIndisponivel;
    return criarPortao({
      id,
      nome,
      peso,
      estado: ESTADOS_PORTAO.NAO_COMPROVADO,
      obrigatorio: ehObrigatorio,
      subcausa,
      bloqueadores: ehObrigatorio ? [`Portão obrigatório "${nome}" não foi comprovado: ${descricao}`] : [],
      motivo: descricao
    });
  }

  // 3. Evidência Reprovada / Divergência de Proveniência / Falha
  const descricao = evidencia.descricao || 'Evidência verificável registrada.';
  if (!evidencia.aprovado || evidencia.divergente) {
    return criarPortao({
      id,
      nome,
      peso,
      estado: ESTADOS_PORTAO.NAO_ATENDE,
      obrigatorio: ehObrigatorio,
      evidencias: [descricao],
      bloqueadores: ehObrigatorio ? [`${nome}: ${descricao}`] : [],
      motivo: 'A evidência disponível não atende ao critério.'
    });
  }

  // 4. Evidência Aprovada
  return criarPortao({
    id,
    nome,
    peso,
    estado: ESTADOS_PORTAO.ATENDE,
    obrigatorio: ehObrigatorio,
    evidencias: [descricao],
    motivo: 'A evidência disponível atende ao portão.'
  });
}

function normalizarErroOperacional(erro) {
  if (erro === null || erro === undefined || erro === false) return null;
  const mensagem = erro instanceof Error ? erro.message : String(erro);
  return mensagem.trim() || null;
}

function normalizarEvidenciaDelta(delta) {
  if (!delta?.ativo) return null;

  const erroOperacional = normalizarErroOperacional(delta.erro);
  if (erroOperacional) {
    return {
      disponivel: false,
      aprovado: false,
      erroOperacional,
      descricao: `O motor de delta falhou operacionalmente: ${erroOperacional}`
    };
  }

  const disponivel = delta.disponivel === true;
  return {
    disponivel,
    aprovado: disponivel,
    descricao: disponivel
      ? `${delta.arquivosAlterados || 0} arquivo(s) avaliado(s) no delta.`
      : 'O delta solicitado não pôde ser avaliado.'
  };
}

function textoImpedimento(portao) {
  return portao.bloqueadores[0] || `${portao.nome}: ${portao.motivo}`;
}

function classificarImpedimentos(portoes, errosContrato = []) {
  const grupos = {
    reprovacoesProjeto: [],
    semEvidenciaCliente: [],
    foraCoberturaMotor: [],
    falhasMotor: []
  };

  for (const portao of portoes) {
    if (portao.estado === ESTADOS_PORTAO.NAO_ATENDE) {
      grupos.reprovacoesProjeto.push(textoImpedimento(portao));
      continue;
    }
    if (portao.estado !== ESTADOS_PORTAO.NAO_COMPROVADO) continue;

    if (portao.subcausa === SUBCAUSAS_NAO_COMPROVADO.SEM_EVIDENCIA_DO_CLIENTE) {
      grupos.semEvidenciaCliente.push(textoImpedimento(portao));
    } else if (portao.subcausa === SUBCAUSAS_NAO_COMPROVADO.FORA_DE_COBERTURA_DO_MOTOR) {
      grupos.foraCoberturaMotor.push(textoImpedimento(portao));
    } else if (portao.subcausa === SUBCAUSAS_NAO_COMPROVADO.MOTOR_FALHOU) {
      grupos.falhasMotor.push(textoImpedimento(portao));
    }
  }

  for (const erro of errosContrato) {
    grupos.semEvidenciaCliente.push(`Contrato de publicação: ${erro}`);
  }

  return Object.freeze(Object.fromEntries(
    Object.entries(grupos).map(([grupo, itens]) => [grupo, Object.freeze(itens)])
  ));
}

function calcularScore(portoes, contrato) {
  const observado = portoes
    .filter((portao) => portao.estado === ESTADOS_PORTAO.ATENDE)
    .reduce((total, portao) => total + portao.peso, 0);

  const pesoDesconhecido = portoes
    .filter((portao) => portao.estado === ESTADOS_PORTAO.NAO_COMPROVADO)
    .reduce((total, portao) => total + portao.peso, 0);

  const coberturaPortoes = portoes
    .filter((portao) => portao.estado !== ESTADOS_PORTAO.NAO_COMPROVADO)
    .reduce((total, portao) => total + portao.peso, 0);

  const coberturaContrato = contrato?.coberturaContexto?.percentual;
  const cobertura = Number.isInteger(coberturaContrato)
    ? Math.min(coberturaPortoes, coberturaContrato)
    : coberturaPortoes;

  return Object.freeze({
    observado,
    maximoPossivel: observado + pesoDesconhecido,
    cobertura,
    // Decomposição só para EXIBIÇÃO no relatório humano: a regra de decisão
    // (min entre motores e contrato) permanece em `cobertura`. Sem isso, todo
    // scan sem contrato mostra 0% e esconde o que os motores comprovaram.
    coberturaMotores: coberturaPortoes,
    coberturaContrato: Number.isInteger(coberturaContrato) ? coberturaContrato : null
  });
}

function resumirContextoPublicacao(contrato) {
  const cobertura = contrato?.coberturaContexto;
  if (!cobertura || !Number.isInteger(cobertura.percentual)) return null;

  return Object.freeze({
    schemaVersion: contrato.versaoContrato || '1.0.0',
    source: contrato.origem || 'unknown',
    provided: contrato.fornecido === true,
    valid: contrato.valido === true,
    sufficient: contrato.suficiente === true,
    coverage: cobertura.percentual,
    provenDimensions: Object.freeze([...(cobertura.comprovadas || [])]),
    unprovenDimensions: Object.freeze([...(cobertura.naoComprovadas || [])])
  });
}

export function avaliarRelatorio({ scanners = {}, integridade, delta, evidencias = {}, contrato = {} }) {
  const contextoPublicacao = resumirContextoPublicacao(contrato);
  const portoes = [
    avaliarScanner({ id: 'segredos', nome: 'Segredos e credenciais', peso: 25, scanner: scanners.gitleaks }),
    avaliarScanner({ id: 'seguranca_estatica', nome: 'Segurança estática', peso: 25, scanner: scanners.semgrep }),
    avaliarEvidencia({
      id: 'funcionamento',
      nome: 'Funcionamento e testes',
      peso: 20,
      evidencia: evidencias.funcionamento,
      obrigatorio: true,
      bloqueador: true,
      contrato
    }),
    avaliarEvidencia({
      id: 'integridade',
      nome: 'Integridade read-only',
      peso: 10,
      obrigatorio: true,
      bloqueador: true,
      contrato,
      subcausaAusencia: SUBCAUSAS_NAO_COMPROVADO.MOTOR_FALHOU,
      subcausaIndisponivel: SUBCAUSAS_NAO_COMPROVADO.MOTOR_FALHOU,
      evidencia: integridade ? {
        disponivel: true,
        aprovado: integridade.inalterado,
        descricao: integridade.inalterado
          ? 'Digest permaneceu inalterado durante a análise.'
          : 'O conteúdo do projeto foi alterado durante a análise.'
      } : null
    }),
    // Proveniência e vínculo ao release: OBRIGATÓRIO
    avaliarEvidencia({
      id: 'proveniencia_auditabilidade',
      nome: 'Proveniência e vínculo ao release',
      peso: 10,
      evidencia: evidencias.proveniencia,
      obrigatorio: true,
      bloqueador: true,
      contrato
    }),
    // Impacto do Delta: OPCIONAL
    avaliarEvidencia({
      id: 'impacto_delta',
      nome: 'Impacto do delta',
      peso: 5,
      obrigatorio: false,
      bloqueador: false,
      contrato,
      subcausaAusencia: SUBCAUSAS_NAO_COMPROVADO.FORA_DE_COBERTURA_DO_MOTOR,
      subcausaIndisponivel: SUBCAUSAS_NAO_COMPROVADO.MOTOR_FALHOU,
      evidencia: normalizarEvidenciaDelta(delta)
    }),
    // Manutenção e Documentação: OPCIONAL
    avaliarEvidencia({
      id: 'manutencao_documentacao',
      nome: 'Manutenção e documentação',
      peso: 5,
      obrigatorio: false,
      bloqueador: false,
      contrato,
      subcausaAusencia: SUBCAUSAS_NAO_COMPROVADO.FORA_DE_COBERTURA_DO_MOTOR,
      evidencia: evidencias.manutencaoDocumentacao
    })
  ];

  const bloqueadores = [...portoes.flatMap((portao) => portao.bloqueadores)];

  // Contrato inválido/insuficiente é "contexto de publicação não comprovado"
  // (cobertura insuficiente) — NÃO é um bloqueador material comprovado. Ele não
  // entra em `bloqueadores`; apenas em `impedimentos.semEvidenciaCliente`.
  const errosContrato = contrato && typeof contrato === 'object' && Array.isArray(contrato.erros)
    ? contrato.erros
    : [];

  const impedimentos = classificarImpedimentos(portoes, errosContrato);

  // Portões OBRIGATÓRIOS aplicáveis (um NAO_APLICAVEL autorizado deixa de ser obrigatório).
  const portoesObrigatorios = portoes.filter((p) => p.obrigatorio && p.estado !== ESTADOS_PORTAO.NAO_APLICAVEL);

  // MASS-307: separação estrita entre "reprovação comprovada" e "não comprovado".
  // 1) BLOQUEADOR MATERIAL COMPROVADO = portão obrigatório NAO_ATENDE (achado de
  //    segurança, evidência reprovada, divergência de proveniência ou integridade
  //    violada). Há PROVA de reprovação -> NAO_PUBLICAR.
  // 2) INCONCLUSIVO = portão obrigatório NAO_COMPROVADO (sensor ausente, falha
  //    operacional, timeout, truncamento, alvo fora de cobertura, evidência do
  //    cliente ausente, integridade não comprovada) OU cobertura abaixo do mínimo
  //    OU contrato de publicação não comprovado. NÃO há prova de reprovação, mas
  //    também não há prova de atendimento -> INCONCLUSIVO.
  // 3) PUBLICAR = todos os obrigatórios ATENDE, cobertura mínima atendida e sem
  //    bloqueador material comprovado.
  const bloqueadoresComprovados = portoesObrigatorios.filter(
    (portao) => portao.estado === ESTADOS_PORTAO.NAO_ATENDE
  );
  const inconclusivosObrigatorios = portoesObrigatorios.filter(
    (portao) => portao.estado === ESTADOS_PORTAO.NAO_COMPROVADO
  );

  const score = calcularScore(portoes, contrato);
  const coberturaInsuficiente = score.cobertura < COBERTURA_MINIMA_PUBLICACAO;
  const contratoInconclusivo = errosContrato.length > 0;

  // MASS-307 revisão: alvo FORA DE COBERTURA (mesmo em portão OPCIONAL) impede
  // PUBLICAR — a avaliação fica INCONCLUSIVO, nunca aprovação. "Fora de
  // cobertura" é uma limitação do ZUNVIO, não uma reprovação do projeto.
  const temForaDeCobertura = impedimentos.foraCoberturaMotor.length > 0;

  let codigo;
  let decisaoPublicacao;
  let rotulo;
  if (bloqueadoresComprovados.length > 0) {
    codigo = CODIGO_DECISAO.NAO_ACEITAR;
    decisaoPublicacao = DECISAO_PUBLICACAO.NAO_PUBLICAR;
    rotulo = 'NÃO PUBLICAR';
  } else if (inconclusivosObrigatorios.length > 0 || temForaDeCobertura || contratoInconclusivo || coberturaInsuficiente) {
    codigo = CODIGO_DECISAO.INCONCLUSIVO;
    decisaoPublicacao = DECISAO_PUBLICACAO.INCONCLUSIVO;
    rotulo = 'INCONCLUSIVO';
  } else {
    codigo = CODIGO_DECISAO.ACEITAR;
    decisaoPublicacao = DECISAO_PUBLICACAO.PUBLICAR;
    rotulo = 'PUBLICAR';
  }
  const publicar = decisaoPublicacao === DECISAO_PUBLICACAO.PUBLICAR;
  const inconclusivo = decisaoPublicacao === DECISAO_PUBLICACAO.INCONCLUSIVO;

  // Natureza do impedimento derivada dos grupos já classificados (abrange TODOS
  // os portões, inclusive opcionais — fora de cobertura opcional é limite ZUNVIO).
  const temImpedimentoProjetoOuCliente =
    impedimentos.reprovacoesProjeto.length > 0 || impedimentos.semEvidenciaCliente.length > 0;
  const temLimiteZunvio =
    impedimentos.foraCoberturaMotor.length > 0 || impedimentos.falhasMotor.length > 0;
  const naturezaImpedimento = publicar
    ? 'NENHUM'
    : temImpedimentoProjetoOuCliente && temLimiteZunvio
      ? 'MISTO'
      : temLimiteZunvio
        ? 'LIMITE_ZUNVIO'
        : 'PROJETO_OU_CLIENTE';
  const portoesConclusivos = portoes.filter((portao) =>
    portao.estado === ESTADOS_PORTAO.ATENDE || portao.estado === ESTADOS_PORTAO.NAO_ATENDE
  ).length;

  const mensagem = publicar
    ? 'Todos os portões obrigatórios atendem aos critérios de publicação.'
    : inconclusivo
      ? `Avaliação inconclusiva (${portoesConclusivos} de ${portoes.length} portões com evidência conclusiva). Não há bloqueador material comprovado, mas faltam evidências obrigatórias${coberturaInsuficiente ? ' ou cobertura mínima' : ''}; não é possível afirmar que pode publicar.`
      : `Existem ${bloqueadoresComprovados.length} bloqueador(es) material(is) comprovado(s) que impedem a publicação.`;

  return Object.freeze({
    portoes: Object.freeze(portoes),
    score,
    ...(contextoPublicacao ? { contextoPublicacao } : {}),
    decisao: Object.freeze({
      codigo,
      decisaoPublicacao,
      rotulo,
      publicar,
      inconclusivo,
      mensagem,
      naturezaImpedimento,
      impedimentos,
      bloqueadores: Object.freeze(bloqueadores)
    })
  });
}
