import { ausenciaNaoComprova, temModeloDeCompletude } from '../models/completeness.mjs';

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
// - NAO_PUBLICAR: bloqueador material (achado alto pendente de revisão,
//   evidência reprovada, divergência de proveniência ou integridade violada).
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

/**
 * PL-03: frases do portão por significado. Separa o que foi DEMONSTRADO do que só pede revisão, e diz quantos
 * achados foram considerados informativos (não bloqueiam). Sem contagem por significado (motor antigo), nada muda.
 */
function frasesDeSignificado(scanner) {
  const b = scanner?.significadosBloqueantes;
  const t = scanner?.significados;
  if (!b || typeof b !== 'object') return null;
  const n = (v) => (Number.isInteger(v) && v > 0 ? v : 0);
  const risco = n(b.RISCO_DEMONSTRADO);
  const revisao = n(b.REVISAO_NECESSARIA) + n(b.SEM_SIGNIFICADO);
  const informativos = t && typeof t === 'object' ? n(t.INFORMATIVO) : 0;
  const evidencias = [];
  if (risco > 0) evidencias.push(`${risco} achado(s) com risco demonstrado (entrada externa chega à operação sensível).`);
  if (revisao > 0) evidencias.push(`${revisao} achado(s) que exigem revisão: o padrão foi encontrado, mas o risco não foi demonstrado.`);
  if (informativos > 0) evidencias.push(`${informativos} achado(s) informativo(s): não impedem a publicação.`);
  return { risco, revisao, informativos, evidencias };
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
  const totalAchadosBloqueantes = Number.isInteger(scanner.totalAchadosBloqueantes)
    ? scanner.totalAchadosBloqueantes
    : scanner.totalAchados;
  const significado = frasesDeSignificado(scanner);
  if (totalAchadosBloqueantes > 0) {
    if (significado && significado.risco > 0) {
      return criarPortao({
        id,
        nome,
        peso,
        estado: ESTADOS_PORTAO.NAO_ATENDE,
        obrigatorio: true,
        evidencias: significado.evidencias,
        bloqueadores: [`O sensor "${nome}" demonstrou risco em ${significado.risco} achado(s); corrija antes da publicação.`],
        motivo: 'Há achado com risco demonstrado: entrada externa chega a uma operação sensível.'
      });
    }
    return criarPortao({
      id,
      nome,
      peso,
      estado: ESTADOS_PORTAO.NAO_ATENDE,
      obrigatorio: true,
      evidencias: significado
        ? significado.evidencias
        : [`${totalAchadosBloqueantes} padrão(ões) detectado(s); validação: NECESSITA_REVISAO.`],
      bloqueadores: [`Achado heurístico no sensor "${nome}" necessita revisão antes da publicação.`],
      motivo: 'O sensor detectou padrões de segurança ainda não confirmados por verificação adicional.'
    });
  }

  // Fatia 1 (Scanner Completeness) — regra fundamental: ausência de finding não
  // é evidência de ausência numa região cuja análise não foi comprovadamente
  // completa. Aplicada só onde é necessária para não representar cobertura de
  // forma enganosa: o sensor tem modelo de completude, não provou completude e
  // não há achado bloqueante (achados continuam valendo como NAO_ATENDE acima).
  if (ausenciaNaoComprova(scanner.completude)) {
    const c = scanner.completude;
    const onde = c.affectedFileCount > 0
      ? `${c.affectedFileCount} arquivo(s) não verificado(s) por completo`
      : 'completude da análise não comprovada';
    const tipo = c.status === 'PARTIAL' ? 'parcial' : (c.status === 'DEGRADED' ? 'degradada' : 'com completude desconhecida');
    return criarPortao({
      id,
      nome,
      peso,
      estado: ESTADOS_PORTAO.NAO_COMPROVADO,
      obrigatorio: true,
      subcausa: SUBCAUSAS_NAO_COMPROVADO.MOTOR_FALHOU,
      evidencias: [`Análise ${tipo}: ${onde} (${c.reasons.join(', ')}).`],
      bloqueadores: [`Sensor obrigatório "${nome}" não verificou todo o código; a ausência de achados não comprova ausência de problemas.`],
      motivo: 'A análise do sensor não foi comprovadamente completa; nenhum achado não significa nenhum problema.'
    });
  }

  // PL-04 (decisão do fundador, portão "Segredos" = opção A): sensor que não comprova cobertura (sem modelo de
  // completude, ex.: Gitleaks) também não sustenta ATENDE por ausência de achado. A evidência permite dizer "nenhum
  // achado reportado pelo sensor", não "o projeto atende ao portão". Ausência de achado + cobertura não comprovada ≠
  // conformidade comprovada. (Sem objeto de completude — produtor antigo/teste — mantém o comportamento anterior.)
  if (scanner.completude && !temModeloDeCompletude(scanner.completude)) {
    const enviados = scanner.completude.universe?.expected;
    return criarPortao({
      id,
      nome,
      peso,
      estado: ESTADOS_PORTAO.NAO_COMPROVADO,
      obrigatorio: true,
      subcausa: SUBCAUSAS_NAO_COMPROVADO.FORA_DE_COBERTURA_DO_MOTOR,
      evidencias: [`Nenhum achado reportado pelo sensor, mas não foi possível comprovar quais arquivos ele analisou${Number.isInteger(enviados) ? ` (${enviados} arquivo(s) enviados)` : ''}.`],
      bloqueadores: [`A cobertura do sensor "${nome}" não pôde ser comprovada; ausência de achado não comprova conformidade.`],
      motivo: 'O sensor não informa quais arquivos analisou: ausência de achado reportado não é conformidade comprovada.'
    });
  }

  // Baseline (MASS-325): achado coberto por entrada auditável (fingerprint +
  // autor + data + justificativa) não bloqueia, mas fica explícito na evidência —
  // nunca um "sem achados" indistinguível do caminho realmente limpo.
  const suprimidos = Array.isArray(scanner.suprimidosPorBaseline) ? scanner.suprimidosPorBaseline : [];
  if (suprimidos.length > 0) {
    return criarPortao({
      id,
      nome,
      peso,
      estado: ESTADOS_PORTAO.ATENDE,
      obrigatorio: true,
      evidencias: [
        `${suprimidos.length} achado(s) aceito(s) com ressalva via baseline auditável.`,
        ...suprimidos.map(
          (s) => `Suprimido: ${s.achado?.fingerprint || '?'} — aceito por ${s.autor} em ${s.data}: ${s.justificativa}`
        )
      ],
      motivo: 'Todos os achados do sensor estão cobertos por baseline auditável (aceitos com ressalva).'
    });
  }

  return criarPortao({
    id,
    nome,
    peso,
    estado: ESTADOS_PORTAO.ATENDE,
    obrigatorio: true,
    // PL-03: achados informativos existem, mas não bloqueiam — dizer isso, nunca "sem achados".
    // E2E mínimo: achado em revisão aceito por revisão humana registrada também é dito — nunca "sem achados" nem
    // "segurança comprovada".
    evidencias: [
      ...(significado && significado.informativos > 0
        ? ['Sensor executado com sucesso; nenhum achado bloqueante.', ...significado.evidencias]
        : (scanner.revisadosPorHumano > 0 ? ['Sensor executado com sucesso; nenhum achado bloqueante.'] : ['Sensor executado com sucesso e sem achados.'])),
      ...(scanner.revisadosPorHumano > 0
        ? [`${scanner.revisadosPorHumano} achado(s) que pediam revisão foram revisados por humano e aceitos neste contexto (revisão registrada; não é prova de ausência de risco).`]
        : [])
    ],
    motivo: scanner.revisadosPorHumano > 0
      ? 'A evidência disponível atende ao portão, com revisão humana registrada para achados que pediam revisão.'
      : 'A evidência disponível atende ao portão.'
  });
}

/**
 * LC-06 — portão "Segredos" com as duas partes do sensor (decisão do fundador, 26/09/2026):
 *   NAO_ATENDE     — há achado de segredo que viola o portão (working tree ou histórico);
 *   ATENDE         — somente com: working tree com cobertura COMPLETA do universo elegível, histórico Git esperado com
 *                    cobertura COMPLETA demonstrada (ou alvo sem histórico) e zero achado, nem suprimido por baseline;
 *   NAO_COMPROVADO — sem achado, mas qualquer cobertura necessária não comprovada, sensor falho, ou achado aceito
 *                    pela baseline do próprio projeto (o avaliado não pode reduzir a cobertura do auditor e receber
 *                    confiança positiva por isso).
 * O verificador de recibo (receipt/verifier.mjs) deriva o mesmo estado dos campos selados.
 */
function avaliarPortaoSegredos({ arvore, historico }) {
  const id = 'segredos';
  const nome = 'Segredos e credenciais';
  const peso = 25;
  const bloqueantes = (s) => (Number.isInteger(s?.totalAchadosBloqueantes) ? s.totalAchadosBloqueantes : (s?.totalAchados || 0));
  const somar = (campo) => {
    const soma = {};
    for (const s of [arvore, historico]) for (const [k, v] of Object.entries(s?.[campo] || {})) if (Number.isInteger(v)) soma[k] = (soma[k] || 0) + v;
    return soma;
  };
  const significado = frasesDeSignificado({ significadosBloqueantes: somar('significadosBloqueantes'), significados: somar('significados') });
  const total = bloqueantes(arvore) + bloqueantes(historico);
  if (total > 0) {
    const noHistorico = bloqueantes(historico);
    const onde = noHistorico > 0 ? [`${noHistorico} achado(s) no histórico Git (segredo commitado continua exposto no repositório).`] : [];
    if (significado && significado.risco > 0) {
      return criarPortao({
        id, nome, peso, estado: ESTADOS_PORTAO.NAO_ATENDE, obrigatorio: true,
        evidencias: [...significado.evidencias, ...onde],
        bloqueadores: [`O sensor "${nome}" demonstrou risco em ${significado.risco} achado(s); corrija antes da publicação.`],
        motivo: 'Há achado com risco demonstrado: entrada externa chega a uma operação sensível.'
      });
    }
    return criarPortao({
      id, nome, peso, estado: ESTADOS_PORTAO.NAO_ATENDE, obrigatorio: true,
      evidencias: [...(significado ? significado.evidencias : [`${total} padrão(ões) detectado(s); validação: NECESSITA_REVISAO.`]), ...onde],
      bloqueadores: [`Achado heurístico no sensor "${nome}" necessita revisão antes da publicação.`],
      motivo: 'O sensor detectou padrões de segurança ainda não confirmados por verificação adicional.'
    });
  }

  const arvoreFalhou = !arvore?.disponivel || arvore.status !== 'SUCCESS';
  const historicoFalhou = !historico || !['SUCCESS', 'NOT_RUN'].includes(historico.status);
  if (arvoreFalhou || historicoFalhou) {
    return criarPortao({
      id, nome, peso, estado: ESTADOS_PORTAO.NAO_COMPROVADO, obrigatorio: true, subcausa: SUBCAUSAS_NAO_COMPROVADO.MOTOR_FALHOU,
      evidencias: [
        ...(arvoreFalhou ? [`Estado atual dos arquivos: a varredura de segredos não concluiu${arvore?.erro ? ` (${arvore.erro})` : ''}.`] : []),
        ...(historicoFalhou ? [`Histórico Git: a varredura não concluiu${historico?.erro ? ` (${historico.erro})` : ''}.`] : [])
      ],
      bloqueadores: [`Sensor obrigatório "${nome}" não produziu evidência verificável.`],
      motivo: 'Sensor de segredos não concluiu; a evidência não pôde ser produzida.'
    });
  }

  const ca = arvore.completude;
  const ch = historico.completude;
  if (ca?.status !== 'COMPLETE') {
    const u = ca?.universe;
    const onde = u && Number.isInteger(u.expected)
      ? `${u.notAnalyzed} de ${u.expected} arquivo(s) elegíveis não foram analisados (${(ca.reasons || []).join(', ')})`
      : `cobertura dos arquivos não determinada (${(ca?.reasons || []).join(', ')})`;
    return criarPortao({
      id, nome, peso, estado: ESTADOS_PORTAO.NAO_COMPROVADO, obrigatorio: true, subcausa: SUBCAUSAS_NAO_COMPROVADO.MOTOR_FALHOU,
      evidencias: [`Nenhum segredo encontrado, mas a cobertura do estado atual dos arquivos não é completa: ${onde}.`],
      bloqueadores: [`Sensor obrigatório "${nome}" não verificou todo o código; a ausência de achados não comprova ausência de segredos.`],
      motivo: 'A análise de segredos dos arquivos não foi comprovadamente completa; nenhum achado não significa nenhum segredo.'
    });
  }
  if (ch?.status !== 'COMPLETE') {
    const h = ch?.history || {};
    return criarPortao({
      id, nome, peso, estado: ESTADOS_PORTAO.NAO_COMPROVADO, obrigatorio: true, subcausa: SUBCAUSAS_NAO_COMPROVADO.FORA_DE_COBERTURA_DO_MOTOR,
      evidencias: [`Nenhum segredo encontrado, mas a cobertura do histórico Git não foi demonstrada (${(ch?.reasons || []).join(', ')}${h.applicable === false ? '; o alvo não é um repositório Git: o histórico do release não pôde ser varrido' : ''}${Number.isInteger(h.commitsExpected) && Number.isInteger(h.commitsScanned) ? `; ${h.commitsScanned} de ${h.commitsExpected} commit(s) esperados` : ''}).`],
      bloqueadores: [`A cobertura do histórico Git pelo sensor "${nome}" não pôde ser comprovada; ausência de achado não comprova conformidade.`],
      motivo: 'O histórico Git esperado não foi comprovadamente varrido por inteiro.'
    });
  }
  const suprimidos = [...(arvore.suprimidosPorBaseline || []), ...(historico.suprimidosPorBaseline || [])];
  if (suprimidos.length > 0) {
    return criarPortao({
      id, nome, peso, estado: ESTADOS_PORTAO.NAO_COMPROVADO, obrigatorio: true, subcausa: SUBCAUSAS_NAO_COMPROVADO.SEM_EVIDENCIA_DO_CLIENTE,
      evidencias: [
        `${suprimidos.length} achado(s) aceito(s) pela baseline do próprio projeto, sem verificação independente.`,
        ...suprimidos.map((s) => `Suprimido: ${s.achado?.fingerprint || '?'} — aceito por ${s.autor} em ${s.data}: ${s.justificativa}`)
      ],
      bloqueadores: [`Há segredo aceito pela baseline do próprio projeto; o portão "${nome}" não pode ser comprovado por declaração do avaliado.`],
      motivo: 'Achado de segredo aceito pelo próprio projeto não é ausência comprovada de segredos.'
    });
  }
  // PL-03: achado que não bloqueia (dependência de terceiros, artefato gerado, informativo) existe e é dito — nunca
  // um "sem achados" indistinguível do caminho limpo.
  const naoBloqueiam = [arvore, historico].reduce((t, s) => t + Math.max(0, (s?.totalAchados || 0) - bloqueantes(s)), 0);
  return criarPortao({
    id, nome, peso, estado: ESTADOS_PORTAO.ATENDE, obrigatorio: true,
    evidencias: [
      `Estado atual dos arquivos: ${ca.universe.analyzed} de ${ca.universe.expected} arquivo(s) elegíveis analisados por inteiro, sem achado bloqueante.`,
      `Histórico Git: ${ch.history.commitsScanned} de ${ch.history.commitsExpected} commit(s) esperados varridos (HEAD ${String(ch.history.headCommit).slice(0, 12)}), sem achado bloqueante.`,
      ...(naoBloqueiam > 0 ? [`${naoBloqueiam} achado(s) de segredo que não bloqueiam (dependência de terceiros, artefato gerado ou informativo) — continuam listados.`] : [])
    ],
    motivo: 'A cobertura de segredos foi demonstrada no estado atual e no histórico, sem achado que viole o portão.'
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
    // LC-06: com o sensor de segredos em duas partes (scanner próprio + Gitleaks no histórico), vale a regra do LC-06.
    // Sem ele (produtor anterior ao 0.7.0 / testes do motor antigo), a regra da época.
    scanners['zunvio-segredos']
      ? avaliarPortaoSegredos({ arvore: scanners['zunvio-segredos'], historico: scanners.gitleaks })
      : avaliarScanner({ id: 'segredos', nome: 'Segredos e credenciais', peso: 25, scanner: scanners.gitleaks }),
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
    // PL-01/PL-04: acima do limite operacional o digest de integridade cobre só a parte do projeto que coube no
    // snapshot — "inalterado" não pode ser afirmado para o projeto inteiro.
    integridade?.limitesExcedidos ? criarPortao({
      id: 'integridade',
      nome: 'Integridade read-only',
      peso: 10,
      estado: ESTADOS_PORTAO.NAO_COMPROVADO,
      obrigatorio: true,
      subcausa: SUBCAUSAS_NAO_COMPROVADO.FORA_DE_COBERTURA_DO_MOTOR,
      evidencias: [`O digest foi comparado só sobre a parte do projeto dentro do limite operacional${integridade.motivoLimite ? ` (${integridade.motivoLimite})` : ''}.`],
      bloqueadores: ['A integridade read-only não pôde ser comprovada para o projeto inteiro (limite operacional).'],
      motivo: 'O projeto passa do limite operacional: a integridade foi verificada só em parte.'
    }) : avaliarEvidencia({
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
  // (cobertura insuficiente) — NÃO é um bloqueador material detectado. Ele não
  // entra em `bloqueadores`; apenas em `impedimentos.semEvidenciaCliente`.
  const errosContrato = contrato && typeof contrato === 'object' && Array.isArray(contrato.erros)
    ? contrato.erros
    : [];

  const impedimentos = classificarImpedimentos(portoes, errosContrato);

  // Portões OBRIGATÓRIOS aplicáveis (um NAO_APLICAVEL autorizado deixa de ser obrigatório).
  const portoesObrigatorios = portoes.filter((p) => p.obrigatorio && p.estado !== ESTADOS_PORTAO.NAO_APLICAVEL);

  // MASS-353: NAO_ATENDE inclui achado heurístico que ainda necessita revisão;
  // a decisão permanece fail-closed sem alegar que a credencial foi confirmada.
  // Evidência reprovada, divergência de proveniência ou integridade violada
  // também levam a NAO_PUBLICAR.
  // 2) INCONCLUSIVO = portão obrigatório NAO_COMPROVADO (sensor ausente, falha
  //    operacional, timeout, truncamento, alvo fora de cobertura, evidência do
  //    cliente ausente, integridade não comprovada) OU cobertura abaixo do mínimo
  //    OU contrato de publicação não comprovado. NÃO há prova de reprovação, mas
  //    também não há prova de atendimento -> INCONCLUSIVO.
  // 3) PUBLICAR = todos os obrigatórios ATENDE, cobertura mínima atendida e sem
  //    bloqueador material.
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
      ? `Avaliação inconclusiva (${portoesConclusivos} de ${portoes.length} portões com evidência conclusiva). Não há bloqueador material detectado, mas faltam evidências obrigatórias${coberturaInsuficiente ? ' ou cobertura mínima' : ''}; não é possível afirmar que pode publicar.`
      : `Existem ${bloqueadoresComprovados.length} bloqueador(es) preventivo(s) que exigem revisão antes da publicação.`;

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
