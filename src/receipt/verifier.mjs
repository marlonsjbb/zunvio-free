import { validarEvidencePackV0 } from '../schema/validador-schema.mjs';
import { calcularHashCanonico } from '../utils/canonical-json.mjs';
import { COBERTURA_MINIMA_PUBLICACAO, OUTCOME_CANONICO } from '../decision/evaluator.mjs';
import { ausenciaNaoComprova, temModeloDeCompletude } from '../models/completeness.mjs';
import packageJson from '../../package.json' with { type: 'json' };
import { problemasDaRevisaoSelada } from '../models/human-review.mjs';

// Resultado de verificação de um Score Receipt (Evidence Pack) por terceiro.
// O verificador não reexecuta scanners, não acessa rede, não executa código do
// projeto, não escreve no alvo e não corrige/reemite o recibo. Ele apenas
// re-hidrata o JSON recebido e confere integridade, vínculo e coerência.
//
// IMPORTANTE (B9): "VÁLIDO" não autentica origem/emissor nem certifica segurança.
// O hash canônico prova integridade e coerência internas, apenas. O rótulo humano
// deixa isso explícito.
export const RESULTADO = Object.freeze({
  VALIDO: 'VALIDO',
  INVALIDO: 'INVALIDO',
  NAO_SUPORTADO: 'NAO_SUPORTADO'
});

export const ROTULO_INTEGRIDADE_INTERNA = 'INTEGRIDADE E COERÊNCIA INTERNAS VÁLIDAS — ORIGEM NÃO AUTENTICADA';

// Receipts emitidos pelo CLI usam a versão do produto declarada no package.json.
// A versão 0.2.0 do schema permanece aceita para verificar receipts já emitidos.
// Fatia 1 (Scanner Completeness): 0.3.0 acrescenta completude por scanner.
// PL-03 (fechamento): 0.4.0 acrescenta o significado selado por achado.
// PL-02: 0.5.0 acrescenta o universo esperado por scanner na completude.
// LC-06: 0.7.0 acrescenta o sensor de segredos em duas partes (scanner próprio + Gitleaks só no histórico).
const VERSOES_SUPORTADAS = new Set([packageJson.version, '0.1.0', '0.2.0', '0.3.0', '0.4.0', '0.5.0', '0.6.0', '0.7.0', '0.8.0']);
const COMPLETUDES_VALIDAS = new Set(['CLEAN', 'WITH_FINDINGS', 'NOT_STARTED', 'FAILED']);
// LC-06: NOT_RUN = o Gitleaks não tinha histórico a varrer (alvo sem repositório, ou subdiretório de um).
const STATUS_SENSOR_VALIDOS = new Set(['SUCCESS', 'UNAVAILABLE', 'ERROR', 'TIMEOUT', 'BUFFER_OVERFLOW', 'NOT_RUN']);
const SEVERIDADES_VALIDAS = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
const CATEGORIAS_ACHADO_VALIDAS = new Set([
  'CODIGO_PROPRIO', 'TERCEIROS_DEPENDENCIAS', 'TESTES_FIXTURES', 'ARTEFATOS_GERADOS'
]);
const STATUS_VALIDACAO_ACHADO_VALIDOS = new Set(['NECESSITA_REVISAO', 'CONFIRMADO']);
const STATUS_IDENTIDADE_SIMBOLO_VALIDOS = new Set(['CONFIRMADA', 'RECUSADA', 'NAO_DETERMINADA']);
const HEX64 = /^[a-f0-9]{64}$/;
const SENSORES_CANONICOS = ['gitleaks', 'semgrep'];
// LC-06 (0.7.0 e a projeção da CLI que o carrega): o scanner próprio de segredos também é canônico.
const temSegredosProprio = (receipt) => receipt?.versao === '0.7.0' || receipt?.versao === '0.8.0'
  || (ehObjeto(receipt?.canonicalContent?.scannersSummary) && Object.hasOwn(receipt.canonicalContent.scannersSummary, 'zunvio-segredos'));
const sensoresCanonicos = (receipt) => (temSegredosProprio(receipt) ? ['gitleaks', 'zunvio-segredos', 'semgrep'] : SENSORES_CANONICOS);
// B4: mapeia cada sensor canônico ao portão que o evaluator deriva dele.
const SENSOR_GATE = Object.freeze({ gitleaks: 'segredos', semgrep: 'seguranca_estatica' });

// Conjunto canônico de portões (id, ordem, peso e obrigatoriedade) do método
// 0.2.0. Um receipt forjado que use outro conjunto/ordem/peso/obrigatoriedade é
// rejeitado, mesmo que tenha hash recalculado (B3).
const GATES_CANONICOS = Object.freeze([
  Object.freeze({ id: 'segredos', peso: 25, obrigatorio: true }),
  Object.freeze({ id: 'seguranca_estatica', peso: 25, obrigatorio: true }),
  Object.freeze({ id: 'funcionamento', peso: 20, obrigatorio: true }),
  Object.freeze({ id: 'integridade', peso: 10, obrigatorio: true }),
  Object.freeze({ id: 'proveniencia_auditabilidade', peso: 10, obrigatorio: true }),
  Object.freeze({ id: 'impacto_delta', peso: 5, obrigatorio: false }),
  Object.freeze({ id: 'manutencao_documentacao', peso: 5, obrigatorio: false })
]);

function ehObjeto(valor) {
  return valor !== null && typeof valor === 'object' && !Array.isArray(valor);
}

// Extrai o SHA de 40 hex do release auditado a partir do portão de proveniência
// selado no canonicalContent.decision.gates. Retorna null quando ausente.
function extrairShaRelease(receipt) {
  const gates = receipt?.canonicalContent?.decision?.gates;
  if (!Array.isArray(gates)) return null;
  const prov = gates.find((g) => g && g.id === 'proveniencia_auditabilidade');
  if (!prov) return null;
  for (const ev of prov.evidencias || []) {
    const m = /[0-9a-f]{40}/i.exec(String(ev));
    if (m) return m[0];
  }
  return null;
}

// B3: valida o conjunto canônico de portões com TIPOS EXATOS. Sem Boolean() nem
// Number(): `peso` precisa ser número real e `obrigatorio` precisa ser booleano
// real. Uma string "false" ou "25" é rejeitada, não coagida.
function validarGatesCanonicos(gates, motivos) {
  if (!Array.isArray(gates) || gates.length !== GATES_CANONICOS.length) {
    motivos.push(`conjunto de gates inválido: esperados ${GATES_CANONICOS.length} gates, recebidos ${gates?.length ?? 'n/d'}`);
    return;
  }
  for (let i = 0; i < GATES_CANONICOS.length; i++) {
    const esperado = GATES_CANONICOS[i];
    const gate = gates[i];
    if (!ehObjeto(gate)) {
      motivos.push(`gate[${i}] inválido (não é objeto)`);
      continue;
    }
    if (typeof gate.id !== 'string' || gate.id !== esperado.id) {
      motivos.push(`gate[${i}] id inválido: esperado "${esperado.id}", recebido ${JSON.stringify(gate.id)}`);
    }
    if (typeof gate.peso !== 'number' || gate.peso !== esperado.peso) {
      motivos.push(`gate "${gate.id ?? i}" peso inválido: esperado número ${esperado.peso}, recebido ${typeof gate.peso} ${JSON.stringify(gate.peso)}`);
    }
    if (typeof gate.obrigatorio !== 'boolean' || gate.obrigatorio !== esperado.obrigatorio) {
      motivos.push(`gate "${gate.id ?? i}" obrigatoriedade inválida: esperado booleano ${esperado.obrigatorio}, recebido ${typeof gate.obrigatorio} ${JSON.stringify(gate.obrigatorio)}`);
    }
  }
}

// B3/P2: valida as invariantes de integridade do receipt. O verificador não pode
// confiar apenas na flag `immutable`: confere initialDigest === finalDigest,
// differences vazio e o vínculo do inventoryDigest selado com o digest inicial.
// Retorna true apenas quando a integridade está PROVADAMENTE preservada.
function validarIntegridade(receipt, motivos) {
  const ip = receipt.integrityProof;
  const cc = receipt.canonicalContent;
  if (!ehObjeto(ip)) {
    motivos.push('integrityProof ausente ou inválido');
    return false;
  }

  const initial = ip.initialDigest;
  const final = ip.finalDigest;
  const immutable = ip.immutable;
  const differences = Array.isArray(ip.differences) ? ip.differences : null;

  if (typeof initial !== 'string' || !HEX64.test(initial)) {
    motivos.push('integrityProof.initialDigest deve ser SHA-256 de 64 caracteres hexadecimais');
  }
  if (typeof final !== 'string' || !HEX64.test(final)) {
    motivos.push('integrityProof.finalDigest deve ser SHA-256 de 64 caracteres hexadecimais');
  }
  if (typeof immutable !== 'boolean') {
    motivos.push('integrityProof.immutable deve ser boolean');
  }
  if (differences === null) {
    motivos.push('integrityProof.differences deve ser array');
  }

  // O inventário dos scanners pode ter perímetro reduzido (vendor/gerados
  // excluídos). Packs atuais selam o digest do alvo completo em targetDigest;
  // packs anteriores mantêm o vínculo legado via inventoryDigest.
  const digestAlvoSelado = ehObjeto(cc) && typeof cc.targetDigest === 'string'
    ? cc.targetDigest
    : cc?.inventoryDigest;
  if (typeof digestAlvoSelado === 'string' && digestAlvoSelado !== initial) {
    motivos.push('targetDigest diverge do initialDigest');
  }

  const digestsIguais = typeof initial === 'string' && typeof final === 'string' && initial === final;
  const semDiferencas = differences !== null && differences.length === 0;
  const integridadePreservada = digestsIguais && semDiferencas;

  if (immutable === true && !integridadePreservada) {
    motivos.push('integrityProof.immutable=true incompatível com digests divergentes ou differences não vazio');
  }
  if (immutable === false && integridadePreservada) {
    motivos.push('integrityProof.immutable=false incompatível com digests iguais e differences vazio');
  }

  return immutable === true && integridadePreservada;
}

// Deriva a completude esperada do sensor a partir do status real (a mesma
// máquina de estados usada pelo scanner em `classificarCompletude`).
function completudeEsperada(status, totalAchados) {
  if (status === 'SUCCESS') return totalAchados > 0 ? 'WITH_FINDINGS' : 'CLEAN';
  if (status === 'UNAVAILABLE' || status === 'NOT_RUN') return 'NOT_STARTED';
  return 'FAILED';
}

// B4: valida a identidade/completude dos sensores e reconcilia contagens/digest
// com os achados canônicos selados. Rejeita sensores extras, ausentes, com
// status desconhecido e combinações status↔completion impossíveis.
function validarSensores(receipt) {
  const motivos = [];
  const canonicalContent = receipt?.canonicalContent;
  const scannersSummary = canonicalContent?.scannersSummary;
  if (!ehObjeto(scannersSummary)) {
    return ['scannersSummary ausente ou inválido'];
  }

  // B4: somente os sensores canônicos esperados.
  const canonicos = sensoresCanonicos(receipt);
  for (const chave of Object.keys(scannersSummary)) {
    if (!canonicos.includes(chave)) {
      motivos.push(`sensor extra não canônico: "${chave}"`);
    }
  }

  const achados = Array.isArray(canonicalContent.findings) ? canonicalContent.findings : null;

  for (const chave of canonicos) {
    const sensor = scannersSummary[chave];
    if (!ehObjeto(sensor)) {
      motivos.push(`identidade do sensor "${chave}" ausente`);
      continue;
    }
    if (sensor.id !== chave) {
      motivos.push(`id do sensor "${chave}" inválido`);
    }
    if (!COMPLETUDES_VALIDAS.has(sensor.completion)) {
      motivos.push(`completude do sensor "${chave}" inválida`);
      continue;
    }

    // B4: status deve ser um dos valores conhecidos; status BOGUS é rejeitado.
    if (typeof sensor.status !== 'string' || !STATUS_SENSOR_VALIDOS.has(sensor.status)) {
      motivos.push(`status do sensor "${chave}" desconhecido ou inválido: ${JSON.stringify(sensor.status)}`);
      continue;
    }

    // Reconciliação de contagem por sensor com os achados canônicos selados.
    const achadosDoSensor = achados
      ? achados.filter((a) => ehObjeto(a) && a.scanner === chave)
      : [];
    const contagemCanonica = achadosDoSensor.length;
    if (typeof sensor.findingsCount !== 'number' || sensor.findingsCount !== contagemCanonica) {
      motivos.push(`sensor "${chave}" findingsCount (${JSON.stringify(sensor.findingsCount)}) diverge dos achados selados (${contagemCanonica})`);
    }

    const completudeDerivada = completudeEsperada(sensor.status, contagemCanonica);
    if (sensor.completion !== completudeDerivada) {
      motivos.push(`completude do sensor "${chave}" incoerente: status "${sensor.status}" exige "${completudeDerivada}", recebido "${sensor.completion}"`);
    }

    if (sensor.completion === 'CLEAN' && contagemCanonica !== 0) {
      motivos.push(`sensor "${chave}" declara CLEAN com ${contagemCanonica} achado(s)`);
    }
    if (sensor.completion === 'WITH_FINDINGS' && contagemCanonica < 1) {
      motivos.push(`sensor "${chave}" declara WITH_FINDINGS com ${contagemCanonica} achado(s)`);
    }
    if ((sensor.completion === 'NOT_STARTED' || sensor.completion === 'FAILED') && sensor.findingsDigest !== null) {
      motivos.push(`sensor "${chave}" não concluiu mas declara findingsDigest`);
    }

    // CLEAN/WITH_FINDINGS exigem identidade completa (versão real, configHash e
    // digest canônicos) e um digest que casa byte a byte com os achados selados.
    if (sensor.completion === 'CLEAN' || sensor.completion === 'WITH_FINDINGS') {
      if (typeof sensor.version !== 'string' || sensor.version.trim() === '') {
        motivos.push(`sensor "${chave}" ${sensor.completion} sem versão real do binário`);
      }
      for (const campo of ['configHash', 'findingsDigest']) {
        const valor = sensor[campo];
        if (typeof valor !== 'string' || !HEX64.test(valor)) {
          motivos.push(`sensor "${chave}" ${sensor.completion} sem ${campo} canônico válido`);
        }
      }
      if (typeof sensor.findingsDigest === 'string' && HEX64.test(sensor.findingsDigest)) {
        const digestEsperado = calcularHashCanonico(achadosDoSensor);
        if (sensor.findingsDigest !== digestEsperado) {
          motivos.push(`sensor "${chave}" findingsDigest diverge do digest dos achados selados`);
        }
      }
    }

    for (const campo of ['configHash', 'findingsDigest']) {
      const valor = sensor[campo];
      if (valor !== null && valor !== undefined && !HEX64.test(String(valor))) {
        motivos.push(`sensor "${chave}" ${campo} inválido`);
      }
    }
  }
  return motivos;
}

// B4: valida os achados canônicos. Todo achado deve ser de um sensor conhecido e
// conter TODOS os campos canônicos com tipos exatos (nada de achado parcial).
function validarAchadosCanonicos(receipt) {
  const motivos = [];
  const canonicalContent = receipt?.canonicalContent;
  if (!ehObjeto(canonicalContent)) return ['canonicalContent ausente ou inválido'];
  const achados = Array.isArray(canonicalContent.findings) ? canonicalContent.findings : null;
  if (achados === null) {
    return ['canonicalContent.findings deve ser array'];
  }
  for (const [indice, a] of achados.entries()) {
    if (!ehObjeto(a)) {
      motivos.push(`achado canônico[${indice}] não é objeto`);
      continue;
    }
    if (typeof a.scanner !== 'string' || !sensoresCanonicos(receipt).includes(a.scanner)) {
      motivos.push(`achado canônico[${indice}] com scanner desconhecido ou inválido`);
    }
    if (typeof a.ruleId !== 'string') {
      motivos.push(`achado canônico[${indice}] sem ruleId canônico`);
    }
    if (typeof a.severity !== 'string' || !SEVERIDADES_VALIDAS.has(a.severity)) {
      motivos.push(`achado canônico[${indice}] sem severity canônica válida`);
    }
    if (typeof a.filePath !== 'string') {
      motivos.push(`achado canônico[${indice}] sem filePath canônico`);
    }
    if (a.categoria !== undefined && !CATEGORIAS_ACHADO_VALIDAS.has(a.categoria)) {
      motivos.push(`achado canônico[${indice}] com categoria inválida`);
    }
    if (a.estadoDeteccao !== undefined && a.estadoDeteccao !== 'DETECTADO') {
      motivos.push(`achado canônico[${indice}] com estado de detecção inválido`);
    }
    if (a.statusValidacao !== undefined && !STATUS_VALIDACAO_ACHADO_VALIDOS.has(a.statusValidacao)) {
      motivos.push(`achado canônico[${indice}] com status de validação inválido`);
    }
    if (typeof a.startLine !== 'number') {
      motivos.push(`achado canônico[${indice}] sem startLine numérico`);
    }
    if (typeof a.endLine !== 'number') {
      motivos.push(`achado canônico[${indice}] sem endLine numérico`);
    }
    if (typeof a.message !== 'string') {
      motivos.push(`achado canônico[${indice}] sem message canônica`);
    }
    // PL-03 · Fatia 1: quando presente, a identidade de símbolo selada precisa ter status reconhecido.
    if (a.identidadeSimbolo !== undefined && (!ehObjeto(a.identidadeSimbolo) || !STATUS_IDENTIDADE_SIMBOLO_VALIDOS.has(a.identidadeSimbolo.status))) {
      motivos.push(`achado canônico[${indice}] com identidadeSimbolo inválida`);
    }
  }
  if (typeof canonicalContent.findingsCount !== 'number' || canonicalContent.findingsCount !== achados.length) {
    motivos.push(`findingsCount global (${JSON.stringify(canonicalContent.findingsCount)}) diverge dos achados selados (${achados.length})`);
  }
  return motivos;
}

// B4: reconcilia cada sensor canônico com o portão que o evaluator deriva dele.
// Sensor falho, indisponível ou com achado incompatível não pode coexistir com o
// portão ATENDE (nem com ACCEPT).
function validarReconciliacaoSensorGate(receipt) {
  const motivos = [];
  const cc = receipt?.canonicalContent;
  const scannersSummary = cc?.scannersSummary;
  const gates = cc?.decision?.gates;
  if (!ehObjeto(scannersSummary) || !Array.isArray(gates)) return motivos;
  const achados = Array.isArray(cc.findings) ? cc.findings : [];

  // LC-06 (0.7.0): o portão Segredos deriva das DUAS partes do sensor (reconciliação própria abaixo).
  const segredosProprio = temSegredosProprio(receipt);
  if (segredosProprio) motivos.push(...reconciliarPortaoSegredos07(cc, achados));
  // 0.8.0, ou a projeção --json da CLI que carrega as revisões do pack de onde veio (o validador já exigiu coerência).
  const comRevisaoHumana = receipt.versao === '0.8.0'
    || (receipt?.outputProjection?.code === 'SAFE_FINGERPRINTED_V1' && receipt.versao === packageJson.version && Array.isArray(cc.humanReviews));
  for (const [sensorId, gateId] of Object.entries(SENSOR_GATE)) {
    if (segredosProprio && gateId === 'segredos') continue;
    const sensor = scannersSummary[sensorId];
    const gate = gates.find((g) => ehObjeto(g) && g.id === gateId);
    if (!ehObjeto(sensor) || !ehObjeto(gate)) continue;

    // PL-03: conta só o que BLOQUEIA — o efeito selado no significado (INFORMATIVO não bloqueia) e a identidade
    // de símbolo recusada (Fatia 1), espelhando achadoBloqueiaCodigoProprio. A coerência classe↔efeito do
    // significado é exigida pelo validador do pack 0.4.0, então o efeito não pode ser rebaixado isoladamente.
    const totalAchados = achados.filter((a) => ehObjeto(a)
      && a.scanner === sensorId
      && a.categoria !== 'TERCEIROS_DEPENDENCIAS'
      && a.categoria !== 'ARTEFATOS_GERADOS'
      && a.significado?.efeitoNaDecisao !== 'NAO_BLOQUEIA'
      && a.identidadeSimbolo?.status !== 'RECUSADA'
      // E2E mínimo (0.8.0): revisão humana ACEITA e coerente (REVISAO_NECESSARIA, chave e contexto) deixa de bloquear,
      // espelhando achadoBloqueiaCodigoProprio; o validador já recusou revisão incoerente ou fora do 0.8.0.
      && !(comRevisaoHumana && a.revisaoHumana?.estado === 'ACEITA' && problemasDaRevisaoSelada(a).length === 0)).length;
    // Fatia 1 (Scanner Completeness): sem achado e com completude não comprovada
    // (0.3.0), a ausência não comprova atendimento — o portão coerente é
    // NAO_COMPROVADO/MOTOR_FALHOU, espelhando a regra do avaliador.
    // PL-01 + PL-04 (0.6.0): sensor sem sinal de cobertura (sem modelo de completude) também não sustenta ATENDE — o
    // portão coerente é NAO_COMPROVADO/FORA_DE_COBERTURA_DO_MOTOR. Packs até 0.5.0 seguem a regra da época.
    const semCoberturaComprovavel = receipt.versao === '0.6.0'
      && ehObjeto(sensor.completeness) && !temModeloDeCompletude(sensor.completeness);
    const estadoEsperado = sensor.status === 'SUCCESS'
      ? (totalAchados > 0 ? 'NAO_ATENDE' : ((ausenciaNaoComprova(sensor.completeness) || semCoberturaComprovavel) ? 'NAO_COMPROVADO' : 'ATENDE'))
      : 'NAO_COMPROVADO';
    const subcausaEsperada = sensor.status === 'SUCCESS' && totalAchados === 0 && semCoberturaComprovavel
      ? 'FORA_DE_COBERTURA_DO_MOTOR'
      : 'MOTOR_FALHOU';

    // A projeção --json da CLI (versao = produto) não diz de qual versão de pack veio — como nas demais regras por
    // versão, aceita os dois estados coerentes para sensor sem sinal de cobertura: ATENDE (até 0.5.0) ou
    // NAO_COMPROVADO/FORA_DE_COBERTURA_DO_MOTOR (0.6.0). O pack em si (o que o SaaS ingere) exige a regra da versão.
    const ehProjecao = receipt?.outputProjection?.code === 'SAFE_FINGERPRINTED_V1';
    if (ehProjecao && sensor.status === 'SUCCESS' && totalAchados === 0
      && ehObjeto(sensor.completeness) && !temModeloDeCompletude(sensor.completeness)
      && gate.estado === 'NAO_COMPROVADO' && gate.subcausa === 'FORA_DE_COBERTURA_DO_MOTOR') {
      continue;
    }

    if (gate.estado !== estadoEsperado) {
      motivos.push(`gate "${gateId}" incoerente com o sensor "${sensorId}": sensor ${sensor.status} com ${totalAchados} achado(s) exige "${estadoEsperado}", recebido "${gate.estado}"`);
    } else if (estadoEsperado === 'NAO_COMPROVADO' && gate.subcausa !== subcausaEsperada) {
      motivos.push(`gate "${gateId}" NAO_COMPROVADO por sensor deve usar subcausa ${subcausaEsperada}`);
    }
  }
  return motivos;
}

// LC-06: estado do portão Segredos derivado SÓ de campos selados — mesma regra do avaliador (avaliarPortaoSegredos):
// achado que bloqueia (depois da baseline) ⇒ NAO_ATENDE; sensor falho ou working tree incompleto ⇒ NAO_COMPROVADO/
// MOTOR_FALHOU; histórico não demonstrado ⇒ NAO_COMPROVADO/FORA_DE_COBERTURA_DO_MOTOR; achado suprimido pela baseline
// do projeto ⇒ NAO_COMPROVADO/SEM_EVIDENCIA_DO_CLIENTE; senão ATENDE.
function reconciliarPortaoSegredos07(cc, achados) {
  const s = cc.scannersSummary;
  const arvore = s['zunvio-segredos'];
  const historico = s.gitleaks;
  const gate = Array.isArray(cc.decision?.gates) ? cc.decision.gates.find((g) => ehObjeto(g) && g.id === 'segredos') : null;
  if (!ehObjeto(arvore) || !ehObjeto(historico) || !ehObjeto(gate)) return ['portão Segredos ou sensores de segredos ausentes'];
  const bloqueia = (id) => achados.filter((a) => ehObjeto(a) && a.scanner === id
    && a.categoria !== 'TERCEIROS_DEPENDENCIAS' && a.categoria !== 'ARTEFATOS_GERADOS'
    && a.significado?.efeitoNaDecisao !== 'NAO_BLOQUEIA' && a.identidadeSimbolo?.status !== 'RECUSADA').length;
  const supr = (x) => (ehObjeto(x.suppressedByBaseline) ? x.suppressedByBaseline : { count: 0, blocking: 0 });
  const remanescentes = bloqueia('zunvio-segredos') + bloqueia('gitleaks') - supr(arvore).blocking - supr(historico).blocking;
  let estado = 'ATENDE';
  let subcausa = null;
  if (remanescentes > 0) estado = 'NAO_ATENDE';
  else if (arvore.status !== 'SUCCESS' || !['SUCCESS', 'NOT_RUN'].includes(historico.status)) { estado = 'NAO_COMPROVADO'; subcausa = 'MOTOR_FALHOU'; }
  else if (arvore.completeness?.status !== 'COMPLETE') { estado = 'NAO_COMPROVADO'; subcausa = 'MOTOR_FALHOU'; }
  else if (historico.completeness?.status !== 'COMPLETE') { estado = 'NAO_COMPROVADO'; subcausa = 'FORA_DE_COBERTURA_DO_MOTOR'; }
  else if (supr(arvore).count + supr(historico).count > 0) { estado = 'NAO_COMPROVADO'; subcausa = 'SEM_EVIDENCIA_DO_CLIENTE'; }
  if (gate.estado !== estado) return [`gate "segredos" incoerente com os sensores de segredos (working tree + histórico): exige "${estado}", recebido "${gate.estado}"`];
  if (estado === 'NAO_COMPROVADO' && gate.subcausa !== subcausa) return [`gate "segredos" NAO_COMPROVADO deve usar subcausa ${subcausa}`];
  return [];
}

// Valida a coerência interna entre score, cobertura, gates e decisão usando as
// regras públicas de peso/estado já existentes (sem tocar no avaliador), exige
// o conjunto canônico de sete portões (B3) e deriva o outcome exato dos gates
// e da integridade (P2).
function validarCoerencia(receipt, integridadeOk) {
  const motivos = [];
  const decisao = receipt?.canonicalContent?.decision;
  if (!ehObjeto(decisao)) {
    return ['decision ausente ou inválida'];
  }
  const gates = Array.isArray(decisao.gates) ? decisao.gates : null;
  if (!gates) {
    return ['decision.gates ausente ou inválido'];
  }

  validarGatesCanonicos(gates, motivos);

  let scoreEsperado = 0;
  let coberturaEsperada = 0;
  let pesoDesconhecido = 0;
  // MASS-307: separa reprovação comprovada (NAO_ATENDE/bypass) de não comprovado
  // (NAO_COMPROVADO) para derivar o outcome em três estados (ACCEPT/REJECT/UNPROVEN).
  let temBloqueadorComprovado = false;
  let temInconclusivo = false;
  const bloqueadores = [];

  for (const gate of gates) {
    if (!ehObjeto(gate)) continue;
    // Peso já validado como número real em validarGatesCanonicos; sem coerção.
    const peso = typeof gate.peso === 'number' ? gate.peso : 0;
    const estado = gate.estado;
    if (estado === 'ATENDE') scoreEsperado += peso;
    if (estado !== 'NAO_COMPROVADO') coberturaEsperada += peso;
    if (estado === 'NAO_COMPROVADO') pesoDesconhecido += peso;

    // P2: tipo canônico estrito de `bloqueadores` em TODOS os gates. Qualquer
    // valor não-array (string, objeto, null, número, booleano) é rejeitado,
    // mesmo quando o array não seria usado na derivação do outcome. Cada item
    // do array também precisa ser string.
    if (!Object.hasOwn(gate, 'bloqueadores')) {
      motivos.push(`gate "${gate.id}" sem campo bloqueadores canônico`);
    } else if (!Array.isArray(gate.bloqueadores)) {
      motivos.push(`gate "${gate.id}" bloqueadores deve ser array (recebido ${typeof gate.bloqueadores})`);
    } else {
      for (const [bi, b] of gate.bloqueadores.entries()) {
        if (typeof b !== 'string') {
          motivos.push(`gate "${gate.id}" bloqueadores[${bi}] deve ser string (recebido ${typeof b})`);
        }
      }
    }

    // B3: um portão obrigatório jamais pode ser NÃO APLICÁVEL (bypass de gate).
    if (gate.obrigatorio === true && estado === 'NAO_APLICAVEL') {
      temBloqueadorComprovado = true;
      motivos.push(`portão obrigatório "${gate.id}" declarado NÃO APLICÁVEL sem exceção coerente`);
    }
    // MASS-307: NAO_ATENDE = reprovação comprovada (REJECT); NAO_COMPROVADO =
    // sem prova de atendimento nem de reprovação (UNPROVEN).
    if (gate.obrigatorio === true && estado === 'NAO_ATENDE') {
      temBloqueadorComprovado = true;
    }
    if (gate.obrigatorio === true && estado === 'NAO_COMPROVADO') {
      temInconclusivo = true;
    }

    // P2: um portão ATENDE jamais emite bloqueadores (o evaluator não emite).
    if (estado === 'ATENDE' && Array.isArray(gate.bloqueadores) && gate.bloqueadores.length > 0) {
      motivos.push(`gate "${gate.id}" ATENDE não pode declarar bloqueadores`);
    } else if (Array.isArray(gate.bloqueadores)) {
      bloqueadores.push(...gate.bloqueadores.filter((b) => typeof b === 'string'));
    }
  }

  const maximoEsperado = scoreEsperado + pesoDesconhecido;

  if (decisao.score !== scoreEsperado) {
    motivos.push(`score incoerente: declarado ${decisao.score}, esperado ${scoreEsperado}`);
  }
  const coberturaContrato = receipt?.canonicalContent?.publicationContextCoverage
    ?? receipt?.canonicalContent?.claimEvidenceMap?.coverage;
  const coberturaFinalEsperada = Number.isInteger(coberturaContrato)
    ? Math.min(coberturaEsperada, coberturaContrato)
    : coberturaEsperada;
  if (decisao.coverage !== coberturaFinalEsperada) {
    motivos.push(`cobertura incoerente: declarada ${decisao.coverage}, esperada ${coberturaFinalEsperada}`);
  }
  if (decisao.maxPossibleScore !== maximoEsperado) {
    motivos.push(`maxPossibleScore incoerente: declarado ${decisao.maxPossibleScore}, esperado ${maximoEsperado}`);
  }

  // P2/B3/MASS-307: o outcome deve ser exatamente derivável dos gates e da
  // integridade em TRÊS estados canônicos:
  //   - REJECT:  reprovação comprovada (portão obrigatório NAO_ATENDE/bypass) ou
  //              integridade violada (prova de que o alvo mudou).
  //   - UNPROVEN: sem reprovação comprovada, mas com portão obrigatório NÃO
  //              COMPROVADO (sensor ausente/falhou/timeout/truncado, alvo fora de
  //              cobertura, evidência do cliente ausente, integridade não
  //              comprovada) ou cobertura abaixo do mínimo.
  //   - ACCEPT:  todos os obrigatórios ATENDE, cobertura mínima e integridade OK.
  const coberturaInsuficiente = coberturaFinalEsperada < COBERTURA_MINIMA_PUBLICACAO;
  let outcomeEsperado;
  if (temBloqueadorComprovado || !integridadeOk) {
    outcomeEsperado = OUTCOME_CANONICO.REJECT;
  } else if (temInconclusivo || coberturaInsuficiente) {
    outcomeEsperado = OUTCOME_CANONICO.UNPROVEN;
  } else {
    outcomeEsperado = OUTCOME_CANONICO.ACCEPT;
  }
  if (decisao.outcome !== outcomeEsperado) {
    motivos.push(`outcome incoerente: declarado ${decisao.outcome}, esperado ${outcomeEsperado}`);
  }

  return motivos;
}

function montarResultado(resultado, motivos) {
  const rotulo = resultado === RESULTADO.VALIDO
    ? ROTULO_INTEGRIDADE_INTERNA
    : resultado === RESULTADO.NAO_SUPORTADO
      ? 'NÃO SUPORTADO'
      : 'INVÁLIDO';
  return { resultado, rotulo, motivos };
}

/**
 * Verifica um Score Receipt (Evidence Pack) re-hidratado de JSON.
 * Retorna { resultado, rotulo, motivos }. O hash prova integridade/coerência
 * internas, não autenticidade de origem (B9).
 */
export function verificarReceipt(receipt) {
  if (!ehObjeto(receipt)) {
    return montarResultado(RESULTADO.INVALIDO, ['receipt não é um objeto JSON']);
  }

  const versao = receipt.versao;
  if (!VERSOES_SUPORTADAS.has(versao)) {
    const motivo = versao === undefined
      ? 'versão ausente'
      : `versão não suportada: ${versao}`;
    return montarResultado(RESULTADO.NAO_SUPORTADO, [motivo]);
  }

  // Schema + hash canônico (reusa o validador já aprovado; confere que o hash
  // declarado corresponde ao conteúdo canônico).
  const validacao = validarEvidencePackV0(receipt);
  if (!validacao.valido) {
    return montarResultado(RESULTADO.INVALIDO, validacao.erros);
  }

  const motivos = [];

  const sha = extrairShaRelease(receipt);
  const gateProveniencia = receipt.canonicalContent?.decision?.gates?.find(
    (gate) => gate?.id === 'proveniencia_auditabilidade'
  );
  // Um alvo sem Git pode produzir um receipt internamente íntegro, mas sua
  // decisão permanece inconclusiva pelo gate obrigatório NAO_COMPROVADO. SHA
  // auditável só é obrigatório quando o próprio gate declara ATENDE.
  if (!sha && gateProveniencia?.estado === 'ATENDE') {
    motivos.push('release/HEAD ausente ou sem vínculo auditável');
  }

  const integridadeOk = validarIntegridade(receipt, motivos);
  motivos.push(...validarCoerencia(receipt, integridadeOk));
  motivos.push(...validarSensores(receipt));
  motivos.push(...validarAchadosCanonicos(receipt));
  motivos.push(...validarReconciliacaoSensorGate(receipt));

  return motivos.length === 0
    ? montarResultado(RESULTADO.VALIDO, [])
    : montarResultado(RESULTADO.INVALIDO, motivos);
}
