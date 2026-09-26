import schemaEvidencePack from './evidence-pack-v0.schema.json' with { type: 'json' };
import { calcularHashCanonico, serializarJsonCanonico } from '../utils/canonical-json.mjs';
import { validarMapaClaimEvidence } from '../decision/claim-evidence-map.mjs';
import packageJson from '../../package.json' with { type: 'json' };
import {
  ausenciaNaoComprova,
  problemasDeCoerencia,
  MARCA_RISCO_INCOMPLETO,
  MARCA_RISCO_INTEGRAL,
  problemasDoHistorico
} from '../models/completeness.mjs';
import { problemasDoSignificado } from '../models/finding-meaning.mjs';
import { problemasDaRevisaoSelada, ESTADOS_REVISAO } from '../models/human-review.mjs';
import { problemasDoUniverso, TETO_ARQUIVOS_AFETADOS } from '../models/expected-universe.mjs';

const ESTADOS_PUBLICOS = new Set(['ATENDE', 'NAO_ATENDE', 'NAO_COMPROVADO', 'NAO_APLICAVEL']);
const SUBCAUSAS_NAO_COMPROVADO = new Set([
  'SEM_EVIDENCIA_DO_CLIENTE',
  'FORA_DE_COBERTURA_DO_MOTOR',
  'MOTOR_FALHOU'
]);
const VERSAO_SCHEMA_DECISORIA = '0.2.0';
// Fatia 1 (Scanner Completeness): 0.3.0 = 0.2.0 + completude por scanner
// (canônica) + limitations estruturadas + metadados de reconstrução.
const VERSAO_COMPLETUDE = '0.3.0';
// PL-03 (fechamento): 0.4.0 = 0.3.0 + significado selado por achado do Gitleaks/Semgrep.
const VERSAO_SIGNIFICADO = '0.4.0';
// PL-02: 0.5.0 = 0.4.0 + universo esperado por scanner na completude.
const VERSAO_UNIVERSO = '0.5.0';
// PL-01 + PL-04: 0.6.0 = 0.5.0 com sinais de confiança derivados da completude.
const VERSAO_CONFIANCA = '0.6.0';
// LC-06: 0.7.0 = 0.6.0 + sensor de segredos em duas partes (scanner próprio no working tree + Gitleaks no histórico).
const VERSAO_SEGREDOS = '0.7.0';
// E2E mínimo: 0.8.0 = 0.7.0 + revisão humana registrável (humanReviews + revisaoHumana selada no achado aceito).
const VERSAO_REVISAO = '0.8.0';
const VERSOES_CONHECIDAS = new Set(['0.1.0', VERSAO_SCHEMA_DECISORIA, VERSAO_COMPLETUDE, VERSAO_SIGNIFICADO, VERSAO_UNIVERSO, VERSAO_CONFIANCA, VERSAO_SEGREDOS, VERSAO_REVISAO, packageJson.version]);
const temUniversoSelado = (v) => v === VERSAO_UNIVERSO || v === VERSAO_CONFIANCA || v === VERSAO_SEGREDOS || v === VERSAO_REVISAO;
const temRegrasDeConfianca = (v) => v === VERSAO_CONFIANCA || v === VERSAO_SEGREDOS || v === VERSAO_REVISAO;
const temSegredosEmDuasPartes = (v) => v === VERSAO_SEGREDOS || v === VERSAO_REVISAO;
/** Sensores canônicos cuja completude o pack sela (o 0.7.0 acrescenta o scanner próprio de segredos). */
const sensoresDoPack = (cc) => (cc?.scannersSummary && Object.hasOwn(cc.scannersSummary, 'zunvio-segredos') ? ['gitleaks', 'zunvio-segredos', 'semgrep'] : ['gitleaks', 'semgrep']);

const HEX64_SEG = /^[0-9a-f]{64}$/;
const naoNeg = (n) => Number.isInteger(n) && n >= 0;

// LC-06 (0.7.0): as duas coberturas de segredos são seladas e coerentes, e o portão Segredos nunca afirma mais que elas.
function validarSegredos07(cc, erros) {
  const s = cc.scannersSummary || {};
  const arvore = s['zunvio-segredos'];
  const historico = s.gitleaks;
  if (!arvore || typeof arvore !== 'object') { erros.push('Evidence Pack 0.7.0 exige canonicalContent.scannersSummary[\'zunvio-segredos\']'); return; }
  const ch = historico?.completeness;
  if (!ch || typeof ch !== 'object' || ch.history === undefined) erros.push('Evidence Pack 0.7.0 exige canonicalContent.scannersSummary.gitleaks.completeness.history');
  else for (const p of problemasDoHistorico(ch)) erros.push(`canonicalContent.scannersSummary.gitleaks.completeness.${p}`);
  const ca = arvore.completeness;
  if (ca?.status === 'COMPLETE' && ca.universe?.coverage?.source !== 'ALL_FILES_SENT') erros.push('canonicalContent.scannersSummary[\'zunvio-segredos\'].completeness: COMPLETE exige o universo de todos os arquivos enviados');
  const d = arvore.coverageDetail;
  if (!d || typeof d !== 'object' || d.model !== 'lc06-1.0' || !naoNeg(d.bytesRead) || !d.policyExclusions || !naoNeg(d.policyExclusions.count)
    || !HEX64_SEG.test(d.policyExclusions.digest || '') || !d.notInspected || !naoNeg(d.notInspected.count) || !HEX64_SEG.test(d.notInspected.digest || '')
    || typeof d.universeDetermined !== 'boolean') {
    erros.push('canonicalContent.scannersSummary[\'zunvio-segredos\'].coverageDetail fora do modelo');
  } else if (ca?.universe && Number.isInteger(ca.universe.byReason?.UNSUPPORTED_EXTENSION ?? 0) && (ca.universe.byReason?.UNSUPPORTED_EXTENSION ?? 0) !== d.notInspected.count) {
    erros.push('canonicalContent.scannersSummary[\'zunvio-segredos\']: formatos não inspecionados divergem do universo');
  }
  for (const [id, sensor] of [['zunvio-segredos', arvore], ['gitleaks', historico]]) {
    const b = sensor?.suppressedByBaseline;
    if (!b || !naoNeg(b.count) || !naoNeg(b.blocking) || b.blocking > b.count) erros.push(`canonicalContent.scannersSummary.${id}.suppressedByBaseline fora do modelo`);
  }
  const portao = Array.isArray(cc.decision?.gates) ? cc.decision.gates.find((g) => g && g.id === 'segredos') : null;
  if (portao && portao.estado === 'ATENDE') {
    const suprimidos = (arvore.suppressedByBaseline?.count || 0) + (historico?.suppressedByBaseline?.count || 0);
    if (ca?.status !== 'COMPLETE' || ch?.status !== 'COMPLETE' || suprimidos > 0) {
      erros.push('canonicalContent.decision: Segredos ATENDE sem as duas coberturas completas ou com achado suprimido pela baseline do projeto');
    }
  }
}

// PL-01 + PL-04 (0.6.0): o agregado UNKNOWN nunca fica silencioso, e nenhum portão afirma mais do que a evidência.
// - sensor sem sinal de cobertura (UNKNOWN sem modelo) com o universo enviado conhecido tem limitação COMPLETENESS_UNKNOWN;
// - limite operacional do inventário atingido (limitação LIMIT_EXCEEDED de origem 'inventory') ⇒ integridade não é ATENDE.
function validarConfianca06(cc, erros) {
  const limitacoes = Array.isArray(cc.limitations) ? cc.limitations : [];
  for (const id of sensoresDoPack(cc)) {
    const c = cc.scannersSummary?.[id]?.completeness;
    if (!c || typeof c !== 'object') continue;
    const semModelo = c.status === 'UNKNOWN' && c.criterion === 'SCANNER_WITHOUT_COMPLETENESS_MODEL';
    if (semModelo && c.universe && !limitacoes.some((l) => l && l.scanner === id && l.code === 'COMPLETENESS_UNKNOWN')) {
      erros.push(`canonicalContent.limitations não pode omitir a limitação COMPLETENESS_UNKNOWN do scanner ${id} (cobertura não comprovável)`);
    }
  }
  const limiteAtingido = limitacoes.some((l) => l && l.code === 'LIMIT_EXCEEDED' && l.source === 'inventory');
  const integridade = Array.isArray(cc.decision?.gates) ? cc.decision.gates.find((g) => g && g.id === 'integridade') : null;
  if (limiteAtingido && integridade && integridade.estado === 'ATENDE') {
    erros.push('canonicalContent.decision: integridade ATENDE com o limite operacional atingido (integridade verificada só em parte)');
  }
}
const CRITERIOS_DE_UNIVERSO = new Set(['SUCCESS_EXPECTED_UNIVERSE_ANALYZED', 'SUCCESS_WITH_UNANALYZED_EXPECTED_FILES']);
const HEX64_DIGEST = /^[0-9a-f]{64}$/;

// PL-02: o universo esperado selado é coerente (contagens fecham; COMPLETE ⇒ nada esperado fora da análise;
// sem sinal de cobertura ⇒ nada afirmado) e a lista de arquivos respeita o teto com digest auditável.
function validarUniverso05(cc, erros) {
  for (const id of sensoresDoPack(cc)) {
    const c = cc.scannersSummary?.[id]?.completeness;
    if (!c || typeof c !== 'object') continue;
    // LC-06: a completude do histórico Git (0.7.0) é por commits, não por arquivos — validada em validarSegredos07.
    if (c.history !== undefined) continue;
    if (CRITERIOS_DE_UNIVERSO.has(c.criterion) && c.universe === undefined) {
      erros.push(`canonicalContent.scannersSummary.${id}.completeness: critério ${c.criterion} exige o universo esperado`);
    }
    if (c.universe !== undefined) {
      for (const problema of problemasDoUniverso(c.universe, c)) erros.push(`canonicalContent.scannersSummary.${id}.completeness.${problema}`);
    }
    // Revisão r1 (B1): no 0.5.0, COMPLETE só é comprovado contra o universo esperado. O critério da Fatia 1 sem
    // universo não sustenta COMPLETE (senão bastaria trocar o critério e apagar o universo para esconder a lacuna).
    if (c.status === 'COMPLETE' && (c.criterion !== 'SUCCESS_EXPECTED_UNIVERSE_ANALYZED' || c.universe === undefined)) {
      erros.push(`canonicalContent.scannersSummary.${id}.completeness: COMPLETE no 0.5.0 exige o critério e o universo esperado`);
    }
    if (Array.isArray(c.affectedFiles) && c.affectedFiles.length > TETO_ARQUIVOS_AFETADOS) {
      erros.push(`canonicalContent.scannersSummary.${id}.completeness.affectedFiles acima do teto (${TETO_ARQUIVOS_AFETADOS})`);
    }
    // Revisão r2: marcar truncada uma lista que não foi truncada é incoerente.
    if (c.affectedFilesTruncated === true && Array.isArray(c.affectedFiles) && Number.isInteger(c.affectedFileCount) && c.affectedFileCount <= c.affectedFiles.length) {
      erros.push(`canonicalContent.scannersSummary.${id}.completeness: affectedFilesTruncated sem truncamento`);
    }
    if (Array.isArray(c.affectedFiles) && Number.isInteger(c.affectedFileCount) && c.affectedFileCount > c.affectedFiles.length) {
      if (c.affectedFilesTruncated !== true || !HEX64_DIGEST.test(c.affectedFilesDigest || '')) {
        erros.push(`canonicalContent.scannersSummary.${id}.completeness: lista truncada exige affectedFilesTruncated e affectedFilesDigest`);
      }
    }
  }
}
const SCANNERS_COM_SIGNIFICADO = new Set(['gitleaks', 'zunvio-segredos', 'semgrep']);

// PL-03: no 0.4.0 o achado do Gitleaks/Semgrep carrega significado (os scanners sempre o produzem) e, quando
// presente, ele precisa ser coerente — o efeito na decisão sai dele. Ausente, o achado vale pela regra anterior
// (BLOQUEIA): a ausência só pode tornar a decisão mais conservadora, nunca liberar publicação.
function validarSignificados04(cc, erros) {
  if (!Array.isArray(cc.findings)) return;
  for (const [i, a] of cc.findings.entries()) {
    if (!a || typeof a !== 'object' || !SCANNERS_COM_SIGNIFICADO.has(a.scanner) || a.significado === undefined) continue;
    const identidade = a.ruleId === 'zunvio.child-process-exec' ? (a.identidadeSimbolo ?? null) : undefined;
    for (const problema of problemasDoSignificado(a.significado, identidade)) {
      erros.push(`canonicalContent.findings[${i}]: ${problema}`);
    }
  }
}
const ESTADOS_COMPLETUDE = new Set(['COMPLETE', 'PARTIAL', 'DEGRADED', 'UNKNOWN']);

const ESTADOS_REVISAO_VALIDOS = new Set(Object.values(ESTADOS_REVISAO));
const HEX16 = /^[0-9a-f]{16}$/;
/**
 * E2E mínimo (0.8.0): revisão humana registrável. Toda revisão registrada fica em `humanReviews` com o estado calculado;
 * só a ACEITA fica selada no achado (`revisaoHumana`), e só pode existir num achado do Semgrep REVISAO_NECESSARIA com
 * chave e contexto iguais. Fora do 0.8.0, nenhuma revisão pode aparecer (não se destrava achado sem declarar a versão).
 */
function validarRevisoesHumanas(cc, eh08, erros) {
  const achados = Array.isArray(cc?.findings) ? cc.findings : [];
  const revisados = achados.map((a, i) => [a, i]).filter(([a]) => a && typeof a === 'object' && a.revisaoHumana !== undefined);
  if (!eh08) {
    if (revisados.length > 0 || cc?.humanReviews !== undefined) erros.push('revisão humana só é aceita no Evidence Pack 0.8.0');
    return;
  }
  const lista = cc?.humanReviews;
  if (!Array.isArray(lista) || lista.length === 0) {
    erros.push('Evidence Pack 0.8.0 exige canonicalContent.humanReviews com ao menos uma revisão registrada');
    return;
  }
  for (const [i, r] of lista.entries()) {
    const ok = r && typeof r === 'object' && ESTADOS_REVISAO_VALIDOS.has(r.estado) && HEX16.test(r.chaveRevisao ?? '') && HEX16.test(r.contextoRevisao ?? '')
      && r.classificacaoOriginal === 'REVISAO_NECESSARIA' && typeof r.autor === 'string' && r.autor.trim() && typeof r.data === 'string' && r.data.trim()
      && typeof r.justificativa === 'string' && r.justificativa.trim().length >= 10;
    if (!ok) erros.push(`canonicalContent.humanReviews[${i}] fora do modelo`);
  }
  for (const [a, i] of revisados) {
    if (a.scanner !== 'semgrep') erros.push(`canonicalContent.findings[${i}]: revisão humana só vale para achado de código (Semgrep)`);
    for (const problema of problemasDaRevisaoSelada(a)) erros.push(`canonicalContent.findings[${i}]: ${problema}`);
  }
  const aceitas = lista.filter((r) => r?.estado === 'ACEITA');
  const chavesSeladas = revisados.map(([a]) => a.chaveRevisao).sort();
  const chavesAceitas = aceitas.map((r) => r.chaveRevisao).sort();
  if (JSON.stringify(chavesSeladas) !== JSON.stringify(chavesAceitas)) {
    erros.push('canonicalContent.humanReviews: as revisões ACEITAS não correspondem aos achados com revisaoHumana selada');
  }
}

function validarCompletude03(cc, erros, residualRiskStatement) {
  if (!cc.completeness || typeof cc.completeness !== 'object' || !ESTADOS_COMPLETUDE.has(cc.completeness.status)) {
    erros.push('Evidence Pack 0.3.0 exige canonicalContent.completeness.status em COMPLETE|PARTIAL|DEGRADED|UNKNOWN');
  }
  const porScanner = {};
  for (const id of sensoresDoPack(cc)) {
    const c = cc.scannersSummary?.[id]?.completeness;
    if (!c || typeof c !== 'object' || !ESTADOS_COMPLETUDE.has(c.status)) {
      erros.push(`Evidence Pack 0.3.0 exige canonicalContent.scannersSummary.${id}.completeness.status válido`);
      continue;
    }
    if (!Array.isArray(c.reasons) || !Array.isArray(c.affectedFiles) || !Number.isInteger(c.affectedFileCount)) {
      erros.push(`canonicalContent.scannersSummary.${id}.completeness deve ter reasons[], affectedFiles[] e affectedFileCount inteiro`);
    }
    // Revisão r1, achado 1: critério fora do modelo ou incoerente com o estado (ex.:
    // PARTIAL rotulado "sem modelo") desligaria a proteção; é recusado.
    for (const problema of problemasDeCoerencia(id, c)) erros.push(`canonicalContent.scannersSummary.${id}.completeness: ${problema}`);
    porScanner[id] = c;
  }
  if (Array.isArray(cc.limitations)) {
    for (const [i, l] of cc.limitations.entries()) {
      if (!l || typeof l !== 'object' || typeof l.code !== 'string' || typeof l.whatWasNotVerified !== 'string'
        || typeof l.impact !== 'string' || !Array.isArray(l.why?.reasons) || !l.where || typeof l.where !== 'object') {
        erros.push(`canonicalContent.limitations[${i}] deve ser limitação estruturada (code, whatWasNotVerified, where, why.reasons, impact)`);
      }
    }
    // Regra da Fatia 1: scanner com modelo que não provou completude (PARTIAL,
    // DEGRADED ou UNKNOWN por falta de sinais) nunca convive com limitations sem a
    // entrada dele. Scanner sem modelo (NOT_EVALUATED) não gera limitação.
    for (const [id, c] of Object.entries(porScanner)) {
      if (ausenciaNaoComprova(c) && !cc.limitations.some((l) => l && l.scanner === id)) {
        erros.push(`canonicalContent.limitations não pode omitir a limitação do scanner ${id} (${c.status})`);
      }
    }
  }
  // Revisão r1, achado 2: coverageAndResidualRisk fica fora do canonicalHash (desde o
  // 0.2.0). A frase não pode contradizer a completude protegida: com análise não
  // comprovadamente completa, ela declara a incompletude e nunca "100% de integridade".
  if (Object.values(porScanner).some((c) => ausenciaNaoComprova(c))) {
    const frase = typeof residualRiskStatement === 'string' ? residualRiskStatement : '';
    if (!frase.includes(MARCA_RISCO_INCOMPLETO) || frase.includes(MARCA_RISCO_INTEGRAL)) {
      erros.push(`coverageAndResidualRisk.residualRiskStatement contradiz a completude canônica: deve declarar "${MARCA_RISCO_INCOMPLETO}" e não "${MARCA_RISCO_INTEGRAL}"`);
    }
  }
  // Revisão r1, achado 3: a identidade da execução é canônica; quando presente, forma mínima.
  if (cc.execution !== undefined) {
    const eng = cc.execution?.engine;
    if (!eng || typeof eng !== 'object' || eng.name !== 'zunvio-score' || typeof eng.version !== 'string'
      || !(eng.commit === null || /^[0-9a-f]{40}$/.test(eng.commit ?? ''))
      || !(eng.dirty === null || typeof eng.dirty === 'boolean')
      || !/^[0-9a-f]{64}$/.test(eng.codeDigest ?? '')) {
      erros.push('canonicalContent.execution.engine deve ter name, version, commit (SHA ou null), dirty (boolean ou null) e codeDigest (SHA-256)');
    }
  }
  // O agregado é o pior estado entre os scanners (DEGRADED > PARTIAL > UNKNOWN > COMPLETE),
  // mesma regra do adaptador do SaaS; divergência é defeito do produtor.
  const ordem = ['COMPLETE', 'UNKNOWN', 'PARTIAL', 'DEGRADED'];
  const estados = Object.values(porScanner).map((c) => c.status);
  if (estados.length === sensoresDoPack(cc).length && cc.completeness && ESTADOS_COMPLETUDE.has(cc.completeness.status)) {
    const pior = estados.reduce((acc, e) => (ordem.indexOf(e) > ordem.indexOf(acc) ? e : acc), 'COMPLETE');
    if (cc.completeness.status !== pior) {
      erros.push(`canonicalContent.completeness.status (${cc.completeness.status}) diverge do pior estado dos scanners (${pior})`);
    }
  }
}

/**
 * Validador estrutural determinístico do Evidence Pack v0.
 * @param {object} evidencePack
 * @param {{ finalidade?: 'DECISAO' | 'SELO' | 'APROVACAO' | 'COMPARACAO_DECISORIA' | 'HISTORICO' }} [opcoes]
 * @returns {{ valido: boolean, erros: string[] }}
 */
export function validarEvidencePackV0(evidencePack, { finalidade = 'DECISAO' } = {}) {
  const erros = [];

  if (!evidencePack || typeof evidencePack !== 'object') {
    return { valido: false, erros: ['Evidence pack deve ser um objeto não nulo'] };
  }

  // 1. Campos de primeiro nível obrigatórios
  // A projeção segura do CLI identifica explicitamente sua versão de produto
  // no topo, mas mantém o contrato decisório moderno protegido pelo hash.
  // O marcador distingue essa saída dos packs legados 0.1.0 históricos.
  const ehProjecaoCliAtual = evidencePack.versao === packageJson.version
    && evidencePack.outputProjection?.code === 'SAFE_FINGERPRINTED_V1';
  const ehPackDecisorio = evidencePack.versao === VERSAO_SCHEMA_DECISORIA
    || evidencePack.versao === VERSAO_COMPLETUDE
    || evidencePack.versao === VERSAO_SIGNIFICADO
    || evidencePack.versao === VERSAO_UNIVERSO
    || evidencePack.versao === VERSAO_CONFIANCA
    || evidencePack.versao === VERSAO_SEGREDOS
    || evidencePack.versao === VERSAO_REVISAO
    || ehProjecaoCliAtual;

  const camposObrigatorios = [
    'versao',
    'target',
    'canonicalHash',
    'canonicalContent',
    'volatileMetadata',
    'integrityProof',
    'decision',
    'coverageAndResidualRisk'
  ];

  for (const campo of camposObrigatorios) {
    if (evidencePack[campo] === undefined || evidencePack[campo] === null) {
      erros.push(`Campo obrigatório ausente: '${campo}'`);
    }
  }

  // 2. Validação da versão
  if (!VERSOES_CONHECIDAS.has(evidencePack.versao)) {
    erros.push(`Versão inválida: '${evidencePack.versao}'. Esperadas: '0.1.0', '0.2.0', '0.3.0', '0.4.0', '0.5.0', '0.6.0', '0.7.0' ou '0.8.0'`);
  }
  if (evidencePack.versao === '0.1.0' && !ehProjecaoCliAtual && finalidade !== 'HISTORICO') {
    erros.push(`Evidence Pack 0.1.0 é aceito somente como evidência histórica; seu uso decisório falha fechado porque decision não integra o canonicalHash`);
  }

  // 3. Validação do canonicalHash
  if (typeof evidencePack.canonicalHash !== 'string' || !/^[a-f0-9]{64}$/.test(evidencePack.canonicalHash)) {
    erros.push(`canonicalHash inválido: esperado SHA-256 de 64 caracteres hexadecimais`);
  }

  // 4. Validação de canonicalContent
  const cc = evidencePack.canonicalContent;
  if (ehPackDecisorio && cc?.decision === undefined) {
    erros.push(`Evidence Pack 0.2.0 exige canonicalContent.decision protegido pelo canonicalHash`);
  }
  if (cc && typeof cc === 'object') {
    if (typeof cc.filesAnalyzed !== 'number' || cc.filesAnalyzed < 0) {
      erros.push(`canonicalContent.filesAnalyzed deve ser inteiro >= 0`);
    }
    if (typeof cc.inventoryDigest !== 'string' || !/^[a-f0-9]{64}$/.test(cc.inventoryDigest)) {
      erros.push(`canonicalContent.inventoryDigest deve ser SHA-256 de 64 caracteres`);
    }
    if (cc.targetDigest !== undefined && (typeof cc.targetDigest !== 'string' || !/^[a-f0-9]{64}$/.test(cc.targetDigest))) {
      erros.push(`canonicalContent.targetDigest deve ser SHA-256 de 64 caracteres`);
    }
    if (cc.publicationContextCoverage !== undefined && (!Number.isInteger(cc.publicationContextCoverage) || cc.publicationContextCoverage < 0 || cc.publicationContextCoverage > 100)) {
      erros.push(`canonicalContent.publicationContextCoverage deve ser inteiro entre 0 e 100`);
    }
    if (!Array.isArray(cc.findings)) {
      erros.push(`canonicalContent.findings deve ser um array`);
    }
    if (!Array.isArray(cc.exclusions)) {
      erros.push(`canonicalContent.exclusions deve ser um array`);
    }
    if (!Array.isArray(cc.limitations)) {
      erros.push(`canonicalContent.limitations deve ser um array`);
    }
    if (evidencePack.versao === VERSAO_COMPLETUDE || evidencePack.versao === VERSAO_SIGNIFICADO || temUniversoSelado(evidencePack.versao)) {
      validarCompletude03(cc, erros, evidencePack.coverageAndResidualRisk?.residualRiskStatement);
    }
    if (evidencePack.versao === VERSAO_SIGNIFICADO || temUniversoSelado(evidencePack.versao)) {
      validarSignificados04(cc, erros);
    }
    if (temUniversoSelado(evidencePack.versao)) {
      validarUniverso05(cc, erros);
    }
    if (temRegrasDeConfianca(evidencePack.versao)) {
      validarConfianca06(cc, erros);
    }
    if (temSegredosEmDuasPartes(evidencePack.versao)) {
      validarSegredos07(cc, erros);
    }
    // E2E mínimo: revisão humana só existe (e só pode destravar achado) no 0.8.0, e só coerente.
    // A projeção --json da CLI atual (versao = produto) carrega as revisões do pack 0.8.0 de onde veio.
    validarRevisoesHumanas(cc, evidencePack.versao === VERSAO_REVISAO || (ehProjecaoCliAtual && cc.humanReviews !== undefined), erros);
    if (
      typeof evidencePack.canonicalHash === 'string' &&
      calcularHashCanonico(cc) !== evidencePack.canonicalHash
    ) {
      erros.push(`canonicalHash não corresponde ao canonicalContent`);
    }
  }

  // 4.1. Claim-to-Evidence Map v1 é aditivo, mas, quando presente, deve ser
  // formalmente válido, idêntico nos dois níveis e protegido pelo canonicalHash.
  if (evidencePack.claimEvidenceMap !== undefined) {
    const validacaoMapa = validarMapaClaimEvidence(evidencePack.claimEvidenceMap);
    for (const erro of validacaoMapa.erros) erros.push(`claimEvidenceMap: ${erro}`);
    if (cc?.claimEvidenceMap === undefined) {
      erros.push('claimEvidenceMap deve integrar canonicalContent.');
    } else if (
      serializarJsonCanonico(cc.claimEvidenceMap)
      !== serializarJsonCanonico(evidencePack.claimEvidenceMap)
    ) {
      erros.push('claimEvidenceMap diverge de canonicalContent.claimEvidenceMap.');
    }
  } else if (cc?.claimEvidenceMap !== undefined) {
    erros.push('canonicalContent.claimEvidenceMap exige claimEvidenceMap no primeiro nível.');
  }

  // 5. Validação de volatileMetadata
  const vm = evidencePack.volatileMetadata;
  if (vm && typeof vm === 'object') {
    if (typeof vm.timestamp !== 'string') {
      erros.push(`volatileMetadata.timestamp deve ser string ISO`);
    }
    if (typeof vm.durationMs !== 'number' || vm.durationMs < 0) {
      erros.push(`volatileMetadata.durationMs deve ser número >= 0`);
    }
  }

  // 6. Validação de integrityProof
  const ip = evidencePack.integrityProof;
  if (ip && typeof ip === 'object') {
    if (typeof ip.immutable !== 'boolean') {
      erros.push(`integrityProof.immutable deve ser boolean`);
    }
    if (typeof ip.initialDigest !== 'string' || typeof ip.finalDigest !== 'string') {
      erros.push(`integrityProof digests inicial e final devem ser strings`);
    }
  }

  // 7. Validação de decision
  const dec = evidencePack.decision;
  if (dec && typeof dec === 'object') {
    if (typeof dec.score !== 'number' || dec.score < 0 || dec.score > 100) {
      erros.push(`decision.score deve ser número entre 0 e 100`);
    }
    if (typeof dec.coverage !== 'number' || dec.coverage < 0 || dec.coverage > 100) {
      erros.push(`decision.coverage deve ser número entre 0 e 100`);
    }
    if (!['ACCEPT', 'REJECT', 'UNPROVEN'].includes(dec.outcome)) {
      erros.push(`decision.outcome deve ser 'ACCEPT', 'REJECT' ou 'UNPROVEN'`);
    }
    if (
      ehPackDecisorio &&
      (typeof dec.maxPossibleScore !== 'number' || dec.maxPossibleScore < 0 || dec.maxPossibleScore > 100)
    ) {
      erros.push(`decision.maxPossibleScore deve ser número entre 0 e 100`);
    }
    if (ehPackDecisorio && !Array.isArray(dec.gates)) {
      erros.push(`decision.gates deve ser array no Evidence Pack 0.2.0`);
    } else if (!dec.gates || (typeof dec.gates !== 'object' && !Array.isArray(dec.gates))) {
      erros.push(`decision.gates deve ser objeto ou array`);
    }
    if (Array.isArray(dec.gates)) {
      for (const [indice, gate] of dec.gates.entries()) {
        if (!gate || typeof gate !== 'object') {
          erros.push(`decision.gates[${indice}] deve ser objeto`);
          continue;
        }
        if (!ESTADOS_PUBLICOS.has(gate.estado)) {
          erros.push(`decision.gates[${indice}].estado deve usar um dos quatro estados públicos`);
        }
        if (
          gate.estado === 'NAO_COMPROVADO' &&
          !SUBCAUSAS_NAO_COMPROVADO.has(gate.subcausa)
        ) {
          erros.push(`decision.gates[${indice}] NÃO COMPROVADO exige subcausa interna válida`);
        }
        if (gate.estado !== 'NAO_COMPROVADO' && Object.hasOwn(gate, 'subcausa')) {
          erros.push(`decision.gates[${indice}].subcausa só pode existir em NÃO COMPROVADO`);
        }
      }
    }
    if (
      cc?.decision !== undefined &&
      serializarJsonCanonico(cc.decision) !== serializarJsonCanonico(dec)
    ) {
      erros.push(`decision diverge de canonicalContent.decision`);
    }
  }

  // 8. Validação de coverageAndResidualRisk
  const cr = evidencePack.coverageAndResidualRisk;
  if (cr && typeof cr === 'object') {
    if (!Array.isArray(cr.excludedPaths)) {
      erros.push(`coverageAndResidualRisk.excludedPaths deve ser array`);
    }
    if (!Array.isArray(cr.unexecutedChecks)) {
      erros.push(`coverageAndResidualRisk.unexecutedChecks deve ser array`);
    }
    if (typeof cr.residualRiskStatement !== 'string' || !cr.residualRiskStatement.trim()) {
      erros.push(`coverageAndResidualRisk.residualRiskStatement deve ser string não-vazia`);
    }
  }

  return {
    valido: erros.length === 0,
    erros
  };
}
