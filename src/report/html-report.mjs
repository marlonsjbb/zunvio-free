import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { validarEvidencePackV0 } from '../schema/validador-schema.mjs';
import { redigirTexto } from '../utils/redactor.mjs';
import { TERMOS_GLOSSARIO } from '../glossary/termos.mjs';

export const VERSAO_RELATORIO_HTML = '1.0.0';

const WORDMARK_PATH = fileURLToPath(new URL('../../marca/zunvio-wordmark.png', import.meta.url));
const WORDMARK_SHA256 = '446450e43c2b42bc7a300fc3a2710f828bcae71c81f7d1f4dada786bb00dc0f3';

const DIMENSOES = Object.freeze({
  objetivoProduto: 'Objetivo do produto',
  publicoUsuarios: 'Público e usuários',
  jornadasCriticas: 'Jornadas críticas',
  ambientePublicacao: 'Ambiente de publicação',
  integracoesIndispensaveis: 'Integrações indispensáveis',
  dadosTratados: 'Dados tratados',
  requisitosSegurancaPrivacidade: 'Segurança e privacidade',
  capacidadeDesempenho: 'Capacidade e desempenho',
  requisitosLegaisRegulatorios: 'Requisitos legais e regulatórios',
  operacaoRollback: 'Operação e rollback',
  criteriosInaceitaveis: 'Critérios inaceitáveis',
  vinculoRelease: 'Vínculo com a release'
});

const ESTADOS = Object.freeze({
  ATENDE: Object.freeze({ classe: 'atende', simbolo: '✓', rotulo: 'Atende' }),
  NAO_ATENDE: Object.freeze({ classe: 'nao-atende', simbolo: '!', rotulo: 'Não atende' }),
  NAO_COMPROVADO: Object.freeze({ classe: 'nao-comprovado', simbolo: '?', rotulo: 'Não comprovado' }),
  NAO_APLICAVEL: Object.freeze({ classe: 'nao-aplicavel', simbolo: '—', rotulo: 'Não aplicável' })
});

const ORIGENS_CONCLUSAO = Object.freeze({
  NO_DECLARED_CLAIM: 'Nenhuma informação declarada',
  DECLARATION_ONLY: 'Somente informação declarada',
  EXTERNAL_CLAIM_EVIDENCE: 'Prova externa controlada',
  GIT_PROVENANCE: 'Proveniência Git observada',
  UNTRUSTED_EVIDENCE: 'Prova interna não confiável'
});

const PROXIMAS_ACOES = Object.freeze({
  segredos: 'Remova e rotacione as credenciais expostas; depois execute a análise novamente.',
  seguranca_estatica: 'Corrija os achados de segurança estática e gere uma nova prova de análise.',
  funcionamento: 'Forneça resultados de testes executados em ambiente controlado e vinculados à release.',
  integridade: 'Repita a análise sobre uma cópia limpa e preserve o digest do início ao fim.',
  proveniencia_auditabilidade: 'Informe e comprove o commit exato da release que será avaliada.',
  impacto_delta: 'Disponibilize o diff Git da release e execute novamente a análise de impacto.',
  manutencao_documentacao: 'Forneça documentação atualizada e uma prova externa de manutenção.'
});

function wordmarkDataUri() {
  const bytes = readFileSync(WORDMARK_PATH);
  const digest = createHash('sha256').update(bytes).digest('hex');
  if (digest !== WORDMARK_SHA256) {
    throw new Error('Ativo oficial do wordmark ZUNVIO diverge da referência de marca aprovada.');
  }
  return `data:image/png;base64,${bytes.toString('base64')}`;
}

function limitar(texto, maximo) {
  return Array.from(texto).slice(0, maximo).join('');
}

function textoSeguro(valor, maximo = 600) {
  const bruto = String(valor ?? '');
  const redigido = redigirTexto(bruto)
    .replace(/\/Users\/[^/\s<>"']+(?:\/[^\s<>"']*)?/g, '[caminho local omitido]')
    .replace(/[A-Za-z]:\\Users\\[^\\\s<>"']+(?:\\[^\s<>"']*)?/gi, '[caminho local omitido]')
    .replace(/[\u202A-\u202E\u2066-\u2069]/g, '')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return limitar(redigido, maximo);
}

function escaparHtml(valor, maximo = 600) {
  return textoSeguro(valor, maximo)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function inteiroSeguro(valor, padrao = 0, minimo = 0, maximo = Number.MAX_SAFE_INTEGER) {
  return Number.isInteger(valor) ? Math.min(maximo, Math.max(minimo, valor)) : padrao;
}

function estadoSeguro(valor) {
  return ESTADOS[valor] || ESTADOS.NAO_COMPROVADO;
}

function compararAscii(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function extrairRelease(evidencePack) {
  const claimRelease = evidencePack.claimEvidenceMap?.claims?.find(
    (claim) => claim.dimension === 'vinculoRelease'
  );
  const portaoRelease = evidencePack.decision?.gates?.find(
    (gate) => gate.id === 'proveniencia_auditabilidade'
  );
  const candidatos = [
    claimRelease?.evidence?.summary,
    claimRelease?.claim?.summary,
    ...(Array.isArray(portaoRelease?.evidencias) ? portaoRelease.evidencias : []),
    portaoRelease?.motivo
  ];
  for (const candidato of candidatos) {
    const sha = typeof candidato === 'string' ? candidato.match(/\b[a-f0-9]{40}\b/i)?.[0] : null;
    if (sha) return sha.toLowerCase();
  }
  return null;
}

function impactoDoGate(gate) {
  if (gate.estado === 'NAO_ATENDE') {
    return 'Há um bloqueio neste critério; achados por padrão permanecem pendentes de revisão humana antes da publicação.';
  }
  if (gate.subcausa === 'SEM_EVIDENCIA_DO_CLIENTE') {
    return 'Falta uma prova obrigatória. Isso não reprova o projeto automaticamente, mas impede uma decisão segura.';
  }
  if (gate.subcausa === 'MOTOR_FALHOU') {
    return 'O ZUNVIO não concluiu esta verificação. O projeto não foi reprovado por este ponto, mas a decisão permanece incompleta.';
  }
  return 'A verificação ficou fora da cobertura atual. O resultado é incompleto, não uma reprovação automática.';
}

function construirBloqueadores(evidencePack) {
  const gates = Array.isArray(evidencePack.decision?.gates) ? evidencePack.decision.gates : [];
  const bloqueadoresGate = gates
    .map((gate, indice) => ({ ...gate, indice }))
    .filter((gate) => gate.obrigatorio === true && ['NAO_ATENDE', 'NAO_COMPROVADO'].includes(gate.estado))
    .sort((a, b) => {
      const rankA = a.estado === 'NAO_ATENDE' ? 0 : 1;
      const rankB = b.estado === 'NAO_ATENDE' ? 0 : 1;
      if (rankA !== rankB) return rankA - rankB;
      const pesoA = inteiroSeguro(a.peso);
      const pesoB = inteiroSeguro(b.peso);
      if (pesoA !== pesoB) return pesoB - pesoA;
      const porId = compararAscii(String(a.id || ''), String(b.id || ''));
      return porId || a.indice - b.indice;
    })
    .map((gate) => ({
      tipo: 'gate',
      id: gate.id,
      titulo: gate.nome || gate.id || 'Verificação obrigatória',
      status: gate.estado,
      causa: gate.motivo || 'A prova obrigatória não foi conclusiva.',
      impacto: impactoDoGate(gate),
      proximaAcao: PROXIMAS_ACOES[gate.id]
        || 'Forneça uma prova externa controlada e execute a análise novamente.',
      evidencias: Array.isArray(gate.evidencias) ? gate.evidencias : []
    }));

  const divergencias = (evidencePack.claimEvidenceMap?.claims || [])
    .filter((claim) => claim.status === 'NAO_ATENDE' && claim.divergence === true)
    .map((claim) => ({
      tipo: 'claim',
      id: claim.dimension,
      titulo: `Divergência em ${DIMENSOES[claim.dimension] || claim.dimension}`,
      status: 'NAO_ATENDE',
      causa: 'A informação declarada e a prova observada não coincidem.',
      impacto: 'A decisão pode estar baseada em um contexto diferente daquele que foi realmente observado.',
      proximaAcao: 'Reconcilie a informação declarada com a prova da release e execute a análise novamente.',
      evidencias: [claim.evidence?.reference].filter(Boolean)
    }));

  return [...bloqueadoresGate, ...divergencias];
}

function decisaoEmLinguagemComum(evidencePack, bloqueadores) {
  const outcome = evidencePack.decision?.outcome;
  if (outcome === 'ACCEPT') {
    return {
      classe: 'aceitar',
      eyebrow: 'Resultado do ZUNVIO · PUBLICAR',
      titulo: 'Pode avançar para avaliação humana de publicação.',
      resumo: 'As verificações obrigatórias foram atendidas no escopo comprovado. Ainda assim, confirme as limitações e o contexto da release antes da decisão final.'
    };
  }
  // MASS-307: outcome UNPROVEN = estado canônico INCONCLUSIVO (não é reprovação).
  if (outcome === 'UNPROVEN') {
    return {
      classe: 'incompleto',
      eyebrow: 'Resultado do ZUNVIO · INCONCLUSIVO',
      titulo: 'Ainda não é possível afirmar que pode publicar.',
      resumo: 'Faltaram provas ou verificações obrigatórias (sensor ausente, falha, timeout, cobertura insuficiente ou integridade não comprovada). INCONCLUSIVO não significa reprovação automática; significa que a decisão ainda está incompleta.'
    };
  }
  return {
    classe: 'recusar',
    eyebrow: 'Resultado do ZUNVIO · NÃO PUBLICAR',
    titulo: 'Não avance para publicação neste momento.',
    resumo: 'Há ao menos um bloqueio material detectado ou divergência relevante. Revise os itens priorizados e gere uma nova análise vinculada à release.'
  };
}

function renderTermos() {
  return TERMOS_GLOSSARIO
    .map((item) => `<article class="term"><h3>${escaparHtml(item.termo, 120)}</h3><p>${escaparHtml(item.definicao, 400)}</p></article>`)
    .join('\n        ');
}

function renderStatus(status) {
  const estado = estadoSeguro(status);
  return `<span class="status status--${estado.classe}"><span aria-hidden="true">${estado.simbolo}</span> ${estado.rotulo}</span>`;
}

function renderBloqueadores(bloqueadores) {
  if (bloqueadores.length === 0) {
    return `<div class="empty-state"><strong>Nenhum bloqueador obrigatório foi reportado.</strong><p>Revise as limitações e os detalhes técnicos antes da decisão final.</p></div>`;
  }
  return bloqueadores.map((item, indice) => {
    const provas = item.evidencias.length > 0
      ? `<ul>${item.evidencias.map((evidencia) => `<li>${escaparHtml(evidencia)}</li>`).join('')}</ul>`
      : '<p>Nenhuma prova conclusiva foi registrada.</p>';
    return `<article class="action-card">
      <div class="action-card__rank" aria-label="Prioridade ${indice + 1}">${String(indice + 1).padStart(2, '0')}</div>
      <div class="action-card__body">
        <div class="action-card__heading"><h3>${escaparHtml(item.titulo, 160)}</h3>${renderStatus(item.status)}</div>
        <dl class="action-grid">
          <div><dt>Causa</dt><dd>${escaparHtml(item.causa)}</dd></div>
          <div><dt>Impacto</dt><dd>${escaparHtml(item.impacto)}</dd></div>
          <div class="action-grid__next"><dt>Próxima ação</dt><dd>${escaparHtml(item.proximaAcao)}</dd></div>
        </dl>
        <details class="inline-details"><summary>Ver prova técnica</summary>${provas}</details>
      </div>
    </article>`;
  }).join('\n');
}

function renderClaims(evidencePack) {
  const claims = Array.isArray(evidencePack.claimEvidenceMap?.claims)
    ? evidencePack.claimEvidenceMap.claims
    : [];
  if (claims.length === 0) {
    return '<div class="empty-state"><strong>As 12 informações não estão disponíveis neste Evidence Pack.</strong></div>';
  }
  return claims.map((claim, indice) => {
    const claimResumo = claim.claim?.declared
      ? claim.claim.summary || 'Informação declarada sem resumo público.'
      : 'Não informada no Contrato de Publicação.';
    const evidenciaResumo = claim.evidence?.observed
      ? claim.evidence.summary || 'Prova observada sem resumo público.'
      : 'Nenhuma prova conclusiva observada.';
    const referencia = claim.evidence?.reference || 'Sem referência segura.';
    const origem = ORIGENS_CONCLUSAO[claim.conclusionSource] || 'Origem não identificada';
    const divergencia = claim.divergence === true
      ? 'Sim — a informação declarada diverge da prova.'
      : claim.divergence === false
        ? 'Não — declaração e prova são concordantes.'
        : 'Não foi possível comparar.';
    const minimo = claim.minimumMissing
      ? `<div><dt>O mínimo que falta</dt><dd>${escaparHtml(claim.minimumMissing)}</dd></div>`
      : '';
    return `<details class="claim-card">
      <summary>
        <span class="claim-card__index">${String(indice + 1).padStart(2, '0')}</span>
        <span class="claim-card__title">${escaparHtml(DIMENSOES[claim.dimension] || claim.dimension, 120)}</span>
        ${renderStatus(claim.status)}
      </summary>
      <div class="claim-card__content">
        <dl class="claim-grid">
          <div><dt>Informação declarada</dt><dd>${escaparHtml(claimResumo)}</dd></div>
          <div><dt>Prova usada</dt><dd>${escaparHtml(evidenciaResumo)}</dd></div>
          <div><dt>Referência segura</dt><dd><code>${escaparHtml(referencia, 160)}</code></dd></div>
          <div><dt>Origem da conclusão</dt><dd>${escaparHtml(origem, 160)}</dd></div>
          <div><dt>Cobertura desta informação</dt><dd>${inteiroSeguro(claim.coverage, 0, 0, 100)}%</dd></div>
          <div><dt>Declarado versus observado</dt><dd>${escaparHtml(divergencia, 180)}</dd></div>
          ${minimo}
        </dl>
      </div>
    </details>`;
  }).join('\n');
}

function renderGates(evidencePack) {
  const gates = Array.isArray(evidencePack.decision?.gates) ? evidencePack.decision.gates : [];
  return gates.map((gate) => {
    const evidencias = Array.isArray(gate.evidencias) && gate.evidencias.length > 0
      ? `<ul>${gate.evidencias.map((item) => `<li>${escaparHtml(item)}</li>`).join('')}</ul>`
      : '<p>Nenhuma prova conclusiva registrada.</p>';
    return `<article class="proof-row">
      <div><h4>${escaparHtml(gate.nome || gate.id, 160)}</h4><p>${gate.obrigatorio ? 'Verificação obrigatória' : 'Verificação complementar'} · peso ${inteiroSeguro(gate.peso, 0, 0, 100)}</p></div>
      <div>${renderStatus(gate.estado)}</div>
      <div><strong>Causa técnica</strong><p>${escaparHtml(gate.motivo)}</p>${evidencias}</div>
    </article>`;
  }).join('\n');
}

function renderFindings(evidencePack) {
  const findings = Array.isArray(evidencePack.canonicalContent?.findings)
    ? evidencePack.canonicalContent.findings
    : [];
  if (findings.length === 0) return '<p class="muted">Nenhum achado técnico foi registrado no Evidence Pack.</p>';
  return findings.map((finding, indice) => {
    const caminho = textoSeguro(finding.filePath, 240).startsWith('/')
      ? '[caminho local omitido]'
      : textoSeguro(finding.filePath, 240);
    const linha = inteiroSeguro(finding.startLine, 0, 0);
    return `<article class="finding">
      <span class="finding__index">${String(indice + 1).padStart(2, '0')}</span>
      <div><strong>${escaparHtml(finding.ruleId || 'regra não identificada', 180)}</strong><p>${escaparHtml(finding.message)}</p><p>Detectado · Necessita revisão</p><code>${escaparHtml(caminho || '[arquivo não identificado]', 240)}${linha ? `:${linha}` : ''}</code></div>
      <span class="severity">${escaparHtml(finding.severity || 'INFO', 24)}</span>
    </article>`;
  }).join('\n');
}

function renderLimitacoesTecnicas(evidencePack) {
  const canonical = evidencePack.canonicalContent || {};
  const checks = Array.isArray(evidencePack.coverageAndResidualRisk?.unexecutedChecks)
    ? evidencePack.coverageAndResidualRisk.unexecutedChecks
    : [];
  const limitations = Array.isArray(canonical.limitations) ? canonical.limitations : [];
  const itens = [
    ...checks.map((item) => `Verificação não executada: ${item}`),
    ...limitations
  ];
  if (itens.length === 0) return '<li>Nenhuma limitação operacional adicional foi registrada.</li>';
  return [...new Set(itens.map((item) => textoSeguro(item)).filter(Boolean))]
    .map((item) => `<li>${escaparHtml(item)}</li>`)
    .join('');
}

function construirCss() {
  return `
    :root {
      color-scheme: dark;
      --iron: #10151a;
      --iron-raised: #171e24;
      --iron-soft: #202930;
      --cream: #f2e8d5;
      --cream-muted: #c9c0af;
      --teal: #4fb3b7;
      --teal-dark: #287b7f;
      --line: #344149;
      --ok: #88c99c;
      --warn: #e0ad62;
      --danger: #ed7c77;
      --neutral: #aab5bc;
      --radius: 16px;
      --shadow: 0 24px 70px rgba(0, 0, 0, .28);
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; background: var(--iron); }
    body {
      margin: 0;
      background:
        linear-gradient(rgba(79,179,183,.035) 1px, transparent 1px),
        linear-gradient(90deg, rgba(79,179,183,.035) 1px, transparent 1px),
        var(--iron);
      background-size: 48px 48px;
      color: var(--cream);
      font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.55;
    }
    a { color: var(--cream); text-underline-offset: .2em; }
    a:focus-visible, summary:focus-visible { outline: 3px solid var(--teal); outline-offset: 4px; border-radius: 4px; }
    .skip-link { position: fixed; left: 16px; top: -80px; z-index: 100; padding: 12px 16px; color: var(--iron); background: var(--cream); }
    .skip-link:focus { top: 16px; }
    .shell { width: min(1120px, calc(100% - 40px)); margin-inline: auto; }
    .topbar { border-bottom: 1px solid var(--line); background: rgba(16,21,26,.96); }
    .topbar__inner { min-height: 92px; display: flex; align-items: center; gap: 24px; }
    .brand { width: 126px; height: auto; filter: invert(91%) sepia(17%) saturate(262%) hue-rotate(348deg) brightness(105%) contrast(92%); }
    .tagline { margin: 0; color: var(--cream-muted); font-size: .94rem; }
    .method-chip { margin-left: auto; border: 1px solid var(--line); border-radius: 999px; padding: 8px 12px; color: var(--cream-muted); font-size: .72rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
    main { padding: 48px 0 72px; }
    section { margin-top: 56px; }
    .hero {
      position: relative;
      overflow: hidden;
      margin-top: 0;
      border: 1px solid var(--line);
      border-radius: 24px;
      padding: clamp(28px, 5vw, 64px);
      background: linear-gradient(145deg, rgba(79,179,183,.12), transparent 42%), var(--iron-raised);
      box-shadow: var(--shadow);
    }
    .hero::after { content: ""; position: absolute; width: 340px; height: 340px; right: -170px; bottom: -210px; border: 1px solid rgba(79,179,183,.35); transform: rotate(45deg); box-shadow: 0 0 0 28px rgba(79,179,183,.035), 0 0 0 56px rgba(79,179,183,.025); }
    .eyebrow { margin: 0 0 14px; color: var(--teal); font-size: .76rem; font-weight: 850; letter-spacing: .12em; text-transform: uppercase; }
    h1, h2, h3, h4 { margin-top: 0; font-family: "Arial Narrow", "Avenir Next Condensed", ui-sans-serif, sans-serif; line-height: 1.08; }
    h1 { max-width: 780px; margin-bottom: 18px; font-size: clamp(2.35rem, 6vw, 4.8rem); letter-spacing: -.035em; }
    .lede { max-width: 760px; margin: 0; color: var(--cream-muted); font-size: clamp(1rem, 2vw, 1.2rem); }
    .metrics { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 12px; margin-top: 38px; }
    .metric { min-height: 132px; padding: 18px; border: 1px solid var(--line); border-radius: 12px; background: rgba(16,21,26,.62); }
    .metric__label { display: block; color: var(--cream-muted); font-size: .78rem; font-weight: 750; letter-spacing: .06em; text-transform: uppercase; }
    .metric__value { display: block; margin-top: 10px; font-size: clamp(1.55rem, 3.5vw, 2.55rem); font-weight: 850; line-height: 1; }
    .metric__note { display: block; margin-top: 10px; color: var(--cream-muted); font-size: .78rem; }
    progress { width: 100%; height: 8px; margin-top: 14px; overflow: hidden; border: 0; border-radius: 8px; background: var(--iron-soft); }
    progress::-webkit-progress-bar { background: var(--iron-soft); }
    progress::-webkit-progress-value { background: var(--teal); }
    progress::-moz-progress-bar { background: var(--teal); }
    .section-heading { display: grid; grid-template-columns: minmax(0, 1fr) minmax(260px, .75fr); gap: 32px; align-items: end; margin-bottom: 22px; }
    .section-heading h2 { margin-bottom: 0; font-size: clamp(1.8rem, 4vw, 3rem); }
    .section-heading p { margin: 0; color: var(--cream-muted); }
    .action-list { display: grid; gap: 12px; }
    .action-card { display: grid; grid-template-columns: 72px minmax(0,1fr); border: 1px solid var(--line); border-radius: var(--radius); background: var(--iron-raised); overflow: hidden; }
    .action-card__rank { display: grid; place-items: start center; padding-top: 25px; border-right: 1px solid var(--line); color: var(--teal); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 1.15rem; font-weight: 800; }
    .action-card__body { padding: 24px; }
    .action-card__heading { display: flex; align-items: start; justify-content: space-between; gap: 16px; }
    .action-card__heading h3 { margin-bottom: 12px; font-size: 1.35rem; }
    .action-grid, .claim-grid { display: grid; grid-template-columns: repeat(2,minmax(0,1fr)); gap: 16px; margin: 8px 0 0; }
    .action-grid div, .claim-grid div { padding-top: 12px; border-top: 1px solid var(--line); }
    .action-grid__next { grid-column: 1 / -1; }
    dt { color: var(--cream-muted); font-size: .72rem; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; }
    dd { margin: 6px 0 0; }
    .status { display: inline-flex; align-items: center; gap: 7px; flex: 0 0 auto; border: 1px solid currentColor; border-radius: 999px; padding: 5px 9px; font-size: .72rem; font-weight: 850; white-space: nowrap; }
    .status--atende { color: var(--ok); }
    .status--nao-atende { color: var(--danger); }
    .status--nao-comprovado { color: var(--warn); }
    .status--nao-aplicavel { color: var(--neutral); }
    details { border: 1px solid var(--line); border-radius: 12px; background: var(--iron-raised); }
    summary { cursor: pointer; }
    .inline-details { margin-top: 18px; background: transparent; }
    .inline-details summary { padding: 10px 12px; font-weight: 750; }
    .inline-details p, .inline-details ul { margin: 0; padding: 0 16px 14px 36px; color: var(--cream-muted); }
    .claim-list { display: grid; gap: 10px; }
    .claim-card summary { display: grid; grid-template-columns: 48px minmax(0,1fr) auto auto; gap: 14px; align-items: center; min-height: 68px; padding: 12px 16px; list-style: none; }
    .claim-card summary::-webkit-details-marker { display: none; }
    .claim-card summary::after { content: "+"; grid-column: 4; color: var(--teal); font-size: 1.25rem; }
    .claim-card[open] summary::after { content: "−"; }
    .claim-card__index { color: var(--teal); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .8rem; }
    .claim-card__title { font-weight: 800; }
    .claim-card__content { padding: 0 20px 22px 78px; }
    code { color: var(--teal); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .84em; overflow-wrap: anywhere; }
    .technical { padding: 24px; border: 1px solid var(--line); border-radius: var(--radius); background: rgba(23,30,36,.72); }
    .technical > summary { font-family: "Arial Narrow", "Avenir Next Condensed", ui-sans-serif, sans-serif; font-size: 1.55rem; font-weight: 850; }
    .technical__content { padding-top: 26px; }
    .proof-meta { display: grid; grid-template-columns: repeat(3,minmax(0,1fr)); gap: 12px; }
    .proof-meta div { padding: 16px; border: 1px solid var(--line); border-radius: 10px; background: var(--iron); }
    .proof-meta dt { margin-bottom: 8px; }
    .proof-meta dd { overflow-wrap: anywhere; }
    .subheading { margin: 34px 0 14px; font-size: 1.25rem; }
    .proof-row { display: grid; grid-template-columns: minmax(180px,.8fr) auto minmax(260px,1.4fr); gap: 18px; align-items: start; padding: 18px 0; border-top: 1px solid var(--line); }
    .proof-row h4, .proof-row p { margin-bottom: 6px; }
    .proof-row p, .proof-row ul { color: var(--cream-muted); }
    .finding { display: grid; grid-template-columns: 42px minmax(0,1fr) auto; gap: 14px; padding: 16px 0; border-top: 1px solid var(--line); }
    .finding p { margin: 4px 0; color: var(--cream-muted); }
    .finding__index { color: var(--teal); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    .severity { color: var(--warn); font-size: .72rem; font-weight: 850; }
    .terms { display: grid; grid-template-columns: repeat(3,minmax(0,1fr)); gap: 12px; }
    .term { padding: 18px; border-top: 2px solid var(--teal-dark); background: var(--iron-raised); }
    .term h3 { margin-bottom: 8px; font-size: 1.05rem; }
    .term p, .muted { margin: 0; color: var(--cream-muted); }
    .limitations { padding: 26px; border: 1px solid var(--warn); border-radius: var(--radius); background: rgba(224,173,98,.06); }
    .limitations h2 { margin-bottom: 10px; }
    .limitations ul { margin-bottom: 0; }
    .empty-state { padding: 26px; border: 1px dashed var(--line); border-radius: var(--radius); color: var(--cream-muted); }
    .empty-state p { margin-bottom: 0; }
    .footer { border-top: 1px solid var(--line); padding: 28px 0 42px; }
    .footer__inner { display: flex; justify-content: space-between; gap: 28px; align-items: center; }
    .footer p { margin: 0; color: var(--cream-muted); }
    .footer__links { display: flex; gap: 10px; flex-wrap: wrap; justify-content: flex-end; }
    .button { display: inline-flex; align-items: center; min-height: 42px; border: 1px solid var(--line); border-radius: 8px; padding: 9px 13px; font-weight: 800; text-decoration: none; }
    .button--accent { border-color: var(--teal); color: var(--iron); background: var(--teal); }
    @media (max-width: 820px) {
      .metrics { grid-template-columns: repeat(2,minmax(0,1fr)); }
      .section-heading, .proof-row { grid-template-columns: 1fr; }
      .terms { grid-template-columns: repeat(2,minmax(0,1fr)); }
      .proof-meta { grid-template-columns: 1fr; }
    }
    @media (max-width: 560px) {
      .shell { width: min(100% - 24px, 1120px); }
      .topbar__inner { min-height: 76px; gap: 14px; }
      .brand { width: 98px; }
      .tagline { display: none; }
      .method-chip { font-size: .62rem; }
      main { padding-top: 24px; }
      section { margin-top: 42px; }
      .hero { padding: 26px 20px; border-radius: 18px; }
      .metrics { grid-template-columns: 1fr; }
      .metric { min-height: auto; }
      .action-card { grid-template-columns: 50px minmax(0,1fr); }
      .action-card__body { padding: 18px; }
      .action-grid, .claim-grid { grid-template-columns: 1fr; }
      .action-card__heading { align-items: start; flex-direction: column; }
      .claim-card summary { grid-template-columns: 36px minmax(0,1fr) auto; }
      .claim-card summary .status { grid-column: 2; justify-self: start; }
      .claim-card summary::after { grid-column: 3; grid-row: 1 / span 2; }
      .claim-card__content { padding: 0 16px 18px; }
      .terms { grid-template-columns: 1fr; }
      .footer__inner { align-items: flex-start; flex-direction: column; }
      .footer__links { justify-content: flex-start; }
    }
    @media print {
      :root { color-scheme: light; --iron: #fff; --iron-raised: #fff; --iron-soft: #eef2f3; --cream: #11181d; --cream-muted: #39464d; --line: #aab4b9; --teal: #176d71; --ok: #246b3b; --warn: #79510b; --danger: #9a2925; }
      body { background: #fff; color: #11181d; font-size: 10.5pt; }
      .topbar, .hero, .metric, .action-card, details, .term, .technical { background: #fff; box-shadow: none; }
      .brand { filter: none; }
      .shell { width: 100%; }
      .skip-link, .footer__links { display: none; }
      main { padding: 20px 0; }
      section { margin-top: 28px; break-inside: avoid; }
      details:not([open]) > :not(summary) { display: block !important; }
      .claim-card, .action-card, .proof-row, .finding { break-inside: avoid; }
      a { color: #11181d; text-decoration: none; }
      a::after { content: " (" attr(href) ")"; font-size: .85em; }
    }
  `;
}

export function gerarRelatorioHtml(evidencePack) {
  const validacao = validarEvidencePackV0(evidencePack);
  if (!validacao.valido) {
    throw new Error(`Evidence Pack inválido para relatório HTML: ${validacao.erros.join('; ')}`);
  }

  // `decision.coverage` é o mínimo entre motores e contrato (uso interno do
  // portão de PUBLICAR) — vira 0% sempre que não há --contract, mesmo com os
  // motores rodando normalmente. A manchete precisa da cobertura dos MOTORES
  // (o que de fato foi verificado), igual o terminal já faz (`formatarRelatorioHumano`).
  const coberturaMotores = evidencePack.avaliacao?.score?.coberturaMotores;
  const coverage = Number.isInteger(coberturaMotores)
    ? inteiroSeguro(coberturaMotores, 0, 0, 100)
    : inteiroSeguro(evidencePack.decision?.coverage, 0, 0, 100);
  const score = inteiroSeguro(evidencePack.decision?.score, 0, 0, 100);
  // O score é SEMPRE sobre 100 (soma dos pesos dos portões); `maxPossibleScore`
  // é outra informação (o teto que ainda dá pra alcançar depois de descontar
  // reprovações comprovadas) — nunca o denominador do score observado.
  const maxScoreAlcancavel = inteiroSeguro(evidencePack.decision?.maxPossibleScore, 100, 0, 100);
  const bloqueadores = construirBloqueadores(evidencePack);
  const decisao = decisaoEmLinguagemComum(evidencePack, bloqueadores);
  const mapa = evidencePack.claimEvidenceMap;
  const release = extrairRelease(evidencePack);
  const releaseCurta = release ? release.slice(0, 12) : 'não comprovada';
  const totalClaims = inteiroSeguro(mapa?.totalClaims, 12, 0, 12);
  const claimsAtende = inteiroSeguro(mapa?.summary?.atende, 0, 0, 12);
  const claimsNaoAtende = inteiroSeguro(mapa?.summary?.naoAtende, 0, 0, 12);
  const claimsNaoComprovado = inteiroSeguro(mapa?.summary?.naoComprovado, totalClaims, 0, 12);
  const totalAchados = inteiroSeguro(evidencePack.canonicalContent?.findingsCount, 0, 0);
  const arquivos = inteiroSeguro(evidencePack.canonicalContent?.filesAnalyzed, 0, 0);
  const hash = escaparHtml(evidencePack.canonicalHash, 64);
  const versaoMetodo = escaparHtml(evidencePack.versao, 20);

  return `<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; connect-src 'none'; font-src 'none'; object-src 'none'; media-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'">
  <title>Relatório ZUNVIO — ${escaparHtml(decisao.eyebrow, 80)}</title>
  <style>${construirCss()}</style>
</head>
<body>
  <a class="skip-link" href="#conteudo">Pular para o conteúdo principal</a>
  <header class="topbar">
    <div class="shell topbar__inner">
      <img class="brand" src="${wordmarkDataUri()}" alt="ZUNVIO" width="1866" height="465">
      <p class="tagline">Confiança antes de publicar.</p>
      <span class="method-chip">Relatório local · v${VERSAO_RELATORIO_HTML}</span>
    </div>
  </header>

  <main id="conteudo" class="shell">
    <section class="hero hero--${decisao.classe}" aria-labelledby="titulo-relatorio">
      <p class="eyebrow">${escaparHtml(decisao.eyebrow, 90)}</p>
      <h1 id="titulo-relatorio">${escaparHtml(decisao.titulo, 180)}</h1>
      <p class="lede">${escaparHtml(decisao.resumo)}</p>
      <div class="metrics" aria-label="Indicadores principais">
        <div class="metric">
          <span class="metric__label">Quanto conseguimos comprovar</span>
          <strong class="metric__value">${coverage}%</strong>
          <progress max="100" value="${coverage}">${coverage}%</progress>
        </div>
        <div class="metric">
          <span class="metric__label">Score observado</span>
          <strong class="metric__value">${score}<small>/100</small></strong>
          <span class="metric__note">${maxScoreAlcancavel < 100
            ? `Ainda alcançável: ${maxScoreAlcancavel}. Não substitui a decisão e suas provas.`
            : 'Não substitui a decisão e suas provas.'}</span>
        </div>
        <div class="metric">
          <span class="metric__label">Itens que pedem ação</span>
          <strong class="metric__value">${bloqueadores.length}</strong>
          <span class="metric__note">Ordenados por impacto e prioridade de revisão.</span>
        </div>
        <div class="metric">
          <span class="metric__label">Release analisada</span>
          <strong class="metric__value"><code>${escaparHtml(releaseCurta, 20)}</code></strong>
          <span class="metric__note">Vínculo obtido das provas do Evidence Pack.</span>
        </div>
      </div>
    </section>

    <section aria-labelledby="titulo-acoes">
      <div class="section-heading">
        <div><p class="eyebrow">Resumo para decisão</p><h2 id="titulo-acoes">O que precisa acontecer agora</h2></div>
        <p>Cada item mostra a causa, o impacto e a próxima ação. Uma ausência de prova é apresentada como decisão incompleta, não como reprovação automática.</p>
      </div>
      <div class="action-list">${renderBloqueadores(bloqueadores)}</div>
    </section>

    <section aria-labelledby="titulo-informacoes">
      <div class="section-heading">
        <div><p class="eyebrow">Informações e provas</p><h2 id="titulo-informacoes">As 12 informações da publicação</h2></div>
        <p>${claimsAtende} atendem, ${claimsNaoAtende} não atendem e ${claimsNaoComprovado} ainda não foram comprovadas. Abra cada item para ver declaração, prova usada, origem e cobertura.</p>
      </div>
      <div class="claim-list">${renderClaims(evidencePack)}</div>
    </section>

    <section aria-labelledby="titulo-tecnico">
      <div class="section-heading">
        <div><p class="eyebrow">Implementação e auditoria</p><h2 id="titulo-tecnico">Detalhes técnicos</h2></div>
        <p>Estas provas ficam recolhidas por padrão para manter a leitura simples, sem remover informação de engenharia.</p>
      </div>
      <details class="technical">
        <summary>Ver portões, achados, integridade e hashes</summary>
        <div class="technical__content">
          <dl class="proof-meta">
            <div><dt>Release completa</dt><dd><code>${escaparHtml(release || 'Não identificada no Evidence Pack', 80)}</code></dd></div>
            <div><dt>Versão do método</dt><dd>Evidence Pack v${versaoMetodo} · HTML v${VERSAO_RELATORIO_HTML}</dd></div>
            <div><dt>Hash canônico do Evidence Pack</dt><dd><code>${hash}</code></dd></div>
            <div><dt>Arquivos avaliados</dt><dd>${arquivos}</dd></div>
            <div><dt>Achados técnicos</dt><dd>${totalAchados}</dd></div>
            <div><dt>Integridade do alvo</dt><dd>${evidencePack.integrityProof?.immutable ? 'Inalterado durante a análise' : 'Alteração detectada'}</dd></div>
            <div><dt>Perímetro da prova</dt><dd>Somente o repositório-alvo informado</dd></div>
            <div><dt>Algoritmo e janela</dt><dd>SHA-256 entre o início e o fim da execução</dd></div>
          </dl>
          <p>Alterações fora do alvo, como instalação de sensores, são permitidas e esperadas e não fazem parte desta medição.</p>

          <h3 class="subheading">Portões e provas técnicas</h3>
          <div>${renderGates(evidencePack)}</div>

          <h3 class="subheading">Achados registrados</h3>
          <div>${renderFindings(evidencePack)}</div>

          <h3 class="subheading">Limitações operacionais registradas</h3>
          <ul>${renderLimitacoesTecnicas(evidencePack)}</ul>
        </div>
      </details>
    </section>

    <section aria-labelledby="titulo-termos">
      <div class="section-heading">
        <div><p class="eyebrow">Entenda os termos</p><h2 id="titulo-termos">Como ler este relatório</h2></div>
        <p>Os termos abaixo traduzem a linguagem técnica sem retirar a rastreabilidade das provas.</p>
      </div>
      <div class="terms">${renderTermos()}</div>
    </section>

    <section class="limitations" aria-labelledby="titulo-limitacoes">
      <h2 id="titulo-limitacoes">Limitações importantes</h2>
      <ul>
        <li>Este relatório não é certificação, auditoria legal ou garantia absoluta de segurança.</li>
        <li>O resultado é um retrato da release e das provas disponíveis nesta execução.</li>
        <li>Verificações de runtime, terceiros e contexto operacional podem exigir análise adicional.</li>
        <li>Antes de publicar, uma pessoa responsável deve revisar a decisão, as limitações e os detalhes técnicos.</li>
      </ul>
    </section>
  </main>

  <footer class="footer">
    <div class="shell footer__inner">
      <p><strong>ZUNVIO</strong><br>Confiança antes de publicar.</p>
      <nav class="footer__links" aria-label="Próximos recursos">
        <a class="button" href="https://zunvio.com.br/glossario" rel="noreferrer noopener">Glossário completo</a>
        <a class="button button--accent" href="https://zunvio.com.br/analise" rel="noreferrer noopener">Conhecer análise aprofundada</a>
      </nav>
    </div>
    <p class="muted" style="text-align:center;margin:0 0 8px">Os recursos acima dependem da publicação do site (MASS-91) e podem ainda não estar disponíveis.</p>
  </footer>
</body>
</html>`;
}
