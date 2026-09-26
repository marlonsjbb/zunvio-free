import { writeFileSync, readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { executarProcessoSeguro } from '../utils/process-runner.mjs';

// RF-09 (MASS-399): notarização direta do canonicalHash de um Evidence Pack já
// finalizado, via OpenTimestamps. Não depende do SaaS da ZUNVIO — chama os
// servidores de calendário públicos do próprio protocolo OpenTimestamps através
// do cliente de referência (`ots`, do pacote `opentimestamps-client`), o mesmo
// padrão de binário externo provisionado separadamente já usado para gitleaks e
// semgrep. "Local/offline" aqui significa "sem SaaS próprio", não "sem rede": o
// protocolo OpenTimestamps por definição depende de uma chamada aos servidores
// de calendário (ou a um nó Bitcoin local, fora de escopo aqui).

export const STATUS_NOTARIZACAO = Object.freeze({
  SUCESSO: 'SUCESSO',
  INDISPONIVEL: 'INDISPONIVEL',
  ERRO: 'ERRO',
  HASH_INVALIDO: 'HASH_INVALIDO'
});

const HEX64 = /^[a-f0-9]{64}$/;
const LIMITE_ERRO = 300;

function textoErroSeguro(texto) {
  return String(texto || '')
    .replace(/[\x00-\x09\x0B-\x1F]/g, ' ')
    .trim()
    .slice(0, LIMITE_ERRO);
}

function montarResultado(status, extra = {}) {
  return {
    status,
    provaBase64: null,
    canonicalHash: null,
    algoritmo: 'SHA-256',
    calendarServers: null,
    geradoEm: null,
    erro: null,
    ...extra
  };
}

/**
 * Notariza um hash canônico (SHA-256, 64 hex) via OpenTimestamps, usando o
 * cliente `ots` como subprocesso externo — sem reimplementar o formato binário
 * `.ots` nem adicionar dependência de runtime ao projeto (mesmo padrão de
 * gitleaks/semgrep: binário provisionado à parte, chamado via subprocesso sem
 * shell).
 *
 * Convenção de verificação: o arquivo carimbado contém exatamente os 64
 * caracteres hex do canonicalHash, em UTF-8, sem newline final. Quem for
 * verificar a prova depois (`ots verify`) precisa recriar esse mesmo arquivo
 * para o SHA-256 bater — isso é parte do contrato, não um detalhe interno.
 *
 * @param {string} canonicalHash - Hash SHA-256 canônico do Evidence Pack (hex, 64 chars).
 * @param {object} [opcoes={}]
 * @param {Function} [opcoes.runner=executarProcessoSeguro] - Injeção de runner para testes.
 * @param {string} [opcoes.executavel='ots'] - Nome/caminho do binário do cliente OpenTimestamps.
 * @param {number} [opcoes.timeout=60000] - Timeout em ms para o stamp (chamada de rede real).
 * @returns {Promise<{status: string, provaBase64: string|null, canonicalHash: string|null, algoritmo: string, geradoEm: string|null, erro: string|null}>}
 */
export async function notarizarCanonicalHash(canonicalHash, opcoes = {}) {
  const runner = opcoes.runner || executarProcessoSeguro;
  const executavel = opcoes.executavel || 'ots';

  if (typeof canonicalHash !== 'string' || !HEX64.test(canonicalHash)) {
    return montarResultado(STATUS_NOTARIZACAO.HASH_INVALIDO, {
      erro: 'canonicalHash ausente ou não é um SHA-256 hex de 64 caracteres.'
    });
  }

  let dirTemp;
  try {
    dirTemp = mkdtempSync(join(tmpdir(), 'zunvio-ots-'));
  } catch (erro) {
    return montarResultado(STATUS_NOTARIZACAO.ERRO, {
      erro: `Falha ao criar diretório temporário: ${textoErroSeguro(erro.message)}`
    });
  }

  const caminhoHash = join(dirTemp, `${canonicalHash}.hash`);
  const caminhoProva = `${caminhoHash}.ots`;

  try {
    writeFileSync(caminhoHash, canonicalHash, 'utf8');

    const resultado = runner(executavel, ['stamp', caminhoHash], {
      timeout: Number.isInteger(opcoes.timeout) && opcoes.timeout > 0 ? opcoes.timeout : 60_000
    });

    if (resultado.status === 'UNAVAILABLE') {
      return montarResultado(STATUS_NOTARIZACAO.INDISPONIVEL, {
        erro: `Binário '${executavel}' (cliente OpenTimestamps) não encontrado no PATH.`
      });
    }
    if (resultado.status === 'TIMEOUT') {
      return montarResultado(STATUS_NOTARIZACAO.ERRO, {
        erro: 'Timeout ao contatar os servidores de calendário do OpenTimestamps.'
      });
    }
    if (resultado.status !== 'SUCCESS' || resultado.exitCode !== 0) {
      return montarResultado(STATUS_NOTARIZACAO.ERRO, {
        erro: `'ots stamp' falhou (código ${resultado.exitCode ?? 'n/d'}): ${textoErroSeguro(resultado.stderr)}`
      });
    }

    let provaBytes;
    try {
      provaBytes = readFileSync(caminhoProva);
    } catch {
      return montarResultado(STATUS_NOTARIZACAO.ERRO, {
        erro: "'ots stamp' retornou sucesso mas não gerou o arquivo .ots esperado."
      });
    }

    return montarResultado(STATUS_NOTARIZACAO.SUCESSO, {
      provaBase64: provaBytes.toString('base64'),
      canonicalHash,
      geradoEm: new Date().toISOString()
    });
  } finally {
    try {
      rmSync(dirTemp, { recursive: true, force: true });
    } catch {
      // Diretório temporário; falha de limpeza não é motivo para reportar erro
      // ao chamador, que já recebeu o resultado real da notarização.
    }
  }
}

/**
 * Atalho para notarizar diretamente a partir de um Evidence Pack v0 já
 * construído (usa o campo `canonicalHash` do pack, nunca recalcula nada).
 * @param {object} evidencePack
 * @param {object} [opcoes={}]
 */
export async function notarizarEvidencePack(evidencePack, opcoes = {}) {
  return notarizarCanonicalHash(evidencePack?.canonicalHash, opcoes);
}
