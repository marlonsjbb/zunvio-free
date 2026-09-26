// LC-06 — sensor de SEGREDOS = ZUNVIO Secret Scanner (working tree) + Gitleaks (exclusivamente histórico Git).
//
// Cada parte tem identidade e cobertura próprias (nada é atribuído a quem não fez): o working tree é lido pelo scanner
// próprio sobre o inventário do ZUNVIO; o histórico é varrido pelo Gitleaks sobre um clone --bare do alvo. Os achados
// das duas partes passam pela MESMA deduplicação da PER-207 (segredo do working tree fundido ao commit que o introduziu
// só com prova por conteúdo) e pela mesma normalização/significado.

import { relative, resolve } from 'node:path';
import { executarProcessoSeguro } from '../utils/process-runner.mjs';
import { caminhoPermitidoNoInventario } from '../scan-inventory.mjs';
import {
  deduplicarAchadosGitleaks,
  executarHistoricoGitleaks,
  montarIdentidadeGitleaks,
  normalizarAchadosGitleaks,
  OPCOES_LOG_HISTORICO
} from './gitleaks.mjs';
import { ID_SCANNER_SEGREDOS, VERSAO_SCANNER_SEGREDOS, varrerArvoreSegredos } from './zunvio-segredos.mjs';
import { completudeDaArvoreSegredos, completudeDoHistorico } from '../models/completeness.mjs';
import { digestDeLista, TETO_ARQUIVOS_AFETADOS } from '../models/expected-universe.mjs';

/**
 * @param {string} targetCanonic - raiz canônica do alvo
 * @param {object} opcoes
 * @param {object} opcoes.inventario - criarInventarioScanner()
 * @param {boolean} [opcoes.includeVendor=false]
 * @param {object} [opcoes.gitleaks] - executavel, runner, timeout, timeoutGit (injeção em testes)
 * @returns {Promise<{ arvore: object, historico: object }>}
 */
export async function executarSensorSegredos(targetCanonic, { inventario, includeVendor = false, gitleaks = {} } = {}) {
  const alvo = resolve(targetCanonic);
  const arvore = varrerArvoreSegredos(inventario);
  const historico = await executarHistoricoGitleaks(alvo, gitleaks);

  // Caminhos do working tree já são relativos ao alvo (o inventário preserva a estrutura relativa).
  const brutos = [
    ...arvore.vazamentos,
    ...historico.vazamentos
  ];
  const runner = gitleaks.runner || executarProcessoSeguro;
  const lerLinhasDeRef = (ref, arquivoRel) => {
    const r = runner('git', ['-C', alvo, 'show', `${ref}:${arquivoRel}`], { timeout: 5000 });
    if (!r || r.status !== 'SUCCESS' || r.exitCode !== 0 || typeof r.stdout !== 'string') return null;
    return r.stdout.split(/\r?\n/);
  };
  const resolvidos = deduplicarAchadosGitleaks(brutos, alvo, lerLinhasDeRef);
  const filtrados = resolvidos.filter((v) => caminhoPermitidoNoInventario(
    relative(alvo, resolve(alvo, v.File || '')).replace(/\\/g, '/'),
    { includeVendor }
  ));
  const achados = normalizarAchadosGitleaks(filtrados, alvo);
  const achadosArvore = achados.filter((a) => a.scanner === ID_SCANNER_SEGREDOS);
  const achadosHistorico = achados.filter((a) => a.scanner === 'gitleaks');

  return {
    arvore: {
      status: arvore.status,
      disponivel: arvore.status === 'SUCCESS',
      achados: achadosArvore,
      duracaoMs: arvore.duracaoMs,
      erro: arvore.erro,
      identidade: montarIdentidadeGitleaks({ id: ID_SCANNER_SEGREDOS, versao: VERSAO_SCANNER_SEGREDOS, status: arvore.status, achados: achadosArvore, configHash: arvore.rulesetHash }),
      completude: completudeDaArvoreSegredos(arvore, TETO_ARQUIVOS_AFETADOS, digestDeLista),
      // Detalhe auditável da cobertura (política, formatos não inspecionados, codificações) — selado no pack.
      detalheCobertura: arvore.cobertura?.detalhe ?? null
    },
    historico: {
      status: historico.status,
      disponivel: historico.disponivel,
      achados: achadosHistorico,
      duracaoMs: historico.duracaoMs,
      erro: historico.erro,
      identidade: montarIdentidadeGitleaks({ versao: historico.versao, status: historico.status, achados: achadosHistorico }),
      completude: completudeDoHistorico(historico, OPCOES_LOG_HISTORICO)
    }
  };
}
