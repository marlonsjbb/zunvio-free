import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { executarScannerSemgrep } from './semgrep.mjs';

// RF-08 camada 2 (MASS-399): variável de ambiente vazando pro frontend.
// Reaproveita o motor Semgrep (já provisionado/testado), mas com um rulepack
// SEPARADO do canônico (`rules/semgrep/default-rules.yaml`), rodado numa
// segunda passada — de propósito: misturar essas regras no rulepack canônico
// faria os achados alimentarem o portão `seguranca_estatica` de verdade, o
// que contradiz a decisão explícita de manter esta camada informativa por
// enquanto (docs/checkpoints/MASS-399-preflight-rf08-09-11.md).

export const ID_SENSOR = 'frontend-env-exposure';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REGRAS_ENV_FRONTEND = resolve(__dirname, '../../rules/semgrep/frontend-env-exposure.yaml');

/**
 * @param {string} targetPath - Caminho do alvo real (só para cwd/contexto; nunca é lido diretamente).
 * @param {{ raiz: string }} inventario - Cópia read-only já materializada (mesma usada pelos demais scanners).
 * @param {object} [opcoes={}]
 * @returns {Promise<{ status: string, achados: Array, duracaoMs: number, identidade: object, erro: string|null }>}
 */
export async function executarScannerExposicaoEnvFrontend(targetPath, inventario, opcoes = {}) {
  const resultado = await executarScannerSemgrep(targetPath, {
    ...opcoes,
    config: REGRAS_ENV_FRONTEND,
    sourcePath: inventario.raiz
  });

  const achados = (resultado.achados || []).map((achado) => ({
    ...achado,
    scanner: ID_SENSOR
  }));

  return {
    status: resultado.status,
    achados,
    duracaoMs: resultado.duracaoMs,
    identidade: { ...resultado.identidade, id: ID_SENSOR },
    erro: resultado.erro
  };
}
