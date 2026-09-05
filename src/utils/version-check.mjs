// Checagem NÃO BLOQUEANTE e NÃO OBRIGATÓRIA da versão mais nova publicada no
// npm (MASS-388, achado 3). Hoje `npx zunvio-score` sempre traz a versão mais
// recente quando o pacote não está em cache/instalado global, mas quem
// reusa um cache antigo do npx ou instalou global pode ficar rodando uma
// versão desatualizada sem perceber — o CLI só mostra a própria versão sob
// pedido explícito (`--version`), nunca compara com o que está publicado.
//
// Regras (fail-open sempre, sem exceção):
//  - timeout curto (abaixo), rede lenta/indisponível NUNCA atrasa nem
//    derruba a análise;
//  - qualquer falha (rede, JSON malformado, corpo inesperado) resolve pra
//    `null` em silêncio — nem loga, nem propaga erro pro chamador;
//  - dispara já (fire-and-forget) no início de uma análise real; quem chama
//    só aguarda o resultado no momento de montar o relatório final, nunca
//    bloqueia o começo do scan (ver `bin/zunvio.mjs` e `executarCli` em
//    `src/cli.mjs`).

const REGISTRY_URL = 'https://registry.npmjs.org/zunvio-score/latest';
const TIMEOUT_MS = 1500;
// Validação defensiva do valor de versão vindo do registry ANTES de
// interpolar na mensagem impressa no terminal do usuário (revisão do Codex,
// MASS-388 round 2): mesmo o npm sendo fonte confiável, nunca interpola
// string de rede sem confirmar formato esperado — evita qualquer sequência
// de escape de terminal ou conteúdo inesperado entrando na mensagem.
const REGEX_SEMVER = /^\d+\.\d+\.\d+(-[\w.]+)?$/;

function partesVersao(v) {
  return String(v ?? '').split('.').map((n) => Number.parseInt(n, 10) || 0);
}

// Compara só numericamente major.minor.patch (suficiente pra decidir "existe
// uma mais nova publicada"; não precisa de semver completo com pre-release
// aqui, e este pacote nunca publicou pre-release).
function versaoAtualEhMaisAntiga(atual, publicada) {
  const a = partesVersao(atual);
  const b = partesVersao(publicada);
  for (let i = 0; i < 3; i++) {
    if ((a[i] || 0) < (b[i] || 0)) return true;
    if ((a[i] || 0) > (b[i] || 0)) return false;
  }
  return false;
}

/**
 * Dispara a checagem imediatamente e devolve uma Promise que NUNCA rejeita:
 * resolve pra `null` em qualquer falha/timeout/versão igual ou mais nova
 * localmente, ou pra uma linha de aviso já pronta pra imprimir (stderr)
 * quando existe versão mais nova publicada no registry.
 * @param {string} versaoAtual - Versão instalada (de `package.json`).
 * @returns {Promise<string|null>}
 */
export function iniciarChecagemVersao(versaoAtual) {
  return (async () => {
    const controlador = new AbortController();
    const timer = setTimeout(() => controlador.abort(), TIMEOUT_MS);
    try {
      const resposta = await fetch(REGISTRY_URL, { signal: controlador.signal });
      if (!resposta.ok) return null;
      const dados = await resposta.json();
      const versaoPublicada = typeof dados?.version === 'string' ? dados.version : null;
      if (!versaoPublicada) return null;
      // Fora do formato semver esperado: trata como se a checagem tivesse
      // falhado (fail-open) em vez de interpolar dado de rede não validado.
      if (!REGEX_SEMVER.test(versaoPublicada)) return null;
      if (!versaoAtualEhMaisAntiga(versaoAtual, versaoPublicada)) return null;
      return `[zunvio] Há uma versão mais nova publicada (v${versaoPublicada}); rode \`npx zunvio-score@latest\` para usá-la.`;
    } catch {
      // Fail-open silencioso: offline, timeout, JSON malformado etc. nunca
      // viram erro nem log — a análise segue exatamente como se a checagem
      // não existisse.
      return null;
    } finally {
      clearTimeout(timer);
    }
  })();
}
