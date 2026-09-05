// Indicador de progresso por etapas do terminal interativo (MASS-103,
// comentário 8 da issue: "spinner ou indicador enquanto uma etapa estiver
// ativa"). Este módulo só REFLETE o que o orquestrador já executa — nunca
// decide, nunca altera avaliação/score/decisão, nunca é chamado fora de TTY
// interativo (a decisão de instanciar ou não fica inteiramente com quem
// importa este módulo, tipicamente src/cli.mjs, que já filtra --json, pipe,
// CI e NO_COLOR antes de chegar aqui).

const QUADROS_SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const INTERVALO_MS = 90;
const OCULTAR_CURSOR = '[?25l';
const MOSTRAR_CURSOR = '[?25h';
const LIMPAR_LINHA = '[2K';

function subirLinhas(n) {
  return n > 0 ? `[${n}A` : '';
}

/**
 * Decide se ALGUM indicador visual (etapas ou spinner simples) pode escrever
 * códigos ANSI nesta execução: só em TTY interativo real, nunca em --json,
 * pipe/redirecionamento, CI, ou com NO_COLOR setado (MASS-103 e MASS-388,
 * achado 1). Única fonte de verdade — tanto o indicador de etapas em
 * `src/cli.mjs` (escreve em stdout) quanto o spinner de bootstrap do
 * provisionamento de motores em `src/utils/engine-bootstrap.mjs` (escreve em
 * stderr) reaproveitam esta mesma checagem, em vez de duplicar a condição em
 * cada lugar — por isso as DUAS streams (stdout e stderr) precisam ser TTY
 * real: fail-safe, na dúvida desativa (revisão do Codex, MASS-388 round 2).
 * @param {string[]} args - Argumentos crus da linha de comando.
 */
export function podeUsarIndicadorVisual(args = []) {
  if (args.includes('--json')) return false;
  // Convenção universal de CI: QUALQUER valor definido (mesmo "false" como
  // string) indica execução automatizada — nunca arriscar vazar ANSI em log
  // de CI (revisão do Codex, MASS-388 round 2).
  if (process.env.CI) return false;
  // Convenção NO_COLOR (no-color.org): QUALQUER valor definido, inclusive
  // string vazia (`NO_COLOR=`), desliga cores. Checagem precisa ser
  // `!== undefined`, nunca uma checagem de truthy (que trata string vazia
  // como falsa e deixaria passar `NO_COLOR=` sem querer — revisão do Codex,
  // MASS-388 round 2).
  if (process.env.NO_COLOR !== undefined) return false;
  return Boolean(process.stdout.isTTY) && Boolean(process.stderr.isTTY);
}

/**
 * Cria um indicador de progresso por etapas nomeadas, redesenhado no lugar
 * (sem rolar o terminal) enquanto a etapa ativa gira o spinner. Chamador
 * decide quando cada etapa inicia/conclui via `iniciar`/`concluir`; `finalizar`
 * para a animação, restaura o cursor e remove o handler de SIGINT — deve ser
 * chamado sempre, inclusive no caminho de erro, para nunca deixar o terminal
 * em estado corrompido (cursor oculto, linha presa).
 * @param {string[]} nomesEtapas - Rótulos das etapas, na ordem de exibição.
 * @param {{ stream?: NodeJS.WritableStream }} [opcoes]
 */
export function criarIndicadorEtapas(nomesEtapas, opcoes = {}) {
  const stream = opcoes.stream || process.stdout;
  const estados = new Map(nomesEtapas.map((nome) => [nome, 'pendente']));
  let quadro = 0;
  let intervalo = null;
  let linhasImpressas = 0;
  let finalizado = false;

  function render() {
    if (finalizado) return;
    const linhas = nomesEtapas.map((nome) => {
      const estado = estados.get(nome);
      const marcador =
        estado === 'concluida' ? '[32m✓[0m'
          : estado === 'iniciando' ? `[36m${QUADROS_SPINNER[quadro % QUADROS_SPINNER.length]}[0m`
            : ' ';
      return `\r[2K[${marcador}] ${nome}`;
    });
    stream.write(subirLinhas(linhasImpressas) + linhas.join('\n') + '\n');
    linhasImpressas = nomesEtapas.length;
  }

  function iniciar(nome) {
    if (finalizado || !estados.has(nome)) return;
    estados.set(nome, 'iniciando');
    render();
  }

  function concluir(nome) {
    if (finalizado || !estados.has(nome)) return;
    estados.set(nome, 'concluida');
    render();
  }

  function aoSigint() {
    finalizar();
    process.exit(130);
  }

  function finalizar() {
    if (finalizado) return;
    finalizado = true;
    if (intervalo) clearInterval(intervalo);
    intervalo = null;
    process.removeListener('SIGINT', aoSigint);
    stream.write(MOSTRAR_CURSOR);
  }

  stream.write(OCULTAR_CURSOR);
  process.on('SIGINT', aoSigint);
  intervalo = setInterval(() => {
    quadro += 1;
    render();
  }, INTERVALO_MS);
  if (typeof intervalo.unref === 'function') intervalo.unref();
  render();

  return { iniciar, concluir, finalizar };
}

/**
 * Spinner de atividade de uma linha só ("trabalhando..."), para trechos que
 * não têm etapas nomeadas — hoje só o provisionamento dos motores (download
 * do Gitleaks, instalação do Semgrep via pip em `engine-bootstrap.mjs`), que
 * roda em `bin/zunvio.mjs` ANTES do indicador de etapas de
 * `criarIndicadorEtapas` sequer existir (MASS-388, achado 1: hoje essas
 * etapas ficam mudas por até minutos). Mesmas regras do indicador de etapas:
 * quem chama decide se instancia (`podeUsarIndicadorVisual`), a stream é
 * explícita (o bootstrap escreve em stderr, junto dos prompts de
 * consentimento, pra não misturar com o stdout reservado ao relatório), e
 * `finalizar` é idempotente e deve ser chamado sempre — inclusive no caminho
 * de erro/timeout — pra nunca deixar o cursor escondido ou uma linha presa.
 * @param {string} mensagem - Texto fixo ao lado do spinner.
 * @param {{ stream?: NodeJS.WritableStream }} [opcoes]
 */
export function criarIndicadorSimples(mensagem, opcoes = {}) {
  const stream = opcoes.stream || process.stdout;
  let quadro = 0;
  let intervalo = null;
  let finalizado = false;

  function render() {
    if (finalizado) return;
    stream.write(`\r${LIMPAR_LINHA}${QUADROS_SPINNER[quadro % QUADROS_SPINNER.length]} ${mensagem}`);
  }

  function aoSigint() {
    finalizar();
    process.exit(130);
  }

  function finalizar() {
    if (finalizado) return;
    finalizado = true;
    if (intervalo) clearInterval(intervalo);
    intervalo = null;
    process.removeListener('SIGINT', aoSigint);
    stream.write(`\r${LIMPAR_LINHA}`);
    stream.write(MOSTRAR_CURSOR);
  }

  stream.write(OCULTAR_CURSOR);
  process.on('SIGINT', aoSigint);
  intervalo = setInterval(() => {
    quadro += 1;
    render();
  }, INTERVALO_MS);
  if (typeof intervalo.unref === 'function') intervalo.unref();
  render();

  return { finalizar };
}
