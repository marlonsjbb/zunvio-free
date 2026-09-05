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

function subirLinhas(n) {
  return n > 0 ? `[${n}A` : '';
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
