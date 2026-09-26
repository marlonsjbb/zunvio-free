const ANSI_TEAL = '\u001b[38;2;71;165;171m';
const ANSI_RESET = '\u001b[0m';

export const BANNER_UNICODE_PRINCIPAL = Object.freeze([
  '  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ',
  '  █████████████████ ',
  '  ▀▀▀▀▀▀▀▀▀▀▀▀████▀ ',
  '       ▄▄▄  ▄████▀  ',
  '     ████▀ ▄████    ',
  '   ▄████▀ ████▀     ',
  '  ▄████  ▀▀▀▀       ',
  ' ▄████▄▄▄▄▄▄▄▄▄▄▄▄▄ ',
  ' ██████████████████ ',
  '  ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀ '
]);

export const BANNER_UNICODE_COMPACTA = Object.freeze([
  ' ▄▄▄▄▄▄▄▄▄▄ ',
  ' ▀▀▀▀▀▀▀███ ',
  '   ▄██ ▄█▀  ',
  '  ██▀ ██▀   ',
  ' ███▄▄▄▄▄▄▄ ',
  ' ▀▀▀▀▀▀▀▀▀▀ '
]);

export const BANNER_ASCII_PRINCIPAL = Object.freeze([
  ' ################## ',
  '  ################  ',
  '             ####   ',
  '     ##### #####    ',
  '    ####  #####     ',
  '   ####             ',
  ' #################  ',
  ' ################## '
]);

export const BANNER_ASCII_COMPACTA = Object.freeze([
  ' ########## ',
  ' ########## ',
  '    ## ###  ',
  '  ### ##    ',
  ' ########## ',
  ' ##########'
]);

/**
 * Seleciona a arte do banner sem fazer detecção de encoding ou chamadas externas.
 * Retorna null quando a saída não deve receber banner.
 *
 * @param {{ noBanner?: boolean, stream?: NodeJS.WriteStream, ascii?: boolean, noColor?: boolean }} [opcoes]
 * @returns {string[] | null}
 */
export function selecionarBanner(opcoes = {}) {
  const stream = opcoes.stream || process.stdout;
  const semBanner = opcoes.noBanner === true || process.env.ZUNVIO_NO_BANNER === '1' || !stream.isTTY;
  if (semBanner) return null;

  const principal = (stream.columns || 80) >= 80;
  const usarAscii = opcoes.ascii ?? process.env.ZUNVIO_BANNER_ASCII === '1';
  const monocromatica = opcoes.noColor ?? Boolean(process.env.NO_COLOR);
  const arte = usarAscii
    ? (principal ? BANNER_ASCII_PRINCIPAL : BANNER_ASCII_COMPACTA)
    : (principal ? BANNER_UNICODE_PRINCIPAL : BANNER_UNICODE_COMPACTA);

  if (monocromatica) return [...arte];
  return arte.map((linha) => `${ANSI_TEAL}${linha}${ANSI_RESET}`);
}

export const BANNER_COR_OFICIAL = '#47A5AB';
export const BANNER_ANSI_TEAL = ANSI_TEAL;
export const BANNER_ANSI_RESET = ANSI_RESET;
