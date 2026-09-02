function badge(tipo, texto, valor = null) {
  return Object.freeze({ tipo, texto, valor });
}

export function gerarBadges(avaliacao, opcoes = {}) {
  if (!avaliacao?.score || !avaliacao?.decisao) return Object.freeze([]);

  const { observado, cobertura } = avaliacao.score;
  const decisao = avaliacao.decisao;

  const badges = [
    badge('ANALYZED', 'ANALYZED BY ZUNVIO'),
    badge('SCORE', `ZUNVIO SCORE · ${observado} · cobertura ${cobertura}%`, observado)
  ];

  // MASS-307 revisão: VERIFIED exige EXCLUSIVAMENTE decisaoPublicacao === 'PUBLICAR'.
  // `codigo === 'ACEITAR'` (ou qualquer outro campo) não é aceito como alternativa.
  const decisaoAprovada = decisao.decisaoPublicacao === 'PUBLICAR';

  const semBloqueadores = (decisao.bloqueadores || []).length === 0;
  const coberturaIntegral = cobertura === 100;
  const integridadePreservada = opcoes.integridade ? opcoes.integridade.inalterado === true : true;

  if (decisaoAprovada && semBloqueadores && coberturaIntegral && integridadePreservada) {
    badges.push(badge('VERIFIED', 'ZUNVIO · VERIFIED'));
  }

  return Object.freeze(badges);
}
