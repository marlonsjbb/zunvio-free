// Fonte única do glossário reutilizável entre terminal (src/cli.mjs) e
// relatório HTML (src/report/html-report.mjs) — MASS-103, comentário 9 da
// issue: "Criar um glossário único e reutilizável, consumido por
// terminal/relatório/site quando possível".
//
// As 6 primeiras definições já estavam publicadas (seção "Entenda os
// termos" do relatório HTML, MASS-283) e permanecem com o texto idêntico
// para não regredir nenhum caso já aprovado — exceto "Cobertura", corrigida
// em 26/09/2026 (distorção semântica). As demais são a tradução
// termo técnico → linguagem principal que o dono aprovou explicitamente
// no comentário 9 da MASS-103 (transcritas, não reformuladas).
export const TERMOS_GLOSSARIO = Object.freeze([
  Object.freeze({ termo: 'Score observado', definicao: 'Soma ponderada apenas do que teve prova suficiente e atendeu ao critério.' }),
  // A definição antiga igualava cobertura a comprovação e fazia a cobertura dos motores — que inclui conclusões
  // negativas — parecer o quanto está comprovadamente bom. As três medidas são as mesmas da saída da CLI.
  // "Contexto do contrato" mede dimensões DECLARADAS (preenchidas) no contrato — declarar não comprova; a comprovação
  // por evidência de cada dimensão é o mapa de claims.
  Object.freeze({ termo: 'Cobertura', definicao: 'Alcance da avaliação, em três medidas separadas: cobertura da avaliação, cobertura dos motores e contexto declarado do contrato. Nenhuma delas é o quanto foi aprovado.' }),
  Object.freeze({ termo: 'Cobertura da avaliação', definicao: 'Valor usado pela decisão: o menor percentual entre a cobertura dos motores e o contexto declarado do contrato.' }),
  Object.freeze({ termo: 'Cobertura dos motores', definicao: 'Peso dos portões que chegaram a uma conclusão, positiva ou negativa. Não é o quanto foi aprovado.' }),
  Object.freeze({ termo: 'Contexto do contrato', definicao: 'Percentual das 12 dimensões declaradas (preenchidas) no Contrato de Publicação. Declarar não comprova: o que foi comprovado por evidência aparece no mapa de claims.' }),
  Object.freeze({ termo: 'Não comprovado', definicao: 'Faltou prova ou a verificação não concluiu. Não é sinônimo automático de reprovação.' }),
  Object.freeze({ termo: 'Não atende', definicao: 'Existe prova conclusiva de que o critério não foi atendido.' }),
  Object.freeze({ termo: 'Informação declarada', definicao: 'Contexto informado no Contrato de Publicação; sozinho, não é uma prova.' }),
  Object.freeze({ termo: 'Evidence Pack', definicao: 'Conjunto estruturado de provas, decisão, integridade e limitações desta execução.' }),
  Object.freeze({ termo: 'Evidência', definicao: 'Prova usada para chegar à conclusão.' }),
  Object.freeze({ termo: 'Portão (gate)', definicao: 'Verificação obrigatória para avançar.' }),
  Object.freeze({ termo: 'Achado (finding)', definicao: 'Problema ou sinal que precisa ser analisado.' }),
  Object.freeze({ termo: 'Scanner', definicao: 'Ferramenta que realiza uma verificação automática.' }),
  Object.freeze({ termo: 'Release / commit', definicao: 'Versão exata do projeto que foi analisada.' }),
  Object.freeze({ termo: 'Score Receipt', definicao: 'Recibo verificável do resultado (arquivo aceito por "zunvio verify").' }),
  Object.freeze({ termo: 'Fail-closed', definicao: 'Na dúvida, o ZUNVIO não autoriza avançar.' })
]);
