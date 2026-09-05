// Fonte única do glossário reutilizável entre terminal (src/cli.mjs) e
// relatório HTML (src/report/html-report.mjs) — MASS-103, comentário 9 da
// issue: "Criar um glossário único e reutilizável, consumido por
// terminal/relatório/site quando possível".
//
// As 6 primeiras definições já estavam publicadas (seção "Entenda os
// termos" do relatório HTML, MASS-283) e permanecem com o texto idêntico
// para não regredir nenhum caso já aprovado. As demais são a tradução
// termo técnico → linguagem principal que o dono aprovou explicitamente
// no comentário 9 da MASS-103 (transcritas, não reformuladas).
export const TERMOS_GLOSSARIO = Object.freeze([
  Object.freeze({ termo: 'Score observado', definicao: 'Soma ponderada apenas do que teve prova suficiente e atendeu ao critério.' }),
  Object.freeze({ termo: 'Cobertura', definicao: 'Quanto conseguimos comprovar. A parte restante continua desconhecida.' }),
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
