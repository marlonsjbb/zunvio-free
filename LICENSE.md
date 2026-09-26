# Termos de uso — ZUNVIO Score

Copyright © 2026 Marlon Adriano de Sousa Silva. Todos os direitos reservados.

O ZUNVIO Score ("o Software") é distribuído pelo npm como `zunvio-score`. O titular e responsável é Marlon Adriano
de Sousa Silva ("o Titular"). Estes termos valem para a versão que os acompanha. Ao instalar ou executar o
Software, você concorda com eles.

## 1. O que você pode fazer

- Executar o Software gratuitamente para analisar projetos seus ou projetos de terceiros que você tenha autorização
  para analisar, inclusive em uso comercial, em equipe e em integração contínua (CI).
- Usar, guardar e compartilhar livremente os resultados que o Software gera: relatórios, Evidence Packs e saídas
  de terminal.

## 2. O que você não pode fazer

- Redistribuir o Software, no todo ou em parte, fora do pacote oficial do npm (inclusive em outro pacote, imagem
  ou instalador).
- Vender, alugar ou sublicenciar o Software.
- Oferecer o Software, ou a análise que ele executa, como serviço hospedado para terceiros.
- Copiar, modificar ou reutilizar o Software, o código ou as regras proprietárias do ZUNVIO para redistribuir,
  sublicenciar, revender ou oferecer produto ou serviço derivado, sem autorização por escrito do Titular.
- Remover ou alterar avisos de direitos autorais e estes termos.

## 3. Componentes de terceiros

Na primeira execução, o Software baixa, das fontes oficiais, o Gitleaks (licença MIT, baixado do GitHub junto com
o arquivo LICENSE dele) e o Semgrep (licença LGPL-2.1-or-later, instalado do PyPI com os metadados de licença
dele). Eles ficam em `~/.zunvio`, não fazem parte do Software e seguem as próprias licenças, cujos avisos são
mantidos.

## 4. Sem garantia

O Software é fornecido "no estado em que se encontra", sem garantia de qualquer tipo. O resultado apoia uma
decisão sobre uma versão específica de um projeto. Ele não é certificação, auditoria nem garantia de ausência de
risco. Na máxima extensão permitida pela lei, o Titular não responde por danos decorrentes do uso do Software ou
dos seus resultados.

## 5. Dados e rede

A análise do código-fonte realizada pelo ZUNVIO CLI ocorre localmente. O ZUNVIO não envia intencionalmente o
conteúdo do código-fonte analisado aos serviços do Titular como parte dessa análise local.

Comunicação de rede que o ZUNVIO CLI inicia:
- baixar os componentes de terceiros do item 3 das fontes oficiais deles;
- o comando `notarize`, só quando você o executa, envia o hash do resultado (não o conteúdo) a calendários
  públicos do OpenTimestamps.

Ferramentas e dependências de terceiros têm comportamento próprio, regido pelas políticas delas:
- o npm/npx, ao instalar ou atualizar o pacote;
- o Semgrep e o Gitleaks, ao executarem. O ZUNVIO executa o Semgrep com a opção de telemetria desligada.

O que você faz com os resultados (compartilhar um relatório, por exemplo) é escolha sua.

## 6. Versões futuras

Versões futuras podem ter termos diferentes. Cada versão é regida pelos termos que a acompanham.

## 7. Lei aplicável

Estes termos são regidos pelas leis da República Federativa do Brasil.

## 8. Contato

Relatos de segurança: security@somosmass.com.
