# ZUNVIO Score

A ZUNVIO analisa **uma versão exata** de um projeto de software e responde, com prova,
à pergunta que importa antes de publicar: **podemos avançar com esta versão?**

A análise é 100% local e **somente leitura**. Nada no projeto é alterado (o relatório
comprova a imutabilidade ao final) e nada sai da sua máquina.

## Usar sem instalar nada

Com Node.js 20+ e Git na máquina, um comando só:

```
npx zunvio-score analyze CAMINHO\DA\PASTA
```

Exemplo:

```
npx zunvio-score analyze D:\Projetos\meu-sistema
```

Se preferir ter o comando `zunvio` instalado de vez:

```
npm install -g zunvio-score
zunvio analyze CAMINHO\DA\PASTA
```

## O que a máquina precisa ter

| Ferramenta | O que é | Precisa? |
| --- | --- | --- |
| Node.js 20+ | o motor que executa a ZUNVIO | sim (`node --version`) |
| Git | controla versões de código; a ZUNVIO lê o histórico do projeto por ele | sim (`git --version`) |
| Gitleaks | o detector de segredos: procura senhas e chaves esquecidas no código e no histórico | a ZUNVIO oferece instalação automática (veja abaixo) |
| Semgrep | analisador de padrões perigosos no código | a ZUNVIO oferece instalação automática; requer Python 3.10+ na máquina |

**Instalação automática dos motores, sempre com a sua permissão.** Quando um motor
está faltando, a ZUNVIO mostra na tela o que é a ferramenta, de onde ela vem (release
oficial do Gitleaks no GitHub, com hash SHA-256 conferido; pacote oficial do Semgrep
no PyPI, com versão fixada), quanto ocupa e onde fica (`~/.zunvio`, nada fora dessa
pasta), e só baixa depois que você responder sim. Em terminal não interativo (scripts,
CI, agentes), nada é instalado sem a variável `ZUNVIO_AUTO_MOTORES=1`. Se você
recusar, a análise roda mesmo assim, com o portão correspondente marcado como
"não comprovado".

Se preferir instalar o Gitleaks por conta própria: `winget install gitleaks`. Se o
winget der erro (comum em máquina corporativa), baixe o
`gitleaks_..._windows_x64.zip` em github.com/gitleaks/gitleaks/releases, extraia e
copie o `gitleaks.exe` para a pasta que abre com `explorer "$env:APPDATA\npm"`.

## Use dentro do Claude (/zunvio-score)

Quem usa o Claude Code pode instalar o atalho uma única vez:

```
npx zunvio-score skill install
```

Depois, em qualquer sessão nova do Claude Code, digite `/zunvio-score` e peça a
análise do projeto que quiser. O Claude executa a ferramenta localmente, pede a sua
permissão antes de instalar qualquer motor e apresenta a decisão com as próximas
ações. Qualquer outro agente com acesso ao terminal também consegue usar a ZUNVIO
sem instalar nada: basta pedir para rodar `npx zunvio-score analyze <pasta>`.

## Como ler o resultado

Leia nesta ordem: **DECISÃO** (PUBLICAR · NÃO PUBLICAR · INCONCLUSIVO), depois
**COBERTURA** (quanto foi de fato comprovado), depois as **Próximas ações**.
Score alto nunca compensa um bloqueador; na dúvida, a ZUNVIO não autoriza avançar.

## Sobre esta distribuição

- Conteúdo: somente os arquivos necessários para o scan gratuito (comandos `analyze`,
  `verify` e `skill install`), extraídos da linha principal do produto.
- Proveniência: base `main@688293e` do repositório principal, mais a correção da
  projeção do Evidence Pack (contrato de ingestão).
- **Código-fonte disponível para avaliação. Todos os direitos reservados (MASS).**
  Esta é uma distribuição de teste; não é uma licença de uso livre nem um pacote
  de código aberto.
