# ZUNVIO: scan gratuito (distribuição de teste)

A ZUNVIO analisa **uma versão exata** de um projeto de software e responde, com prova,
à pergunta que importa antes de publicar: **podemos avançar com esta versão?**

A análise é 100% local e **somente leitura**. Nada no projeto é alterado (o relatório
comprova a imutabilidade ao final) e nada sai da sua máquina.

## Usar sem instalar nada

Com Node.js 20+ e Git na máquina, um comando só:

```
npx github:marlonsjbb/zunvio-free analyze CAMINHO\DA\PASTA
```

Exemplo:

```
npx github:marlonsjbb/zunvio-free analyze D:\Projetos\meu-sistema
```

Se preferir ter o comando `zunvio` instalado de vez:

```
npm install -g github:marlonsjbb/zunvio-free
zunvio analyze CAMINHO\DA\PASTA
```

## O que a máquina precisa ter

| Ferramenta | O que é | Precisa? |
| --- | --- | --- |
| Node.js 20+ | o motor que executa a ZUNVIO | sim (`node --version`) |
| Git | controla versões de código; a ZUNVIO lê o histórico do projeto por ele | sim (`git --version`) |
| Gitleaks | o detector de segredos: procura senhas e chaves esquecidas no código e no histórico | recomendado; sem ele o portão de segredos fica "não comprovado" |
| Semgrep | analisador de padrões perigosos no código | opcional; sem ele o portão correspondente fica "não comprovado" |

Para o Gitleaks: `winget install gitleaks`. Se o winget der erro (comum em máquina
corporativa), baixe o `gitleaks_..._windows_x64.zip` em
github.com/gitleaks/gitleaks/releases, extraia e copie o `gitleaks.exe` para a pasta
que abre com `explorer "$env:APPDATA\npm"` (com o Node instalado, essa pasta já é
reconhecida pelo sistema).

## Como ler o resultado

Leia nesta ordem: **DECISÃO** (PUBLICAR · NÃO PUBLICAR · INCONCLUSIVO), depois
**COBERTURA** (quanto foi de fato comprovado), depois as **Próximas ações**.
Score alto nunca compensa um bloqueador; na dúvida, a ZUNVIO não autoriza avançar.

## Sobre esta distribuição

- Conteúdo: somente os arquivos necessários para o scan gratuito (comandos `analyze`
  e `verify`), extraídos da linha principal do produto.
- Proveniência: base `main@688293e` do repositório principal, mais a correção da
  projeção do Evidence Pack (contrato de ingestão).
- **Código-fonte disponível para avaliação. Todos os direitos reservados (MASS).**
  Esta é uma distribuição de teste; não é uma licença de uso livre nem um pacote
  de código aberto.
