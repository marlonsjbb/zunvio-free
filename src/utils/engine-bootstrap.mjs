import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { createInterface } from 'node:readline/promises';

/**
 * Provisionamento do Gitleaks (o detector de segredos) com CONSENTIMENTO do
 * usuário, autorizado por Marlon em 2026-09-02 com a condição de que a pessoa
 * fique ciente do que está sendo instalado. Nada é baixado em silêncio:
 *
 *  - em terminal interativo, um aviso nomeia a ferramenta, a versão, a origem
 *    oficial, o destino em disco e a verificação de integridade, e pergunta
 *    antes de baixar;
 *  - fora de terminal interativo (pipe/CI), NUNCA baixa sozinho: só com o
 *    consentimento prévio explícito ZUNVIO_AUTO_MOTORES=1;
 *  - versão FIXA, URL oficial de release, SHA-256 conferido contra constante
 *    embutida NESTE código antes de qualquer extração;
 *  - qualquer falha degrada honestamente: o portão de segredos fica
 *    NÃO COMPROVADO, nunca finge sucesso;
 *  - nada é gravado fora de ~/.zunvio/bin.
 *
 * O Semgrep NÃO entra aqui de propósito: não é um binário único (é uma
 * ferramenta Python, com suporte a Windows ainda limitado), então continua
 * opcional com degradação honesta. A produtização multi-motor é a MASS-304.
 */

const VERSAO_GITLEAKS = '8.18.4';

const PINS = {
  'win32-x64': {
    arquivo: `gitleaks_${VERSAO_GITLEAKS}_windows_x64.zip`,
    sha256: '9ba442ca7dda19885a2e569f43a127289feeb2b5fb0dfa251dafd277f4a0ba91',
    binario: 'gitleaks.exe'
  },
  'linux-x64': {
    arquivo: `gitleaks_${VERSAO_GITLEAKS}_linux_x64.tar.gz`,
    sha256: 'ba6dbb656933921c775ee5a2d1c13a91046e7952e9d919f9bac4cec61d628e7d',
    binario: 'gitleaks'
  },
  'darwin-x64': {
    arquivo: `gitleaks_${VERSAO_GITLEAKS}_darwin_x64.tar.gz`,
    sha256: '1a69e5666b13cd374889cbcb1939ed1573b63b551251283d5d2329a53cf58e2f',
    binario: 'gitleaks'
  },
  'darwin-arm64': {
    arquivo: `gitleaks_${VERSAO_GITLEAKS}_darwin_arm64.tar.gz`,
    sha256: 'a480d8593acd8215b22402cf0f3f88b01dcd3610c63b5391db640f7767e62104',
    binario: 'gitleaks'
  }
};

/**
 * Baixa a URL para memória. Prefere o curl do sistema (presente no Windows
 * 10+, macOS e na maioria dos Linux): em algumas redes o fetch do Node
 * expira no connect ao github.com (visto em máquina real) enquanto o curl
 * atravessa normalmente. Sem curl, cai no fetch. A verificação de SHA-256
 * acontece DEPOIS, sobre os bytes, seja qual for o caminho.
 */
async function baixarBytes(url) {
  const { mkdtempSync, readFileSync } = await import('node:fs');
  const dirTemp = mkdtempSync(join(tmpdir(), 'zunvio-dl-'));
  const destino = join(dirTemp, 'pacote.bin');
  try {
    const r = spawnSync('curl', ['-fsSL', '--retry', '2', '--max-time', '120', '-o', destino, url], { timeout: 150_000 });
    if (r.status === 0 && existsSync(destino)) {
      return Buffer.from(readFileSync(destino));
    }
    const resposta = await fetch(url, { redirect: 'follow' });
    if (!resposta.ok) {
      throw new Error(`HTTP ${resposta.status} ao baixar o Gitleaks`);
    }
    return Buffer.from(await resposta.arrayBuffer());
  } finally {
    rmSync(dirTemp, { recursive: true, force: true });
  }
}

function jaNoPath() {
  const r = spawnSync('gitleaks', ['version'], { timeout: 10_000, shell: false });
  return r.status === 0;
}

async function pedirConsentimento(pin, dirCache, log) {
  if (process.env.ZUNVIO_AUTO_MOTORES === '1') {
    return true;
  }
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    log('[zunvio] O detector de segredos (Gitleaks) não está nesta máquina e este terminal não é interativo.');
    log('[zunvio] Para autorizar o download automático verificado, rode com ZUNVIO_AUTO_MOTORES=1; o portão de segredos ficará NÃO COMPROVADO nesta execução.');
    return false;
  }
  log('');
  log('O detector de segredos não está nesta máquina.');
  log(`  Ferramenta:  Gitleaks ${VERSAO_GITLEAKS} (código aberto, licença MIT)`);
  log('  Origem:      github.com/gitleaks/gitleaks (release oficial)');
  log('  Integridade: SHA-256 conferido contra valor fixado neste código');
  log(`  Destino:     ${dirCache} (nada fora desta pasta)`);
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const resposta = (await rl.question('Baixar agora? [S/n] ')).trim().toLowerCase();
    return resposta === '' || resposta === 's' || resposta === 'sim' || resposta === 'y' || resposta === 'yes';
  } finally {
    rl.close();
  }
}

function extrair(plataforma, arquivoBaixado, dirDestino) {
  if (plataforma.startsWith('win32')) {
    const r = spawnSync(
      'powershell',
      ['-NoProfile', '-Command', `Expand-Archive -LiteralPath "${arquivoBaixado}" -DestinationPath "${dirDestino}" -Force`],
      { timeout: 60_000 }
    );
    return r.status === 0;
  }
  const r = spawnSync('tar', ['-xzf', arquivoBaixado, '-C', dirDestino], { timeout: 60_000 });
  return r.status === 0;
}

/**
 * Garante um Gitleaks utilizável, nesta ordem: já no PATH → cache local
 * (~/.zunvio/bin) → download oficial com consentimento e hash conferido.
 * Nunca lança: devolve a origem usada, ou null (e o chamador segue degradado).
 */
export async function garantirGitleaks({ log = (m) => console.error(m) } = {}) {
  try {
    if (jaNoPath()) {
      return { disponivel: true, origem: 'PATH' };
    }

    const plataforma = `${process.platform}-${process.arch}`;
    const pin = PINS[plataforma];
    if (!pin) {
      log(`[zunvio] Gitleaks ausente e sem provisionamento automático para ${plataforma}; o portão de segredos ficará NÃO COMPROVADO.`);
      return { disponivel: false, origem: null };
    }

    const dirCache = join(homedir(), '.zunvio', 'bin');
    const caminhoBinario = join(dirCache, pin.binario);
    const marcador = join(dirCache, `.gitleaks-${VERSAO_GITLEAKS}.ok`);

    if (existsSync(caminhoBinario) && existsSync(marcador)) {
      process.env.PATH = `${dirCache}${delimiter}${process.env.PATH ?? ''}`;
      return { disponivel: true, origem: 'CACHE' };
    }

    const consentiu = await pedirConsentimento(pin, dirCache, log);
    if (!consentiu) {
      return { disponivel: false, origem: null };
    }

    const url = `https://github.com/gitleaks/gitleaks/releases/download/v${VERSAO_GITLEAKS}/${pin.arquivo}`;
    log(`[zunvio] Baixando ${pin.arquivo} do release oficial...`);
    const bytes = await baixarBytes(url);
    const hash = createHash('sha256').update(bytes).digest('hex');
    if (hash !== pin.sha256) {
      // Integridade acima de conveniência: hash divergente nunca é extraído.
      throw new Error(`SHA-256 divergente do fixado (esperado ${pin.sha256.slice(0, 12)}..., veio ${hash.slice(0, 12)}...)`);
    }

    mkdirSync(dirCache, { recursive: true });
    const arquivoTemp = join(tmpdir(), `zunvio-${pin.arquivo}`);
    writeFileSync(arquivoTemp, bytes);
    const okExtracao = extrair(plataforma, arquivoTemp, dirCache);
    rmSync(arquivoTemp, { force: true });
    if (!okExtracao || !existsSync(caminhoBinario)) {
      throw new Error('falha ao extrair o pacote do Gitleaks');
    }
    if (!plataforma.startsWith('win32')) {
      chmodSync(caminhoBinario, 0o755);
    }
    writeFileSync(marcador, `sha256(${pin.arquivo})=${pin.sha256}\n`);

    process.env.PATH = `${dirCache}${delimiter}${process.env.PATH ?? ''}`;
    const confirma = spawnSync(caminhoBinario, ['version'], { timeout: 10_000 });
    if (confirma.status !== 0) {
      throw new Error('binário baixado não executou');
    }
    log(`[zunvio] Gitleaks ${String(confirma.stdout ?? '').trim()} pronto (hash conferido; guardado em ~/.zunvio/bin).`);
    return { disponivel: true, origem: 'BAIXADO' };
  } catch (err) {
    log(`[zunvio] Não foi possível obter o Gitleaks automaticamente (${err.message}); o portão de segredos ficará NÃO COMPROVADO.`);
    return { disponivel: false, origem: null };
  }
}
