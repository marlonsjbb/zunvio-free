import { existsSync } from 'node:fs';

/**
 * Resolve o bundle de autoridades certificadoras (CA) disponível no host.
 * Retorna o primeiro caminho existente, ou null quando nenhum é encontrado.
 * Usado tanto pelo scanner Semgrep quanto pelo preflight do bootstrap para que
 * o diagnóstico ambiental nunca divirja do ambiente real de execução (P3).
 */
export function resolverBundleCa() {
  const candidatos = [
    process.env.SSL_CERT_FILE,
    '/etc/ssl/cert.pem',
    '/etc/ssl/certs/ca-certificates.crt',
    '/opt/homebrew/etc/ca-certificates/cert.pem',
    '/usr/local/etc/ca-certificates/cert.pem'
  ];
  return candidatos.find((caminho) => typeof caminho === 'string' && existsSync(caminho)) || null;
}
