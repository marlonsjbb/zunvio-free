import { cpSync, existsSync, lstatSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Instala o atalho /zunvio-score no Claude Code da máquina, copiando a skill
 * autocontida desta distribuição para ~/.claude/skills/zunvio-score.
 *
 * Guarda deliberada: se o destino já for um LINK (junction/symlink, o arranjo
 * usado em máquina de desenvolvimento apontando para um checkout do
 * repositório), nada é sobrescrito; copiar através do link alteraria o
 * checkout de origem em silêncio.
 *
 * @returns {number} código de saída (0 sucesso, 1 falha)
 */
export function instalarSkill({ log = (m) => console.log(m) } = {}) {
  const origem = join(__dirname, '..', 'skills', 'zunvio-score');
  if (!existsSync(join(origem, 'SKILL.md'))) {
    console.error('[zunvio] Arquivos da skill não encontrados nesta distribuição.');
    return 1;
  }
  const dirSkills = join(homedir(), '.claude', 'skills');
  const destino = join(dirSkills, 'zunvio-score');
  try {
    if (existsSync(destino) && lstatSync(destino).isSymbolicLink()) {
      console.error(`[zunvio] Já existe uma instalação por link em ${destino}; nada foi alterado.`);
      console.error('[zunvio] Remova o link primeiro se quiser trocar pela skill desta distribuição.');
      return 1;
    }
    mkdirSync(dirSkills, { recursive: true });
    cpSync(origem, destino, { recursive: true });
  } catch (err) {
    console.error(`[zunvio] Não foi possível instalar a skill (${err.message}).`);
    return 1;
  }
  log(`Skill /zunvio-score instalada em ${destino}`);
  log('Abra uma nova sessão do Claude Code e digite /zunvio-score para usar.');
  log('Qualquer outro agente com acesso ao terminal usa direto, sem instalar nada:');
  log('  npx zunvio-score analyze <pasta-do-projeto>');
  return 0;
}
