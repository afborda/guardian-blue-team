import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const SRC = join(process.cwd(), 'src');
const ALLOWED = new Set([
  'telegram/messaging/sender.ts',
  'index.ts', // setWebhook / setMyCommands: configuração do bot, não mensagem
]);

function walk(dir: string, files: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full, files);
    else if (full.endsWith('.ts')) files.push(full);
  }
  return files;
}

describe('fronteira do Telegram', () => {
  it('só o sender (e o setup do webhook) fala com api.telegram.org', () => {
    const offenders = walk(SRC)
      .filter(file => readFileSync(file, 'utf8').includes('api.telegram.org'))
      .map(file => relative(SRC, file).replaceAll('\\', '/'));

    expect(offenders.filter(file => !ALLOWED.has(file))).toEqual([]);
  });

  it('nenhum worker monta parse_mode manualmente', () => {
    const offenders = walk(SRC)
      .filter(file => !file.endsWith('telegram/messaging/sender.ts'))
      .filter(file => readFileSync(file, 'utf8').includes("parse_mode: 'HTML'"))
      .map(file => relative(SRC, file).replaceAll('\\', '/'));

    expect(offenders).toEqual([]);
  });
});
