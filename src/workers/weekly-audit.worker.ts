/**
 * WeeklyAuditWorker — auditoria semanal SOMENTE-LEITURA do host `hetzner-prod`,
 * reportada por Telegram via NotifierManager (mesmo padrão do DailyReportWorker).
 *
 * Regras deste worker:
 *  - NUNCA executa comando de escrita: sem rm/mv/delete/prune/restart/stop/docker rmi.
 *  - Acesso ao host via SSH (SSHCollector), usando o servidor 'hetzner-prod' da tabela soc_servers.
 *  - A mensagem é montada para caber no limite de 4096 chars do Telegram (guarda MAX_MESSAGE_CHARS).
 *
 * Agendamento: domingo 09:00 America/Sao_Paulo (= 12:00 UTC; BRT = UTC-3, sem horário de verão).
 * Check a cada 60s (padrão dos workers). Se o Guardian reiniciar depois das 09:00 BRT no
 * domingo, o relatório sai no primeiro tick pós-restart (no máximo 1x por dia BRT — guardado
 * por `lastSentDate` em memória).
 *
 * Baseline de `/` e `/opt` registrada em 2026-10-17 (ver /AGENTS.md §5): ao adicionar uma
 * entrada intencional no servidor, atualize ROOT_BASELINE/OPT_BASELINE — é isso que faz o
 * relatório acusar "novidades" indevidas.
 *
 * Trigger manual:
 *   docker exec guardian node dist/scripts/weekly-audit-now.js [--test] [--dry-run]
 */
import { ServerService } from '../services/server.service.js';
import { SSHCollector, type SSHTarget } from '../collectors/ssh-collector.js';
import { NotifierManager } from '../plugins/notifier-manager.js';
import { logger } from '../utils/logger.js';

const AUDIT_SERVER_NAME = 'hetzner-prod';
const MAX_MESSAGE_CHARS = 3900; // folga sob o limite de 4096 do Telegram
const SSH_TIMEOUT_MS = 60_000;
const MARK = '<<<SEP>>>';

// ── Limiares declarados (ver /AGENTS.md §7) ─────────────────────────────────
const BABARATO_MAX_AGE_HOURS = 26; // cron 03:00 UTC; espelha src/collectors/backup-collector.ts
// Diário leve (zstd + GPG, sem ingested_messages): ~40-120 MB.
const BABARATO_MIN_SIZE_BYTES = 10_000_000;
// Full mensal (cron dia 1, 03:20 UTC) em /backup/monthly — 45d tolera um mês perdido.
const BABARATO_FULL_MAX_AGE_DAYS = 45;
// Offsite do babarato: backup_offsite.sh (diário, 04:10 UTC) copia para o Storage Box.
// Tolerância de 8 dias para não gerar ruído semanal e ainda pegar sincronização parada.
const BABARATO_OFFSITE_MAX_AGE_HOURS = 8 * 24;
const VERBO_MAX_AGE_HOURS = 26; // cron 05,13,21 UTC (cadência de 8h)
const VERBO_MIN_SIZE_BYTES = 1_000_000;
const ROOT_WARN_BYTES = 4 * 1024 ** 3; // /root: alerta acima de 4 GiB (baseline 17/10/2026: 3,7 GiB)
const DISK_WARN_PERCENT = 85;
const DIFF_ITEM_CAP = 6;

// ── Baseline registrada em 2026-10-17 (inspeção somente-leitura) ────────────
// Entradas esperadas na raiz `/`.
const ROOT_BASELINE: readonly string[] = [
  'AGENTS.md',
  'backup', 'bin', 'bin.usr-is-merged', 'boot', 'cdrom', 'data', 'dev', 'etc',
  'home', 'installimage.conf', 'installimage.debug', 'lib', 'lib64',
  'lib.usr-is-merged', 'lost+found', 'media', 'mnt', 'opt', 'proc', 'root',
  'run', 'sbin', 'sbin.usr-is-merged', 'snap', 'srv', 'sys', 'tmp', 'usr', 'var',
];

// Entradas esperadas em `/opt`.
const OPT_BASELINE: readonly string[] = [
  'automabothub', 'automabothub-frontend', 'babarato', 'babarato-backups',
  'casa-compras', 'containerd', 'evolution', 'fraudflow', 'guardian', 'infra',
  'jellyfin', 'jellyfin-bot', 'librechat', 'link-hub', 'ninho', 'ninho-dev',
  'radar-hype', 'raven-exercise', 'raven-exercise-nginx.conf', 'site',
  'synthfin', 'verbo-connect', 'whatsapp',
];

// Arquivos que o sistema mantém em /var/backups (dpkg/apt/alternatives). Qualquer
// outra entrada é sinalizada como "dados de projeto" (política: /var/backups é do sistema).
const VARBACKUPS_SYSTEM_PATTERN = /^(alternatives\.|apt\.|dpkg\.|lost\+found)/;

// ── Comandos remotos (100% leitura) ─────────────────────────────────────────
const CMD_LISTINGS = `ls -1A /; echo '<<<OPT>>>'; ls -1A /opt`;

const CMD_USAGE = [
  `du -s --block-size=1 /root 2>/dev/null`,
  `du -s --block-size=1 /root/* /root/.[!.]* 2>/dev/null | sort -rn | head -8`,
  `du -sx --block-size=1 /var/lib/docker 2>/dev/null`,
  `du -s --block-size=1 /backup 2>/dev/null`,
].join(`; echo '<<<SEP_USAGE>>>'; `);

const CMD_VARBACKUPS = `ls -1A /var/backups`;

const CMD_BACKUPS = [
  // babarato local: último arquivo do diário leve (novo .sql.zst.gpg ou legado .gz.gpg)
  `timeout 30 find /backup/daily -maxdepth 1 \\( -name 'babarato-*.sql.zst.gpg' -o -name 'babarato-*.sql.gz.gpg' \\) -printf '%T@ %s %f\\n' 2>/dev/null | sort -rn | head -1`,
  // babarato full mensal (cron dia 1 03:20 UTC): último arquivo de /backup/monthly
  `timeout 30 find /backup/monthly -maxdepth 1 -name 'babarato-full-*.sql.zst.gpg' -printf '%T@ %s %f\\n' 2>/dev/null | sort -rn | head -1`,
  // staging do verbo: deve estar vazio (só transita durante o backup)
  `timeout 30 find /backup/verbo-connect-staging -mindepth 1 -maxdepth 1 -printf '%f\\n' 2>/dev/null | head -5`,
  // verbo offsite: último arquivo
  `timeout 30 find /var/media/jellyfin/bancoVerboConnect -maxdepth 1 -name 'verbo-connect-*.db' -printf '%T@ %s %f\\n' 2>/dev/null | sort -rn | head -1`,
  // babarato offsite (backup_offsite.sh → Storage Box): arquivos; reportar estado (pruning é do script)
  `timeout 30 find /var/media/jellyfin/babarato-backups -maxdepth 1 -type f -printf '%T@ %s %f\\n' 2>/dev/null | sort -rn | head -10`,
  // Storage Box montado?
  `findmnt -n -o SOURCE --target /var/media/jellyfin 2>/dev/null || echo NOTMOUNTED`,
].join(`; echo '${MARK}'; `);

const CMD_DOCKER = [
  `docker system df`,
  `docker ps -a --filter health=unhealthy --format '{{.Names}}' | head -5`,
  `docker ps -a --filter status=restarting --format '{{.Names}}' | head -5`,
  `docker ps -q | wc -l`,
].join(`; echo '<<<SEP_DOCKER>>>'; `);

const CMD_HEALTH = [
  `cat /proc/mdstat`,
  `systemctl list-units --failed --no-legend --no-pager | head -10`,
  `if [ -f /var/run/reboot-required ]; then echo "PENDING $(date -r /var/run/reboot-required +%F)"; else echo NONE; fi`,
  `df -h --output=target,size,used,pcent / /boot /var /backup /var/media/jellyfin 2>/dev/null | tail -n +2`,
].join(`; echo '<<<SEP_HEALTH>>>'; `);

// ── Tipos auxiliares ────────────────────────────────────────────────────────
interface BackupFileInfo {
  name: string;
  ageHours: number;
  sizeBytes: number;
}

interface DiskInfo {
  mount: string;
  size: string;
  used: string;
  percent: number;
}

interface RaidArrayInfo {
  name: string;
  active: boolean;
  state: string | null;
}

export interface WeeklyAuditOptions {
  /** Marca a mensagem com [teste] (usado no disparo manual). */
  test?: boolean;
  /** Não envia ao Telegram; imprime a mensagem no stdout. */
  dryRun?: boolean;
}

// ── Helpers de formatação/parsing ───────────────────────────────────────────
function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function fmtBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '?';
  const g = bytes / 1024 ** 3;
  if (g >= 1) return `${g.toFixed(1)}G`;
  const m = bytes / 1024 ** 2;
  if (m >= 1) return `${m.toFixed(1)}M`;
  const k = bytes / 1024;
  if (k >= 1) return `${k.toFixed(1)}K`;
  return `${bytes}B`;
}

function fmtAgeHours(hours: number): string {
  if (hours < 48) return `${hours.toFixed(1)}h`;
  return `${(hours / 24).toFixed(1)}d`;
}

function splitSegments(stdout: string, markers: readonly string[]): string[] {
  const out: string[] = [];
  let rest = stdout;
  for (const marker of markers) {
    const i = rest.indexOf(marker);
    if (i === -1) {
      out.push(rest);
      rest = '';
      continue;
    }
    out.push(rest.slice(0, i));
    rest = rest.slice(i + marker.length);
  }
  out.push(rest);
  return out;
}

function parseBackupLine(text: string): BackupFileInfo | null {
  const line = text.trim().split('\n')[0]?.trim() ?? '';
  const m = line.match(/^(\d+(?:\.\d+)?)\s+(\d+)\s+(.+)$/);
  if (!m) return null;
  const mtimeSec = parseFloat(m[1]);
  return {
    name: m[3].trim(),
    ageHours: (Date.now() / 1000 - mtimeSec) / 3600,
    sizeBytes: parseInt(m[2], 10),
  };
}

function parseDuBytes(text: string): number | null {
  const m = (text.trim().split('\n')[0] ?? '').match(/^(\d+)/);
  return m ? parseInt(m[1], 10) : null;
}

function parseDuTop(text: string): Array<{ path: string; bytes: number }> {
  const rows: Array<{ path: string; bytes: number }> = [];
  for (const raw of text.trim().split('\n')) {
    const line = raw.trimEnd();
    if (!line) continue;
    const tab = line.indexOf('\t'); // du separa com TAB
    const idx = tab !== -1 ? tab : line.indexOf(' ');
    if (idx === -1) continue;
    const bytes = parseInt(line.slice(0, idx), 10);
    const p = line.slice(idx + 1).trim();
    if (!Number.isFinite(bytes) || !p) continue;
    rows.push({ path: p, bytes });
  }
  return rows;
}

function baseName(p: string): string {
  const b = p.split('/').filter(Boolean).pop() ?? p;
  return b.length > 30 ? `${b.slice(0, 27)}...` : b;
}

function parseDf(text: string): DiskInfo[] {
  const rows: DiskInfo[] = [];
  for (const line of text.trim().split('\n')) {
    const m = line.trim().match(/^(\S+)\s+(\S+)\s+(\S+)\s+(\d+)%$/);
    if (m) rows.push({ mount: m[1], size: m[2], used: m[3], percent: parseInt(m[4], 10) });
  }
  return rows;
}

function parseRaid(mdstat: string): RaidArrayInfo[] {
  const arrays: RaidArrayInfo[] = [];
  let cur: { name: string; active: boolean; lines: string[] } | null = null;
  const finish = (): void => {
    if (!cur) return;
    const stateLine = cur.lines.find(l => /\[[U_]+\]/.test(l));
    arrays.push({
      name: cur.name,
      active: cur.active,
      state: stateLine?.match(/\[([U_]+)\]/)?.[1] ?? null,
    });
  };
  for (const line of mdstat.split('\n')) {
    const m = line.match(/^(md\d+)\s*:\s*(\S+)/);
    if (m) {
      finish();
      cur = { name: m[1], active: m[2] === 'active', lines: [] };
    } else if (cur) {
      cur.lines.push(line);
    }
  }
  finish();
  return arrays;
}

function diffBaseline(current: string[], baseline: readonly string[]): { added: string[]; removed: string[] } {
  const cur = new Set(current);
  const base = new Set(baseline);
  return {
    added: [...cur].filter(x => !base.has(x)).sort(),
    removed: [...base].filter(x => !cur.has(x)).sort(),
  };
}

function fmtDiff(added: string[], removed: string[], expected: number): string {
  const parts = [...added.map(a => `+${a}`), ...removed.map(r => `-${r}`)];
  if (parts.length === 0) return `sem diffs ✅ (${expected} entradas)`;
  const shown = parts.slice(0, DIFF_ITEM_CAP).join(' ');
  const more = parts.length > DIFF_ITEM_CAP ? ` (+${parts.length - DIFF_ITEM_CAP})` : '';
  return `⚠️ ${shown}${more}`;
}

// ── Worker ──────────────────────────────────────────────────────────────────
export class WeeklyAuditWorker {
  private static intervalId: NodeJS.Timeout | null = null;
  private static readonly CHECK_INTERVAL_MS = 60 * 1000;
  private static readonly DAY_BRT = 0; // domingo
  private static readonly HOUR_BRT = 9; // 09:00 America/Sao_Paulo = 12:00 UTC
  private static lastSentDate: string | null = null;

  static start(): void {
    if (this.intervalId) return;
    this.intervalId = setInterval(() => {
      this.checkAndSend().catch(err => logger.error({ err }, 'Weekly audit check error'));
    }, this.CHECK_INTERVAL_MS);
    logger.info('Weekly audit worker started (sends Sundays 09:00 BRT / 12:00 UTC)');
  }

  static async stop(): Promise<void> {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    logger.info('Weekly audit worker stopped');
  }

  private static async checkAndSend(): Promise<void> {
    const brt = new Date(new Date().toLocaleString('en-US', { timeZone: 'America/Sao_Paulo' }));
    const dateKey = `${brt.getFullYear()}-${brt.getMonth() + 1}-${brt.getDate()}`;
    if (brt.getDay() === this.DAY_BRT && brt.getHours() >= this.HOUR_BRT && this.lastSentDate !== dateKey) {
      this.lastSentDate = dateKey;
      await this.sendReport();
    }
  }

  static async sendReport(options: WeeklyAuditOptions = {}): Promise<void> {
    const server = await ServerService.getByName(AUDIT_SERVER_NAME);
    if (!server) {
      logger.error({ server: AUDIT_SERVER_NAME }, 'Weekly audit: server not found in soc_servers');
      return;
    }
    const target = ServerService.toSSHTarget(server);

    const { body, warnings } = await this.buildReport(target);
    const finalBody = options.test ? `🧪 <b>[TESTE]</b> (disparo manual)\n${body}` : body;
    const title = options.test
      ? `[teste] Auditoria Semanal — ${AUDIT_SERVER_NAME}`
      : `Auditoria Semanal — ${AUDIT_SERVER_NAME}`;

    if (options.dryRun) {
      // eslint-disable-next-line no-console
      console.log(`--- ${title} ---\n${finalBody}\n--- (${finalBody.length} chars) ---`);
      return;
    }

    await NotifierManager.notify({
      title,
      body: finalBody,
      severity: warnings > 0 ? 'medium' : 'low',
      metadata: { type: 'weekly-audit' },
    });
    logger.info({ warnings, test: !!options.test }, 'Weekly audit sent');
  }

  private static async run(target: SSHTarget, cmd: string): Promise<string | null> {
    const result = await SSHCollector.run(target, cmd, SSH_TIMEOUT_MS);
    if (!result.success) {
      logger.warn({ server: target.name, error: result.error }, 'Weekly audit: SSH command failed');
      return null;
    }
    return result.stdout;
  }

  static async buildReport(target: SSHTarget): Promise<{ body: string; warnings: number }> {
    const lines: string[] = [];

    const stamp = new Date().toLocaleString('pt-BR', {
      timeZone: 'America/Sao_Paulo',
      weekday: 'long',
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    });
    lines.push(`📅 ${stamp} (BRT) · somente-leitura`);

    let failures = 0;
    const totalRuns = 6;

    // 1) Listagens / e /opt vs baseline
    lines.push('', '🧭 <b>Novidades vs baseline</b>');
    const listingsOut = await this.run(target, CMD_LISTINGS);
    if (listingsOut === null) {
      failures++;
      lines.push(' • ⚠️ coleta falhou (/ e /opt)');
    } else {
      const [rootSeg, optSeg] = splitSegments(listingsOut, ['<<<OPT>>>']);
      const rootCur = rootSeg.split('\n').map(s => s.trim()).filter(Boolean);
      const optCur = optSeg.split('\n').map(s => s.trim()).filter(Boolean);
      const rd = diffBaseline(rootCur, ROOT_BASELINE);
      const od = diffBaseline(optCur, OPT_BASELINE);
      lines.push(` • /: ${esc(fmtDiff(rd.added, rd.removed, ROOT_BASELINE.length))}`);
      lines.push(` • /opt: ${esc(fmtDiff(od.added, od.removed, OPT_BASELINE.length))}`);
    }

    // 2) /root — tamanho e maiores consumidores
    let dockerDuBytes: number | null = null;
    let backupDuBytes: number | null = null;
    const usageOut = await this.run(target, CMD_USAGE);
    if (usageOut === null) {
      failures++;
      lines.push('', '🏠 <b>/root</b>: ⚠️ coleta falhou');
    } else {
      const [rootSizeSeg, topSeg, dockerDuSeg, backupDuSeg] = splitSegments(usageOut, [
        '<<<SEP_USAGE>>>', '<<<SEP_USAGE>>>', '<<<SEP_USAGE>>>',
      ]);
      const rootBytes = parseDuBytes(rootSizeSeg);
      const top = parseDuTop(topSeg).slice(0, 6);
      dockerDuBytes = parseDuBytes(dockerDuSeg);
      backupDuBytes = parseDuBytes(backupDuSeg);
      const overLimit = rootBytes !== null && rootBytes > ROOT_WARN_BYTES;
      lines.push(
        '',
        `🏠 <b>/root</b>: ${rootBytes !== null ? fmtBytes(rootBytes) : '?'}` +
          (overLimit ? ` ⚠️ acima do limiar (${fmtBytes(ROOT_WARN_BYTES)} — investigar crescimento)` : ' ✅'),
      );
      if (top.length > 0) {
        lines.push(` • top: ${esc(top.map(t => `${baseName(t.path)} ${fmtBytes(t.bytes)}`).join(' · '))}`);
      }
    }

    // 3) /var/backups — deve conter só padrão do sistema
    const varbackupsOut = await this.run(target, CMD_VARBACKUPS);
    if (varbackupsOut === null) {
      failures++;
      lines.push('', '🗄️ /var/backups: ⚠️ coleta falhou');
    } else {
      const entries = varbackupsOut.split('\n').map(s => s.trim()).filter(Boolean);
      const system = entries.filter(e => VARBACKUPS_SYSTEM_PATTERN.test(e));
      const foreign = entries.filter(e => !VARBACKUPS_SYSTEM_PATTERN.test(e));
      const bad = foreign.length > 0;
      lines.push(
        '',
        `🗄️ <b>/var/backups</b>: ${system.length} itens do sistema ${bad ? '' : '✅'}` +
          (bad ? ` · ⚠️ fora do padrão: ${esc(foreign.join(', '))}` : ''),
      );
    }

    // 4) Backups esperados × chegados
    lines.push('', '💾 <b>Backups</b>');
    const backupsOut = await this.run(target, CMD_BACKUPS);
    if (backupsOut === null) {
      failures++;
      lines.push(' • ⚠️ coleta falhou');
    } else {
      const [dailySeg, fullSeg, stagingSeg, verboSeg, babaSbSeg, mountSeg] = splitSegments(backupsOut, [MARK, MARK, MARK, MARK, MARK]);

      const daily = parseBackupLine(dailySeg);
      if (!daily) {
        lines.push(' • ⚠️ babarato local: arquivo não encontrado em /backup/daily');
      } else {
        const ok = daily.ageHours <= BABARATO_MAX_AGE_HOURS && daily.sizeBytes >= BABARATO_MIN_SIZE_BYTES;
        lines.push(
          ` • babarato local: <code>${esc(daily.name)}</code> (${fmtAgeHours(daily.ageHours)}, ${fmtBytes(daily.sizeBytes)}) ${ok ? '✅' : '⚠️ fora do esperado (<26h, >10M)'}`,
        );
      }

      const full = parseBackupLine(fullSeg);
      if (!full) {
        lines.push(' • ⚠️ babarato full mensal: nenhum arquivo em /backup/monthly');
      } else {
        const ok = full.ageHours <= BABARATO_FULL_MAX_AGE_DAYS * 24;
        lines.push(
          ` • babarato full mensal: <code>${esc(full.name)}</code> (${fmtAgeHours(full.ageHours)}, ${fmtBytes(full.sizeBytes)}) ${ok ? '✅' : '⚠️ fora do esperado (<45d)'}`,
        );
      }

      const stagingEntries = stagingSeg.split('\n').map(s => s.trim()).filter(Boolean);
      lines.push(
        ` • staging verbo: ${stagingEntries.length === 0 ? 'vazio ✅' : `⚠️ ${esc(stagingEntries.join(', '))}`}`,
      );

      const verbo = parseBackupLine(verboSeg);
      if (!verbo) {
        lines.push(' • ⚠️ verbo offsite: arquivo não encontrado em bancoVerboConnect');
      } else {
        const ok = verbo.ageHours <= VERBO_MAX_AGE_HOURS && verbo.sizeBytes >= VERBO_MIN_SIZE_BYTES;
        lines.push(
          ` • verbo offsite: <code>${esc(verbo.name)}</code> (${fmtAgeHours(verbo.ageHours)}, ${fmtBytes(verbo.sizeBytes)}) ${ok ? '✅' : '⚠️ fora do esperado (<26h, >1M)'}`,
        );
      }

      const babaSbAll = parseDuToplikeBackup(babaSbSeg);
      const babaSbPartials = babaSbAll.filter(f => f.name.endsWith('.partial'));
      const babaSbComplete = babaSbAll.filter(f => !f.name.endsWith('.partial'));
      if (babaSbComplete.length === 0) {
        lines.push(
          ` • ⚠️ babarato offsite: nenhum arquivo completo em babarato-backups` +
            (babaSbPartials.length > 0 ? ` (${babaSbPartials.length} .partial em trânsito)` : ''),
        );
      } else {
        const latest = babaSbComplete[0];
        const stale = latest.ageHours > BABARATO_OFFSITE_MAX_AGE_HOURS;
        const transit = babaSbPartials.length > 0 ? ` · ${babaSbPartials.length} .partial em trânsito` : '';
        lines.push(
          ` • babarato offsite: <code>${esc(latest.name)}</code> (${fmtAgeHours(latest.ageHours)}, ${fmtBytes(latest.sizeBytes)}) ${stale ? '⚠️ antigo (>8d)' : '✅'}${transit}`,
        );
      }

      const mountSource = mountSeg.trim().split('\n')[0]?.trim() ?? '';
      const mounted = mountSource !== '' && mountSource !== 'NOTMOUNTED';
      lines.push(` • Storage Box: ${mounted ? 'montado ✅' : '⚠️ NÃO montado em /var/media/jellyfin'}`);
    }

    // 5) Docker
    const dockerOut = await this.run(target, CMD_DOCKER);
    if (dockerOut === null) {
      failures++;
      lines.push('', '🐳 Docker: ⚠️ coleta falhou');
    } else {
      const [dfSeg, unhealthySeg, restartingSeg, countSeg] = splitSegments(dockerOut, [
        '<<<SEP_DOCKER>>>', '<<<SEP_DOCKER>>>', '<<<SEP_DOCKER>>>',
      ]);
      const unhealthy = unhealthySeg.split('\n').map(s => s.trim()).filter(Boolean);
      const restarting = restartingSeg.split('\n').map(s => s.trim()).filter(Boolean);
      const count = parseInt(countSeg.trim(), 10);
      lines.push(
        '',
        `🐳 <b>Docker</b>: ${Number.isFinite(count) ? count : '?'} rodando` +
          ` · unhealthy ${unhealthy.length === 0 ? '0 ✅' : `${unhealthy.length} ⚠️ (${esc(unhealthy.join(', '))})`}` +
          ` · restarting ${restarting.length === 0 ? '0 ✅' : `${restarting.length} ⚠️ (${esc(restarting.join(', '))})`}`,
      );
      const dfLine = (label: string): string | null => {
        for (const line of dfSeg.split('\n')) {
          const f = line.trim().split(/\s+/);
          if (f.length >= 4 && f[0] === label) return `${f[3]}${f[4] ? ` (${f[4]} rec)` : ''}`;
          if (f.length >= 5 && f[0] === label.split(' ')[0] && f[1] === label.split(' ')[1]) {
            return `${f[4]}${f[5] ? ` (${f[5]} rec)` : ''}`;
          }
        }
        return null;
      };
      const images = dfLine('Images');
      const volumes = dfLine('Local Volumes');
      const build = dfLine('Build Cache');
      const bits = [
        images ? `images ${images}` : null,
        volumes ? `volumes ${volumes}` : null,
        build ? `build cache ${build}` : null,
      ].filter((x): x is string => !!x);
      if (bits.length > 0) lines.push(` • ${esc(bits.join(' · '))}`);
    }

    // 6) Saúde (RAID / systemd / reboot / df)
    const healthOut = await this.run(target, CMD_HEALTH);
    if (healthOut === null) {
      failures++;
      lines.push('', '🩺 Saúde: ⚠️ coleta falhou');
    } else {
      const [mdSeg, failedSeg, rebootSeg, dfSeg2] = splitSegments(healthOut, [
        '<<<SEP_HEALTH>>>', '<<<SEP_HEALTH>>>', '<<<SEP_HEALTH>>>',
      ]);

      const raid = parseRaid(mdSeg);
      if (raid.length === 0) {
        lines.push('', '🩺 Saúde: ⚠️ não foi possível ler /proc/mdstat');
      } else {
        const raidOk = raid.every(a => a.active && a.state !== null && !a.state.includes('_'));
        lines.push(
          '',
          `🩺 <b>Saúde</b>: RAID ${esc(raid.map(a => `${a.name} [${a.state ?? '??'}]`).join(' · '))} ${raidOk ? '✅' : '⚠️'}`,
        );
      }

      const failed = failedSeg.split('\n').map(s => s.trim()).filter(Boolean);
      lines.push(
        ` • systemd falhas: ${failed.length === 0 ? '0 ✅' : `⚠️ ${esc(failed.slice(0, 3).join(', '))}`}`,
      );

      const reboot = rebootSeg.trim().split('\n')[0]?.trim() ?? '';
      if (reboot.startsWith('PENDING')) {
        lines.push(` • reboot-required: ⚠️ pendente desde ${esc(reboot.replace('PENDING', '').trim())}`);
      } else {
        lines.push(' • reboot-required: nenhum ✅');
      }

      const disks = parseDf(dfSeg2);
      if (disks.length > 0) {
        // dedup: se Storage Box não estiver montado, df repete o mount /var
        const seen = new Set<string>();
        const uniq = disks.filter(d => (seen.has(d.mount) ? false : (seen.add(d.mount), true)));
        const diskText = uniq
          .map(d => `${d.mount === '/var/media/jellyfin' ? 'SB' : d.mount} ${d.percent}%`)
          .join(' · ');
        const hot = uniq.filter(d => d.percent >= DISK_WARN_PERCENT);
        lines.push(`💽 Discos: ${esc(diskText)}${hot.length > 0 ? ` ⚠️ (>=${DISK_WARN_PERCENT}%)` : ''}`);
        lines.push(
          ` • du: /var/lib/docker ${dockerDuBytes !== null ? fmtBytes(dockerDuBytes) : '?'}` +
            ` · /backup ${backupDuBytes !== null ? fmtBytes(backupDuBytes) : '?'}`,
        );
      }
    }

    lines.push('', '🔎 baseline: weekly-audit.worker.ts · sem escrita/prune/restart');

    // Falha total de coleta → mensagem curta e explícita
    if (failures >= totalRuns) {
      return {
        body: `⚠️ <b>Auditoria semanal:</b> não foi possível coletar do host <code>${esc(target.name)}</code> (SSH falhou em todas as coletas). Verificar conectividade.`,
        warnings: 99,
      };
    }

    let body = lines.filter(l => !l.startsWith('<!--')).join('\n');
    if (body.length > MAX_MESSAGE_CHARS) {
      const cut = body.lastIndexOf('\n', MAX_MESSAGE_CHARS - 30);
      body = `${body.slice(0, cut > 0 ? cut : MAX_MESSAGE_CHARS - 30)}\n⚠️ (mensagem truncada)`;
    }
    const warnings = (body.match(/⚠️/g) ?? []).length;
    return { body, warnings };
  }
}

// Parser para a lista (até 10 linhas) de arquivos do babarato offsite.
function parseDuToplikeBackup(text: string): BackupFileInfo[] {
  const out: BackupFileInfo[] = [];
  for (const raw of text.trim().split('\n')) {
    const info = parseBackupLine(raw);
    if (info) out.push(info);
  }
  return out;
}
