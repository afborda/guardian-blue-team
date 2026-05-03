import { db } from '../../database/connection.js';
import { socIncidents } from '../../database/schema.js';
import { eq, and, gte } from 'drizzle-orm';
import type { PlaybookContext } from '../engine.js';

const REPEAT_LOOKBACK_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

export async function checkRepeatOffender(ctx: PlaybookContext): Promise<{ success: boolean; message: string }> {
  if (!ctx.sourceIp) {
    ctx.variables['repeatCount'] = 0;
    return { success: true, message: 'No source IP, repeatCount=0' };
  }

  const cutoff = new Date(Date.now() - REPEAT_LOOKBACK_MS);

  const incidents = await db.select().from(socIncidents)
    .where(and(
      eq(socIncidents.category, 'port_scan'),
      gte(socIncidents.createdAt, cutoff),
    ));

  const count = incidents.filter(r => {
    const ips = (r.sourceIps ?? []) as string[];
    return ips.includes(ctx.sourceIp!);
  }).length;

  ctx.variables['repeatCount'] = count;

  return { success: true, message: `IP ${ctx.sourceIp} has ${count} port scan incident(s) in last 7 days` };
}
