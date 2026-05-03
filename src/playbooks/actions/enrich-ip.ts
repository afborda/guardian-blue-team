import { ThreatIntelManager } from '../../threat-intel/manager.js';
import type { PlaybookContext } from '../engine.js';

export async function enrichIP(ctx: PlaybookContext): Promise<{ success: boolean; message: string }> {
  if (!ctx.sourceIp) {
    return { success: false, message: 'No source IP to enrich' };
  }

  const report = await ThreatIntelManager.lookupIP(ctx.sourceIp);
  if (!report) {
    ctx.variables['score'] = 0;
    return { success: true, message: 'No threat intel available, score=0' };
  }

  ctx.variables['score'] = report.score;
  ctx.variables['totalReports'] = report.totalReports;
  ctx.variables['country'] = report.country;
  ctx.variables['isp'] = report.isp;

  return { success: true, message: `Score: ${report.score}/100 (${report.country}, ${report.totalReports} reports)` };
}
