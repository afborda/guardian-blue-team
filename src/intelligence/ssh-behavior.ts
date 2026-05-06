import { db, dbDate } from '../database/connection.js';
import { securityEvents, behaviorProfiles } from '../database/schema.js';
import { eq, and, gte, inArray } from 'drizzle-orm';
import { logger } from '../utils/logger.js';

export interface SSHUserProfile {
  userName: string;
  loginHours: Record<number, number>;
  knownIPs: string[];
  knownFingerprints: string[];
  avgLoginsPerDay: number;
  totalLogins: number;
  lastSeen: string;
  firstSeen: string;
}

export interface LoginAnomalyScore {
  score: number;
  factors: string[];
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

export class SSHBehaviorProfiler {
  private static readonly PROFILE_TYPE = 'ssh_user';
  private static readonly MAX_KNOWN_IPS = 20;
  private static readonly MAX_KNOWN_FPS = 10;

  static async buildProfiles(serverId: number): Promise<number> {
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

    const logins = await db.select({
      userName: securityEvents.userName,
      sourceIp: securityEvents.sourceIp,
      timestamp: securityEvents.timestamp,
      metadata: securityEvents.metadata,
    })
      .from(securityEvents)
      .where(and(
        eq(securityEvents.serverId, serverId),
        inArray(securityEvents.eventType, ['ssh_login_success', 'ssh_key_login']),
        gte(securityEvents.timestamp, dbDate(thirtyDaysAgo)),
      ));

    if (logins.length === 0) return 0;

    const byUser = new Map<string, typeof logins>();
    for (const login of logins) {
      const user = login.userName || 'unknown';
      const existing = byUser.get(user) || [];
      existing.push(login);
      byUser.set(user, existing);
    }

    let profileCount = 0;
    for (const [userName, userLogins] of byUser) {
      const profile = this.computeProfile(userName, userLogins);
      await this.upsertProfile(serverId, userName, profile, userLogins.length);
      profileCount++;
    }

    logger.debug({ serverId, profileCount, totalLogins: logins.length }, 'SSH behavior profiles updated');
    return profileCount;
  }

  static async scoreLogin(serverId: number, userName: string, sourceIp: string, hour: number, fingerprint?: string): Promise<LoginAnomalyScore> {
    const existing = await this.getProfile(serverId, userName);

    if (!existing) {
      return { score: 0.4, factors: ['first_login_ever'], severity: 'medium' };
    }

    const profile = existing.profile as unknown as SSHUserProfile;
    let score = 0;
    const factors: string[] = [];

    // Factor 1: Unknown IP (0-0.3)
    if (!profile.knownIPs.includes(sourceIp)) {
      score += 0.3;
      factors.push('unknown_ip');
    }

    // Factor 2: Unusual hour (0-0.3)
    const hourCount = profile.loginHours[hour] ?? 0;
    const totalHourLogins = Object.values(profile.loginHours).reduce((a, b) => a + b, 0);
    const hourFrequency = totalHourLogins > 0 ? hourCount / totalHourLogins : 0;
    if (hourFrequency < 0.05) {
      score += 0.3;
      factors.push(`unusual_hour_${hour}`);
    } else if (hourFrequency < 0.1) {
      score += 0.15;
      factors.push(`rare_hour_${hour}`);
    }

    // Factor 3: Unknown fingerprint (0-0.2)
    if (fingerprint && profile.knownFingerprints.length > 0 && !profile.knownFingerprints.includes(fingerprint)) {
      score += 0.2;
      factors.push('unknown_fingerprint');
    }

    // Factor 4: High login velocity (0-0.2)
    if (profile.avgLoginsPerDay > 0) {
      const daysSinceFirst = Math.max(1, (Date.now() - new Date(profile.firstSeen).getTime()) / 86_400_000);
      const currentRate = profile.totalLogins / daysSinceFirst;
      if (currentRate > profile.avgLoginsPerDay * 3) {
        score += 0.2;
        factors.push('high_velocity');
      }
    }

    const severity = this.scoreSeverity(score);
    return { score: Math.min(score, 1), factors, severity };
  }

  private static computeProfile(userName: string, logins: Array<{ sourceIp: string | null; timestamp: Date; metadata: unknown }>): SSHUserProfile {
    const loginHours: Record<number, number> = {};
    const ipCounts = new Map<string, number>();
    const fingerprints = new Set<string>();

    let firstSeen = logins[0].timestamp;
    let lastSeen = logins[0].timestamp;

    for (const login of logins) {
      const hour = login.timestamp.getHours();
      loginHours[hour] = (loginHours[hour] ?? 0) + 1;

      if (login.sourceIp) {
        ipCounts.set(login.sourceIp, (ipCounts.get(login.sourceIp) ?? 0) + 1);
      }

      const meta = login.metadata as Record<string, unknown> | null;
      if (meta?.fingerprint && typeof meta.fingerprint === 'string') {
        fingerprints.add(meta.fingerprint);
      }

      if (login.timestamp < firstSeen) firstSeen = login.timestamp;
      if (login.timestamp > lastSeen) lastSeen = login.timestamp;
    }

    const sortedIPs = [...ipCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, this.MAX_KNOWN_IPS).map(([ip]) => ip);
    const daySpan = Math.max(1, (lastSeen.getTime() - firstSeen.getTime()) / 86_400_000);

    return {
      userName,
      loginHours,
      knownIPs: sortedIPs,
      knownFingerprints: [...fingerprints].slice(0, this.MAX_KNOWN_FPS),
      avgLoginsPerDay: Math.round((logins.length / daySpan) * 100) / 100,
      totalLogins: logins.length,
      lastSeen: lastSeen.toISOString(),
      firstSeen: firstSeen.toISOString(),
    };
  }

  private static async upsertProfile(serverId: number, userName: string, profile: SSHUserProfile, sampleCount: number): Promise<void> {
    const existing = await db.select().from(behaviorProfiles)
      .where(and(
        eq(behaviorProfiles.serverId, serverId),
        eq(behaviorProfiles.profileType, this.PROFILE_TYPE),
        eq(behaviorProfiles.subjectId, userName),
      ))
      .then(rows => rows[0]);

    if (existing) {
      await db.update(behaviorProfiles)
        .set({
          profile: profile as unknown as Record<string, unknown>,
          sampleCount,
          lastUpdatedAt: new Date(),
        })
        .where(eq(behaviorProfiles.id, existing.id));
    } else {
      await db.insert(behaviorProfiles).values({
        serverId,
        profileType: this.PROFILE_TYPE,
        subjectId: userName,
        profile: profile as unknown as Record<string, unknown>,
        sampleCount,
      });
    }
  }

  private static async getProfile(serverId: number, userName: string) {
    const [row] = await db.select().from(behaviorProfiles)
      .where(and(
        eq(behaviorProfiles.serverId, serverId),
        eq(behaviorProfiles.profileType, this.PROFILE_TYPE),
        eq(behaviorProfiles.subjectId, userName),
      ));
    return row ?? null;
  }

  private static scoreSeverity(score: number): 'info' | 'low' | 'medium' | 'high' | 'critical' {
    if (score >= 0.85) return 'critical';
    if (score >= 0.7) return 'high';
    if (score >= 0.5) return 'medium';
    if (score >= 0.3) return 'low';
    return 'info';
  }
}
