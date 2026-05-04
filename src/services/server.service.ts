import { eq, count as dbCount } from 'drizzle-orm';
import { db, dbTrue, dbNow } from '../database/connection.js';
import { socServers } from '../database/schema.js';
import { SSHCollector, type SSHTarget } from '../collectors/ssh-collector.js';
import { logger } from '../utils/logger.js';

export interface ServerInfo {
  id: number;
  name: string;
  host: string;
  sshPort: number;
  sshUser: string;
  sshKeyPath: string | null;
  tags: string[];
  enabled: boolean;
  lastSeenAt: Date | null;
}

export class ServerService {
  static async getAll(): Promise<ServerInfo[]> {
    const rows = await db.select().from(socServers);
    return rows.map(r => ({
      id: r.id,
      name: r.name,
      host: r.host,
      sshPort: r.sshPort,
      sshUser: r.sshUser,
      sshKeyPath: r.sshKeyPath,
      tags: (r.tags ?? []) as string[],
      enabled: r.enabled,
      lastSeenAt: r.lastSeenAt,
    }));
  }

  static async getEnabled(): Promise<ServerInfo[]> {
    const rows = await db.select().from(socServers).where(eq(socServers.enabled, dbTrue));
    return rows.map(r => ({
      id: r.id,
      name: r.name,
      host: r.host,
      sshPort: r.sshPort,
      sshUser: r.sshUser,
      sshKeyPath: r.sshKeyPath,
      tags: (r.tags ?? []) as string[],
      enabled: r.enabled,
      lastSeenAt: r.lastSeenAt,
    }));
  }

  static async getByName(name: string): Promise<ServerInfo | null> {
    const [row] = await db.select().from(socServers).where(eq(socServers.name, name));
    if (!row) return null;
    return {
      id: row.id,
      name: row.name,
      host: row.host,
      sshPort: row.sshPort,
      sshUser: row.sshUser,
      sshKeyPath: row.sshKeyPath,
      tags: (row.tags ?? []) as string[],
      enabled: row.enabled,
      lastSeenAt: row.lastSeenAt,
    };
  }

  static async getById(id: number): Promise<ServerInfo | null> {
    const [row] = await db.select().from(socServers).where(eq(socServers.id, id));
    if (!row) return null;
    return {
      id: row.id,
      name: row.name,
      host: row.host,
      sshPort: row.sshPort,
      sshUser: row.sshUser,
      sshKeyPath: row.sshKeyPath,
      tags: (row.tags ?? []) as string[],
      enabled: row.enabled,
      lastSeenAt: row.lastSeenAt,
    };
  }

  static async add(data: {
    name: string;
    host: string;
    sshPort?: number;
    sshUser?: string;
    sshKeyPath?: string;
    tags?: string[];
  }): Promise<ServerInfo> {
    const [{ cnt }] = await db.select({ cnt: dbCount() }).from(socServers);
    if (cnt >= 100) throw new Error('Max servers reached (100)');

    const [row] = await db.insert(socServers).values({
      name: data.name,
      host: data.host,
      sshPort: data.sshPort ?? 22,
      sshUser: data.sshUser ?? 'ubuntu',
      sshKeyPath: data.sshKeyPath ?? null,
      tags: data.tags ?? [],
    }).returning();

    return {
      id: row.id,
      name: row.name,
      host: row.host,
      sshPort: row.sshPort,
      sshUser: row.sshUser,
      sshKeyPath: row.sshKeyPath,
      tags: (row.tags ?? []) as string[],
      enabled: row.enabled,
      lastSeenAt: row.lastSeenAt,
    };
  }

  static async remove(name: string): Promise<boolean> {
    const result = await db.delete(socServers).where(eq(socServers.name, name)).returning();
    return result.length > 0;
  }

  static async setEnabled(name: string, enabled: boolean): Promise<boolean> {
    const result = await db
      .update(socServers)
      .set({ enabled })
      .where(eq(socServers.name, name))
      .returning();
    return result.length > 0;
  }

  static async updateLastSeen(id: number): Promise<void> {
    await db.update(socServers).set({ lastSeenAt: dbNow() }).where(eq(socServers.id, id));
  }

  static toSSHTarget(server: ServerInfo): SSHTarget {
    return {
      id: server.id,
      name: server.name,
      host: server.host,
      sshPort: server.sshPort,
      sshUser: server.sshUser,
      sshKeyPath: server.sshKeyPath,
    };
  }

  static async checkHealth(): Promise<Array<{ server: ServerInfo; reachable: boolean }>> {
    const servers = await this.getEnabled();
    const results = await Promise.all(
      servers.map(async server => {
        const target = this.toSSHTarget(server);
        const reachable = await SSHCollector.isReachable(target);
        if (reachable) {
          await this.updateLastSeen(server.id);
        }
        return { server, reachable };
      })
    );
    logger.info({ total: servers.length, reachable: results.filter(r => r.reachable).length }, 'Server health check');
    return results;
  }
}
