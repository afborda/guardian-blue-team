import { SSHCollector, type SSHTarget } from '../collectors/ssh-collector.js';
import { ServerService } from '../services/server.service.js';
import { logger } from '../utils/logger.js';

export interface InstalledPackage {
  name: string;
  version: string;
  ecosystem: 'Debian' | 'Alpine' | 'npm';
}

interface CacheEntry {
  packages: InstalledPackage[];
  updatedAt: number;
}

const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

export class InventoryCollector {
  private static cache = new Map<number, CacheEntry>();

  static async getServerInventory(serverId: number): Promise<InstalledPackage[]> {
    const cached = this.cache.get(serverId);
    if (cached && Date.now() - cached.updatedAt < CACHE_TTL_MS) {
      return cached.packages;
    }

    const server = await ServerService.getById(serverId);
    if (!server) return [];

    const target = ServerService.toSSHTarget(server);
    const packages = await this.collectPackages(target);

    this.cache.set(serverId, { packages, updatedAt: Date.now() });
    logger.debug({ serverId, count: packages.length }, 'Inventory collected');
    return packages;
  }

  static async getAllInventories(): Promise<Map<number, InstalledPackage[]>> {
    const servers = await ServerService.getEnabled();
    const result = new Map<number, InstalledPackage[]>();

    const settled = await Promise.allSettled(
      servers.map(async (server) => {
        const packages = await this.getServerInventory(server.id);
        return { id: server.id, packages };
      })
    );

    for (const entry of settled) {
      if (entry.status === 'fulfilled') {
        result.set(entry.value.id, entry.value.packages);
      }
    }

    return result;
  }

  static invalidateCache(serverId?: number): void {
    if (serverId) {
      this.cache.delete(serverId);
    } else {
      this.cache.clear();
    }
  }

  private static async collectPackages(target: SSHTarget): Promise<InstalledPackage[]> {
    const result = await SSHCollector.run(
      target,
      "dpkg-query -W -f '${Package} ${Version}\\n' 2>/dev/null | head -2000",
      30_000
    );

    if (!result.success || !result.stdout.trim()) {
      return this.collectAlpinePackages(target);
    }

    const packages: InstalledPackage[] = [];
    for (const line of result.stdout.trim().split('\n')) {
      const spaceIdx = line.indexOf(' ');
      if (spaceIdx === -1) continue;
      const name = line.slice(0, spaceIdx);
      const version = line.slice(spaceIdx + 1);
      if (name && version) {
        packages.push({ name, version, ecosystem: 'Debian' });
      }
    }
    return packages;
  }

  private static async collectAlpinePackages(target: SSHTarget): Promise<InstalledPackage[]> {
    const result = await SSHCollector.run(
      target,
      "apk list --installed 2>/dev/null | head -2000",
      20_000
    );

    if (!result.success || !result.stdout.trim()) return [];

    const packages: InstalledPackage[] = [];
    for (const line of result.stdout.trim().split('\n')) {
      const match = line.match(/^(\S+)-(\d\S*)\s/);
      if (match) {
        packages.push({ name: match[1], version: match[2], ecosystem: 'Alpine' });
      }
    }
    return packages;
  }
}
