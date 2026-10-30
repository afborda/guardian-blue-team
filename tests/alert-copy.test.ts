import { describe, expect, it } from 'vitest';
import { canonicalIp } from '../src/utils/ip-canonical.js';
import { formatBlockLost, shouldNotifyBlockLost, ufwDenyCommand, ufwVerifyCommand } from '../src/playbooks/actions/firewall-commands.js';
import { formatAnomalyAlert, formatBitRate, gateAnomaly } from '../src/intelligence/anomaly-copy.js';
import type { Anomaly } from '../src/intelligence/anomaly-detector.js';
import { threatAdvice } from '../src/telegram/threat-copy.js';
import { describeDiscoveryChanges, isLabelMigration } from '../src/discovery/baseline-diff.js';

function anomaly(partial: Partial<Anomaly> & Pick<Anomaly, 'metric' | 'currentValue' | 'expectedMean'>): Anomaly {
  return {
    serverId: 1,
    stdDev: 1,
    deviations: 6,
    severity: 'critical',
    method: 'stl',
    ...partial,
  };
}

describe('canonicalIp', () => {
  it('compresses the three IPv6 addresses UFW stores on hetzner-prod', () => {
    expect(canonicalIp('2a01:ecc0:0040:097c:0000:0000:0000:0002')).toBe('2a01:ecc0:40:97c::2');
    expect(canonicalIp('2620:0096:a005:0000:0000:0000:0000:0259')).toBe('2620:96:a005::259');
    expect(canonicalIp('2a01:ecc0:0040:03be:0000:0000:0000:0002')).toBe('2a01:ecc0:40:3be::2');
  });

  it('leaves IPv4 untouched and keeps an already compressed address', () => {
    expect(canonicalIp('103.106.105.103')).toBe('103.106.105.103');
    expect(canonicalIp('2a01:ecc0:40:97c::2')).toBe('2a01:ecc0:40:97c::2');
  });

  it('compresses the first equal-length zero run', () => {
    expect(canonicalIp('2001:0000:0000:0000:0001:0000:0000:0001')).toBe('2001::1:0:0:1');
  });
});

describe('firewall commands', () => {
  it('inserts the deny at position 1 using the compressed address', () => {
    const cmd = ufwDenyCommand('2a01:ecc0:0040:097c:0000:0000:0000:0002', 'guardian-block', 1781482301366);
    expect(cmd).toBe("sudo ufw insert 1 deny from 2a01:ecc0:40:97c::2 comment 'guardian-block-1781482301366'");
  });

  it('looks up the address UFW prints', () => {
    expect(ufwVerifyCommand('2a01:ecc0:0040:097c:0000:0000:0000:0002'))
      .toBe("sudo ufw status | grep -q '2a01:ecc0:40:97c::2'");
  });

  it('pages a lost block once, then weekly', () => {
    expect(shouldNotifyBlockLost(1)).toBe(false);
    expect(shouldNotifyBlockLost(2)).toBe(true);
    expect(shouldNotifyBlockLost(3)).toBe(false);
    expect(shouldNotifyBlockLost(28)).toBe(true);
    expect(shouldNotifyBlockLost(428)).toBe(false);
  });

  it('explains a failed check without calling it an intrusion', () => {
    const text = formatBlockLost('hetzner-prod', '2a01:ecc0:40:97c::2', 428, '2026-09-30T11:05:56Z');
    expect(text.title).toContain('hetzner-prod');
    expect(text.body).toContain('não é invasão');
    expect(text.body).not.toContain('flushed');
  });
});

describe('anomaly copy', () => {
  it('does not page a healthy CPU or a quiet network', () => {
    expect(gateAnomaly(anomaly({ metric: 'load_ratio', currentValue: 0.4, expectedMean: 0.15 }))).toBeNull();
    expect(gateAnomaly(anomaly({ metric: 'network_rx_bps', currentValue: 15691, expectedMean: 6_691_603 }))).toBeNull();
    expect(gateAnomaly(anomaly({ metric: 'network_tx_bps', currentValue: 21359, expectedMean: 577642 }))).toBeNull();
    expect(gateAnomaly(anomaly({ metric: 'network_rx_bps', currentValue: 1_183_650, expectedMean: 53916 }))).toBeNull();
  });

  it('still pages a full CPU and a real flood', () => {
    expect(gateAnomaly(anomaly({ metric: 'load_ratio', currentValue: 0.92, expectedMean: 0.15 }))).not.toBeNull();
    expect(gateAnomaly(anomaly({ metric: 'network_rx_bps', currentValue: 20_000_000, expectedMean: 500_000 }))).not.toBeNull();
  });

  it('speaks in MB/s and says what to do', () => {
    expect(formatBitRate(15_691)).toBe('16 KB/s');
    expect(formatBitRate(6_691_603)).toBe('6,7 MB/s');
    const text = formatAnomalyAlert('hetzner-prod', anomaly({ metric: 'load_ratio', currentValue: 0.92, expectedMean: 0.15 }));
    expect(text.body).toContain('92%');
    expect(text.body).not.toMatch(/z-score|desvio|σ/);
    expect(text.body).toContain('Não é, sozinho, sinal de invasão');
  });
});

describe('threat advice', () => {
  it('does not tell the operator to block an IP that is already blocked', () => {
    const lines = threatAdvice({
      score: 100,
      totalReports: 119,
      eventCount: 17,
      alreadyBlocked: true,
      firewallEvents: 17,
    });
    expect(lines.join('\n')).toContain('JÁ ESTÁ BLOQUEADO');
    expect(lines.join('\n')).not.toContain('/block');
  });

  it('treats firewall logs of an unblocked IP as closed-port noise when reputation is moderate', () => {
    const lines = threatAdvice({
      score: 40,
      totalReports: 2,
      eventCount: 15,
      alreadyBlocked: false,
      firewallEvents: 15,
    });
    expect(lines.join('\n')).toContain('PORTA FECHADA');
  });
});

describe('discovery diff', () => {
  it('treats the model label list as a migration, not an outage', () => {
    const previous = ['docker', 'traefik', 'guardian-api', 'guardian-db', 'fail2ban', 'ufw'];
    const containers = ['guardian', 'guardian-db', 'traefik', 'ninho-backend'];
    expect(isLabelMigration(previous, containers)).toBe(true);
  });

  it('describes a real container change in plain language', () => {
    const lines = describeDiscoveryChanges(
      { services: ['guardian', 'traefik'], ports: [80, 443, 49222] },
      { services: ['guardian', 'traefik', 'evil'], ports: [80, 443, 49222, 8080] },
    );
    expect(lines).toContain('Portas novas abertas para a internet: 8080');
    expect(lines).toContain('Containers novos: evil');
  });
});
