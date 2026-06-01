/**
 * SSHCollector guardian-mode guard — testes de integração.
 *
 * Cobertura:
 * 1. installMode='legacy' (ou null): comportamento atual intacto
 * 2. installMode='guardian' + comando templatável: passa direto pro SSH
 * 3. installMode='guardian' + comando NÃO templatável: skip+warn, retorna
 *    error='GUARDIAN_NO_TEMPLATE' SEM tocar SSH (rede preservada)
 *
 * Estratégia: mocka só a primitiva `node:child_process` (camada externa)
 * pra detectar se o SSH foi chamado ou não. NÃO mocka o módulo SSHCollector
 * inteiro — esse é o ponto: validar a lógica real do guard.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const sshSpawnMock = vi.fn();

vi.mock('node:child_process', () => ({
  // util.promisify usa callback-style; o spy aqui detecta se a chamada SSH
  // chegou a ser disparada e retorna um stdout fake pra promisify resolver.
  execFile: (
    cmd: string,
    args: string[],
    opts: unknown,
    cb: (err: Error | null, result?: { stdout: string; stderr: string }) => void,
  ) => {
    sshSpawnMock(cmd, args, opts);
    cb(null, { stdout: 'ok\n', stderr: '' });
  },
}));

vi.mock('../../src/utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import { SSHCollector, type SSHTarget } from '../../src/collectors/ssh-collector.js';
import { logger } from '../../src/utils/logger.js';

const baseTarget: SSHTarget = {
  id: 1,
  name: 'test-srv',
  host: '10.0.0.1',
  sshPort: 22,
  sshUser: 'guardian',
  sshKeyPath: null,
};

describe('SSHCollector.run — installMode guard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('installMode=legacy or undefined', () => {
    it('runs SSH for any command when installMode is undefined', async () => {
      const result = await SSHCollector.run(baseTarget, 'rm -rf /tmp/anything');
      expect(result.success).toBe(true);
      expect(sshSpawnMock).toHaveBeenCalledOnce();
      expect(logger.warn).not.toHaveBeenCalled();
    });

    it('runs SSH for any command when installMode is "legacy"', async () => {
      const target: SSHTarget = { ...baseTarget, installMode: 'legacy' };
      const result = await SSHCollector.run(target, 'whatever non-templatable garbage');
      expect(result.success).toBe(true);
      expect(sshSpawnMock).toHaveBeenCalledOnce();
    });

    it('runs SSH for any command when installMode is null (DB default)', async () => {
      const target: SSHTarget = { ...baseTarget, installMode: null };
      const result = await SSHCollector.run(target, 'foo bar baz');
      expect(result.success).toBe(true);
      expect(sshSpawnMock).toHaveBeenCalledOnce();
    });
  });

  describe('installMode=guardian + templatable command', () => {
    it('passes through to SSH when command matches a known template', async () => {
      const target: SSHTarget = { ...baseTarget, installMode: 'guardian' };
      const result = await SSHCollector.run(
        target,
        "sudo tail -n 100 /var/log/ufw.log 2>/dev/null || echo ''",
      );
      expect(result.success).toBe(true);
      expect(sshSpawnMock).toHaveBeenCalledOnce();
      expect(logger.warn).not.toHaveBeenCalled();
    });

    it('passes through reachability probe (echo ok)', async () => {
      const target: SSHTarget = { ...baseTarget, installMode: 'guardian' };
      const result = await SSHCollector.run(target, 'echo ok');
      expect(result.success).toBe(true);
      expect(sshSpawnMock).toHaveBeenCalledOnce();
    });
  });

  describe('installMode=guardian + non-templatable command', () => {
    it('skips SSH and returns GUARDIAN_NO_TEMPLATE when no template matches', async () => {
      const target: SSHTarget = { ...baseTarget, installMode: 'guardian' };
      const result = await SSHCollector.run(target, 'rm -rf /tmp/anything');

      expect(result.success).toBe(false);
      expect(result.error).toBe('GUARDIAN_NO_TEMPLATE');
      expect(result.stdout).toBe('');
      // Crítico: SSH NÃO foi chamado — economia de RTT e zero ruído no servidor.
      expect(sshSpawnMock).not.toHaveBeenCalled();
    });

    it('emits a warn log with server name + normalized command', async () => {
      const target: SSHTarget = { ...baseTarget, installMode: 'guardian' };
      await SSHCollector.run(target, 'cat /etc/passwd');

      expect(logger.warn).toHaveBeenCalledOnce();
      const [bindings, message] = vi.mocked(logger.warn).mock.calls[0];
      expect(bindings).toMatchObject({
        server: 'test-srv',
        normalized: 'cat /etc/passwd',
      });
      expect(message).toBe('guardian-mode skip: command not templatable');
    });

    it('returns durationMs even when skipping (telemetry hygiene)', async () => {
      const target: SSHTarget = { ...baseTarget, installMode: 'guardian' };
      const result = await SSHCollector.run(target, 'unknown command here');
      expect(result.durationMs).toBeTypeOf('number');
      expect(result.durationMs).toBeGreaterThanOrEqual(0);
    });
  });

  describe('runMulti also benefits from the guard (delegates to run)', () => {
    it('skips when joined && chain is non-templatable in guardian mode', async () => {
      const target: SSHTarget = { ...baseTarget, installMode: 'guardian' };
      const result = await SSHCollector.runMulti(target, [
        'arbitrary command 1',
        'arbitrary command 2',
      ]);
      expect(result.error).toBe('GUARDIAN_NO_TEMPLATE');
      expect(sshSpawnMock).not.toHaveBeenCalled();
    });

    it('passes through when chain matches a static && template', async () => {
      const target: SSHTarget = { ...baseTarget, installMode: 'guardian' };
      // Esse chain bate o template do system-collector (após fix de aspas).
      const result = await SSHCollector.runMulti(target, [
        'dmesg --time-format iso 2>/dev/null | tail -n 30',
        'echo "---SSEP---"',
        "journalctl -p err --since '5 min ago' --no-pager -o short-iso 2>/dev/null | tail -n 20",
        'echo "---SSEP---"',
        'systemctl list-units --failed --no-legend --no-pager 2>/dev/null',
      ]);
      expect(result.success).toBe(true);
      expect(sshSpawnMock).toHaveBeenCalledOnce();
    });
  });
});
