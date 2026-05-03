import { vi } from 'vitest';

vi.mock('../src/config/environment.js', () => ({
  config: {
    server: { port: 3334, nodeEnv: 'test' },
    database: { url: 'postgres://test:test@localhost:5432/test', automabothubUrl: 'postgres://test:test@localhost:5432/test' },
    automabothub: { enabled: false },
    telegram: { botToken: 'test-token', chatId: '12345', webhookSecret: undefined },
    ai: { geminiApiKey: null, geminiModel: 'test', ollamaUrl: 'http://localhost:11434', ollamaModel: 'test', ollamaChatModel: 'test' },
    resend: { apiKey: null, fromEmail: 'test@test.com' },
    abuse: { confidenceThreshold: 70 },
    health: { uptimeKumaPushUrl: null },
    hostSecurity: { sshHost: '127.0.0.1', sshPort: 49222, sshUser: 'ubuntu', sshKeyPath: null },
    threatIntel: { abuseIpDbKey: null, virusTotalKey: null },
  },
}));

vi.mock('../src/database/connection.js', () => ({
  db: {
    select: () => ({ from: () => ({ where: () => ({ then: (fn: Function) => fn([]) }) }) }),
    insert: () => ({ values: () => ({ returning: () => Promise.resolve([{ id: 1 }]) }) }),
    update: () => ({ set: () => ({ where: () => Promise.resolve() }) }),
  },
  automabothubDb: {
    select: () => ({ from: () => ({ where: () => ({ then: (fn: Function) => fn([]) }) }) }),
  },
}));

vi.mock('../src/utils/logger.js', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

global.fetch = vi.fn(() => Promise.resolve({ ok: true, json: () => Promise.resolve({}) })) as unknown as typeof fetch;
