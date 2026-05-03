import pino from 'pino';
import { config } from '../config/environment.js';

export const logger = pino({
  level: config.server.nodeEnv === 'production' ? 'info' : 'debug',
  transport: config.server.nodeEnv !== 'production'
    ? { target: 'pino-pretty', options: { colorize: true } }
    : undefined,
});
