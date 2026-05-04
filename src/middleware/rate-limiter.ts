import { type Request, type Response, type NextFunction } from 'express';

const ipHits = new Map<string, number[]>();
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;

setInterval(() => {
  const cutoff = Date.now() - 60_000;
  for (const [ip, hits] of ipHits) {
    const valid = hits.filter(t => t > cutoff);
    if (valid.length === 0) ipHits.delete(ip);
    else ipHits.set(ip, valid);
  }
}, CLEANUP_INTERVAL_MS);

export function rateLimiter(maxPerMinute = 60) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const ip = req.ip ?? req.socket.remoteAddress ?? 'unknown';
    const now = Date.now();
    const hits = (ipHits.get(ip) ?? []).filter(t => now - t < 60_000);
    hits.push(now);
    ipHits.set(ip, hits);

    if (hits.length > maxPerMinute) {
      res.status(429).json({ error: 'Too many requests' });
      return;
    }
    next();
  };
}
