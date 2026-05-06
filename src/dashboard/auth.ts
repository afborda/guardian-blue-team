import { type Request, type Response, type NextFunction } from 'express';
import { config } from '../config/environment.js';
import { safeCompare } from '../utils/sanitize.js';

export function dashboardAuth(req: Request, res: Response, next: NextFunction): void {
  if (!config.dashboard.token) {
    res.status(503).json({ error: 'Dashboard disabled — set DASHBOARD_TOKEN' });
    return;
  }

  const token = req.query.token as string
    || req.headers.authorization?.replace('Bearer ', '');

  if (!token || !safeCompare(token, config.dashboard.token)) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  next();
}
