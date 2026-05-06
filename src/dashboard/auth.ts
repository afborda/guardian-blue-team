import { type Request, type Response, type NextFunction } from 'express';
import { config } from '../config/environment.js';
import { safeCompare } from '../utils/sanitize.js';

export type DashboardRole = 'admin' | 'operator' | 'viewer';

declare global {
  namespace Express {
    interface Request {
      dashboardUser?: { username: string; role: DashboardRole };
    }
  }
}

export function dashboardAuth(req: Request, res: Response, next: NextFunction): void {
  if (!config.dashboard.token && config.dashboard.users.length === 0) {
    res.status(503).json({ error: 'Dashboard disabled — set DASHBOARD_TOKEN or DASHBOARD_USERS' });
    return;
  }

  const token = req.query.token as string
    || req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  if (config.dashboard.users.length > 0) {
    const user = config.dashboard.users.find(u => safeCompare(token, u.token));
    if (user) {
      req.dashboardUser = { username: user.username, role: user.role };
      next();
      return;
    }
  }

  if (config.dashboard.token && safeCompare(token, config.dashboard.token)) {
    req.dashboardUser = { username: 'admin', role: 'admin' };
    next();
    return;
  }

  res.status(401).json({ error: 'Unauthorized' });
}

export function requireRole(...roles: DashboardRole[]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const userRole = req.dashboardUser?.role ?? 'viewer';
    if (!roles.includes(userRole)) {
      res.status(403).send('<p class="severity-critical">Forbidden — insufficient permissions</p>');
      return;
    }
    next();
  };
}
