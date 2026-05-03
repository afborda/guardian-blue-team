import { type Request, type Response, type NextFunction } from 'express';

const DASHBOARD_TOKEN = process.env.DASHBOARD_TOKEN || null;

export function dashboardAuth(req: Request, res: Response, next: NextFunction): void {
  if (!DASHBOARD_TOKEN) {
    res.status(503).json({ error: 'Dashboard disabled (DASHBOARD_TOKEN not set)' });
    return;
  }

  const token = req.query.token as string
    || req.headers.authorization?.replace('Bearer ', '');

  if (token !== DASHBOARD_TOKEN) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  next();
}
