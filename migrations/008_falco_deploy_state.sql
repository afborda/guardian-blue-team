-- Track when Falco was deployed via ServerReadinessService.installFalco().
-- NULL = not installed (or failed). Set on successful `docker run guardian-falco`.
ALTER TABLE soc_servers
  ADD COLUMN IF NOT EXISTS falco_installed_at TIMESTAMP NULL;
