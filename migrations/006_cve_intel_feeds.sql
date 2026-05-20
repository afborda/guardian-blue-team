-- External CVE intelligence feeds (EPSS + CISA KEV) for vulnerability prioritization.
-- Both are global catalogs (not per-server) that enrich cve_alerts.

-- EPSS (Exploit Prediction Scoring System) — daily snapshot of exploit probability
-- per CVE in the next 30 days. Source: https://api.first.org/data/v1/epss
-- Snapshot only (current values). For trend, see cve_epss_history below.
CREATE TABLE IF NOT EXISTS cve_epss (
  cve_id         VARCHAR(20)  PRIMARY KEY,
  epss_score     NUMERIC(6,5) NOT NULL,                 -- 0.00000 to 1.00000
  percentile     NUMERIC(6,5) NOT NULL,                 -- relative rank
  fetched_at     TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS cve_epss_score_idx ON cve_epss (epss_score DESC);

-- 30-day rolling history for trend detection ("CVE jumped from 0.1 to 0.9 in 7d").
-- Snapshot every day, prune entries older than 30 days.
CREATE TABLE IF NOT EXISTS cve_epss_history (
  id             BIGINT       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cve_id         VARCHAR(20)  NOT NULL,
  epss_score     NUMERIC(6,5) NOT NULL,
  percentile     NUMERIC(6,5) NOT NULL,
  snapshot_date  DATE         NOT NULL,
  UNIQUE (cve_id, snapshot_date)
);

CREATE INDEX IF NOT EXISTS cve_epss_history_cve_date_idx ON cve_epss_history (cve_id, snapshot_date DESC);
CREATE INDEX IF NOT EXISTS cve_epss_history_date_idx ON cve_epss_history (snapshot_date);

-- CISA KEV (Known Exploited Vulnerabilities) — curated catalog of CVEs proven
-- exploited in the wild. Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
-- Boolean signal: presence in this table = active exploitation confirmed.
CREATE TABLE IF NOT EXISTS cve_kev (
  cve_id              VARCHAR(20)  PRIMARY KEY,
  vendor_project      VARCHAR(200),
  product             VARCHAR(200),
  vulnerability_name  VARCHAR(500),
  date_added          DATE         NOT NULL,
  short_description   TEXT,
  required_action     TEXT,
  due_date            DATE,
  ransomware_use      BOOLEAN      DEFAULT FALSE,
  notes               TEXT,
  cwes                TEXT,                             -- comma-separated CWE IDs
  fetched_at          TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS cve_kev_date_added_idx ON cve_kev (date_added DESC);
CREATE INDEX IF NOT EXISTS cve_kev_ransomware_idx ON cve_kev (ransomware_use) WHERE ransomware_use = TRUE;
