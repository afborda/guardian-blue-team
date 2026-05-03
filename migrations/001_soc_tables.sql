-- SOC Agent Tables
-- Run against the Guardian database

CREATE TABLE IF NOT EXISTS soc_servers (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) UNIQUE NOT NULL,
  host VARCHAR(255) NOT NULL,
  ssh_port INTEGER NOT NULL DEFAULT 22,
  ssh_user VARCHAR(100) NOT NULL DEFAULT 'ubuntu',
  ssh_key_path VARCHAR(500),
  tags JSONB DEFAULT '[]',
  enabled BOOLEAN NOT NULL DEFAULT true,
  last_seen_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS soc_incidents (
  id SERIAL PRIMARY KEY,
  title VARCHAR(500) NOT NULL,
  severity VARCHAR(20) NOT NULL,
  status VARCHAR(30) NOT NULL DEFAULT 'open',
  category VARCHAR(100),
  source_ips JSONB DEFAULT '[]',
  affected_servers JSONB DEFAULT '[]',
  event_count INTEGER NOT NULL DEFAULT 0,
  first_seen_at TIMESTAMP NOT NULL,
  last_seen_at TIMESTAMP NOT NULL,
  resolved_at TIMESTAMP,
  ai_summary TEXT,
  playbook_id VARCHAR(100),
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS soc_incidents_status_idx ON soc_incidents(status);
CREATE INDEX IF NOT EXISTS soc_incidents_severity_idx ON soc_incidents(severity);

CREATE TABLE IF NOT EXISTS security_events (
  id SERIAL PRIMARY KEY,
  server_id INTEGER NOT NULL REFERENCES soc_servers(id),
  timestamp TIMESTAMP NOT NULL,
  source VARCHAR(50) NOT NULL,
  category VARCHAR(50) NOT NULL,
  severity VARCHAR(20) NOT NULL DEFAULT 'info',
  event_type VARCHAR(100) NOT NULL,
  source_ip VARCHAR(45),
  destination_port INTEGER,
  user_name VARCHAR(255),
  process_name VARCHAR(255),
  raw_log TEXT,
  metadata JSONB,
  enrichment JSONB,
  incident_id INTEGER REFERENCES soc_incidents(id),
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS security_events_server_idx ON security_events(server_id);
CREATE INDEX IF NOT EXISTS security_events_timestamp_idx ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS security_events_event_type_idx ON security_events(event_type);
CREATE INDEX IF NOT EXISTS security_events_source_ip_idx ON security_events(source_ip);
CREATE INDEX IF NOT EXISTS security_events_severity_idx ON security_events(severity);

CREATE TABLE IF NOT EXISTS playbook_executions (
  id SERIAL PRIMARY KEY,
  playbook_name VARCHAR(100) NOT NULL,
  incident_id INTEGER REFERENCES soc_incidents(id),
  server_id INTEGER REFERENCES soc_servers(id),
  trigger_type VARCHAR(50),
  status VARCHAR(30) NOT NULL DEFAULT 'running',
  steps_completed JSONB DEFAULT '[]',
  steps_failed JSONB DEFAULT '[]',
  started_at TIMESTAMP NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMP,
  triggered_by VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS threat_intel_cache (
  id SERIAL PRIMARY KEY,
  indicator VARCHAR(500) NOT NULL,
  indicator_type VARCHAR(50) NOT NULL,
  source VARCHAR(100) NOT NULL,
  reputation_score INTEGER,
  data JSONB,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS threat_intel_indicator_source_idx ON threat_intel_cache(indicator, source);
CREATE INDEX IF NOT EXISTS threat_intel_expires_idx ON threat_intel_cache(expires_at);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id SERIAL PRIMARY KEY,
  server_id INTEGER NOT NULL REFERENCES soc_servers(id),
  category VARCHAR(50),
  severity VARCHAR(20),
  title VARCHAR(500),
  description TEXT,
  cve_id VARCHAR(20),
  remediation TEXT,
  status VARCHAR(30) NOT NULL DEFAULT 'open',
  detected_at TIMESTAMP NOT NULL DEFAULT NOW(),
  fixed_at TIMESTAMP
);
