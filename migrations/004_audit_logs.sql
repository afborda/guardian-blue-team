CREATE TABLE IF NOT EXISTS audit_logs (
  id SERIAL PRIMARY KEY,
  category VARCHAR(30) NOT NULL,
  event_type VARCHAR(100) NOT NULL,
  server_id INTEGER,
  timestamp TIMESTAMP DEFAULT NOW() NOT NULL,
  actor VARCHAR(255),
  resource VARCHAR(500),
  action VARCHAR(100),
  result VARCHAR(30),
  details JSONB,
  related_incident_id INTEGER,
  related_playbook_id INTEGER,
  created_at TIMESTAMP DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_logs_server_idx ON audit_logs (server_id, created_at);
CREATE INDEX IF NOT EXISTS audit_logs_category_idx ON audit_logs (category, event_type);
CREATE INDEX IF NOT EXISTS audit_logs_timestamp_idx ON audit_logs (timestamp);
