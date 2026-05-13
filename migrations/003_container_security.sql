CREATE TABLE IF NOT EXISTS container_snapshots (
  id SERIAL PRIMARY KEY,
  server_id INTEGER NOT NULL,
  container_name VARCHAR(200) NOT NULL,
  image_name VARCHAR(300),
  processes JSONB,
  network JSONB,
  filesystem_changes JSONB,
  security_config JSONB,
  cve_count INTEGER DEFAULT 0,
  status VARCHAR(20) DEFAULT 'running',
  collected_at TIMESTAMP DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS container_snapshots_server_idx ON container_snapshots (server_id, collected_at);
CREATE INDEX IF NOT EXISTS container_snapshots_name_idx ON container_snapshots (server_id, container_name);
