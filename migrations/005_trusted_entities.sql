-- Trusted entities confirmed by operator via Telegram (persisted across restarts)
CREATE TABLE IF NOT EXISTS trusted_entities (
  id          SERIAL PRIMARY KEY,
  entity_type VARCHAR(20)  NOT NULL, -- 'ip' | 'fingerprint'
  value       VARCHAR(500) NOT NULL,
  added_by    VARCHAR(100),          -- operator first_name
  added_at    TIMESTAMP    NOT NULL DEFAULT NOW(),
  note        VARCHAR(500),
  UNIQUE (entity_type, value)
);

CREATE INDEX IF NOT EXISTS trusted_entities_type_idx ON trusted_entities (entity_type);
