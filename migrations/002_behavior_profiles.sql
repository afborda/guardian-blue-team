-- ML Behavioral Baselines
CREATE TABLE IF NOT EXISTS behavior_profiles (
  id SERIAL PRIMARY KEY,
  server_id INTEGER NOT NULL,
  profile_type VARCHAR(30) NOT NULL,
  subject_id VARCHAR(255) NOT NULL,
  profile JSONB NOT NULL DEFAULT '{}',
  sample_count INTEGER NOT NULL DEFAULT 0,
  last_updated_at TIMESTAMP DEFAULT NOW() NOT NULL,
  created_at TIMESTAMP DEFAULT NOW() NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS behavior_profiles_subject_idx
  ON behavior_profiles (server_id, profile_type, subject_id);

-- RAG Incident Memory
CREATE TABLE IF NOT EXISTS incident_memory (
  id SERIAL PRIMARY KEY,
  incident_id INTEGER,
  category VARCHAR(100) NOT NULL,
  title VARCHAR(500) NOT NULL,
  source_ips JSONB DEFAULT '[]',
  resolution VARCHAR(500),
  outcome VARCHAR(30),
  false_positive BOOLEAN NOT NULL DEFAULT false,
  root_cause TEXT,
  time_to_contain_minutes INTEGER,
  tags JSONB DEFAULT '[]',
  embedding JSONB,
  created_at TIMESTAMP DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS incident_memory_category_idx ON incident_memory (category);
CREATE INDEX IF NOT EXISTS incident_memory_created_idx ON incident_memory (created_at);
