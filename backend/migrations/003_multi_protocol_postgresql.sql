-- Additive PostgreSQL migration for multi-protocol PAM. SQLite installations
-- are migrated idempotently by app.database.init_db / metadata.create_all.
ALTER TABLE servers ADD COLUMN IF NOT EXISTS protocol VARCHAR(32) NOT NULL DEFAULT 'ssh';
ALTER TABLE servers ADD COLUMN IF NOT EXISTS allowed_domains TEXT;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS allow_private_network BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS allow_subdomains BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS tags TEXT;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS connection_timeout_seconds INTEGER NOT NULL DEFAULT 10;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS protocol VARCHAR(32) NOT NULL DEFAULT 'ssh';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_heartbeat_at TIMESTAMPTZ;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS authentication_expires_at TIMESTAMPTZ;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS absolute_timeout_seconds INTEGER;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS worker_id VARCHAR(128);

CREATE TABLE IF NOT EXISTS web_connection_profiles (
  id SERIAL PRIMARY KEY, server_id INTEGER NOT NULL UNIQUE REFERENCES servers(id), initial_url TEXT NOT NULL,
  authentication_mode VARCHAR(32) NOT NULL DEFAULT 'none', username_secret_id INTEGER REFERENCES secrets(id),
  password_secret_id INTEGER REFERENCES secrets(id), auth_secret_id INTEGER REFERENCES secrets(id),
  username_selector VARCHAR(512), password_selector VARCHAR(512), submit_selector VARCHAR(512),
  success_url_pattern VARCHAR(512), success_dom_selector VARCHAR(512), header_name VARCHAR(128), cookie_name VARCHAR(128),
  blocked_domains TEXT, upload_policy VARCHAR(32) NOT NULL DEFAULT 'deny', download_policy VARCHAR(32) NOT NULL DEFAULT 'deny',
  clipboard_policy VARCHAR(32) NOT NULL DEFAULT 'deny', popup_policy VARCHAR(32) NOT NULL DEFAULT 'same_origin',
  max_upload_bytes INTEGER NOT NULL DEFAULT 10485760, max_download_bytes INTEGER NOT NULL DEFAULT 52428800,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS vnc_connection_profiles (
  id SERIAL PRIMARY KEY, server_id INTEGER NOT NULL UNIQUE REFERENCES servers(id), hostname VARCHAR(255) NOT NULL,
  port INTEGER NOT NULL DEFAULT 5900, secret_id INTEGER REFERENCES secrets(id), tls_required BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS session_events (
  id SERIAL PRIMARY KEY, session_id INTEGER NOT NULL REFERENCES sessions(id), event_type VARCHAR(64) NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP, sequence_number INTEGER NOT NULL, source VARCHAR(32) NOT NULL,
  metadata_json TEXT, sensitive BOOLEAN NOT NULL DEFAULT FALSE, UNIQUE(session_id, sequence_number)
);
CREATE TABLE IF NOT EXISTS session_artifacts (
  id SERIAL PRIMARY KEY, session_id INTEGER NOT NULL REFERENCES sessions(id), artifact_type VARCHAR(32) NOT NULL,
  storage_path VARCHAR(1024) NOT NULL, sha256 VARCHAR(64) NOT NULL, mime_type VARCHAR(128) NOT NULL,
  size_bytes INTEGER NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_session_events_session ON session_events(session_id);
CREATE INDEX IF NOT EXISTS ix_session_artifacts_session ON session_artifacts(session_id);
ALTER TABLE web_connection_profiles ADD COLUMN IF NOT EXISTS login_timeout_seconds INTEGER NOT NULL DEFAULT 30;
ALTER TABLE web_connection_profiles ADD COLUMN IF NOT EXISTS idle_timeout_seconds INTEGER NOT NULL DEFAULT 900;
ALTER TABLE web_connection_profiles ADD COLUMN IF NOT EXISTS maximum_session_duration_minutes INTEGER NOT NULL DEFAULT 60;
CREATE TABLE IF NOT EXISTS access_wizard_drafts (
  id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), mode VARCHAR(32) NOT NULL,
  resource_type VARCHAR(32), data_json TEXT NOT NULL DEFAULT '{}', completed_steps_json TEXT NOT NULL DEFAULT '[]',
  expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS access_wizard_submissions (
  id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), submission_key VARCHAR(64) NOT NULL,
  result_json TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, submission_key)
);
