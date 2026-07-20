-- 004_pam_policies.sql
-- Migration to replace policies and policy_rules with pam_policies

DROP TABLE IF EXISTS policy_rules;
DROP TABLE IF EXISTS policies;

CREATE TABLE pam_policies (
    id SERIAL PRIMARY KEY,
    policy_id VARCHAR(128) NOT NULL,
    category VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(32) DEFAULT 'disabled',
    value_json TEXT,
    scope VARCHAR(32) DEFAULT 'global',
    scope_target VARCHAR(255),
    priority INTEGER DEFAULT 100,
    exceptions_json TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by_id INTEGER REFERENCES users(id),
    updated_by_id INTEGER REFERENCES users(id)
);

CREATE INDEX ix_pam_policies_policy_id ON pam_policies(policy_id);
CREATE INDEX ix_pam_policies_category ON pam_policies(category);
CREATE INDEX ix_pam_policies_status ON pam_policies(status);
CREATE INDEX ix_pam_policies_scope ON pam_policies(scope);
CREATE INDEX ix_pam_policies_priority ON pam_policies(priority);

-- Update foreign keys if necessary
-- Note: SQLite doesn't support DROP COLUMN easily, but for PostgreSQL:
ALTER TABLE session_commands DROP COLUMN IF EXISTS matched_policy_rule_id;
ALTER TABLE session_commands ADD COLUMN matched_policy_id INTEGER REFERENCES pam_policies(id);

ALTER TABLE risk_events DROP COLUMN IF EXISTS rule_id;
ALTER TABLE risk_events ADD COLUMN matched_policy_id INTEGER REFERENCES pam_policies(id);
