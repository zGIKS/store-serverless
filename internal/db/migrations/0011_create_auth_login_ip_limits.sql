CREATE TABLE IF NOT EXISTS auth_login_ip_limits (
    ip TEXT PRIMARY KEY,
    window_started_at TIMESTAMPTZ NOT NULL,
    hits INTEGER NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_login_ip_limits_updated_at ON auth_login_ip_limits(updated_at);
