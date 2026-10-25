-- Modified for Railway owner-password authentication.
--
-- Numbered 9000, outside upstream's range, so upstream releases never collide
-- with it (it was 535 on v0.5.1; every statement is idempotent, so DBs that
-- already applied 535_owner_password_auth re-run it as a no-op).
--
-- owner_bootstrap is a durable singleton: the first server start that sees
-- MULTICA_OWNER_EMAIL/MULTICA_OWNER_PASSWORD writes exactly one row and no
-- later start ever rewrites it. 'owner_created' carries the owner's password
-- credential; 'existing_data' records that the database already had users or
-- workspaces, so no password is ever attached to a pre-existing account and
-- initialization never reopens (not even after users are deleted).
CREATE TABLE IF NOT EXISTS owner_bootstrap (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    outcome TEXT NOT NULL CHECK (outcome IN ('owner_created', 'existing_data')),
    user_id UUID,
    email TEXT,
    password_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        (outcome = 'owner_created' AND user_id IS NOT NULL AND email IS NOT NULL AND password_hash IS NOT NULL)
        OR (outcome = 'existing_data' AND user_id IS NULL AND email IS NULL AND password_hash IS NULL)
    )
);

COMMENT ON TABLE owner_bootstrap IS 'Modified for Railway owner-password authentication. Durable singleton owner credential and bootstrap closure marker.';

-- Fixed-window owner password login attempt counters, keyed by bucket
-- (per client IP plus one global bucket). Persisted in PostgreSQL so the cap
-- survives restarts and holds without Redis.
CREATE TABLE IF NOT EXISTS owner_password_login_attempt (
    bucket TEXT PRIMARY KEY,
    window_start TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL
);
COMMENT ON TABLE owner_password_login_attempt IS 'Modified for Railway owner-password authentication. Durable password-login rate limits.';
