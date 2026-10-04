-- Modified for Railway owner-password authentication.

-- name: GetOwnerBootstrap :one
SELECT * FROM owner_bootstrap
WHERE singleton;

-- name: CreateOwnerBootstrap :exec
-- Modified for Railway owner-password authentication.
INSERT INTO owner_bootstrap (outcome, user_id, email, password_hash)
VALUES ($1, $2, $3, $4);

-- name: HasUsersOrWorkspaces :one
SELECT (EXISTS (SELECT 1 FROM "user") OR EXISTS (SELECT 1 FROM workspace))::bool AS has_data;

-- name: RecordOwnerPasswordLoginAttempt :one
-- Atomically counts one attempt in a fixed window. A window older than
-- window_seconds restarts at 1.
INSERT INTO owner_password_login_attempt (bucket, window_start, attempts)
VALUES (@bucket, now(), 1)
ON CONFLICT (bucket) DO UPDATE SET
    window_start = CASE
        WHEN owner_password_login_attempt.window_start <= now() - make_interval(secs => @window_seconds::int)
        THEN now() ELSE owner_password_login_attempt.window_start END,
    attempts = CASE
        WHEN owner_password_login_attempt.window_start <= now() - make_interval(secs => @window_seconds::int)
        THEN 1 ELSE owner_password_login_attempt.attempts + 1 END
RETURNING attempts;

-- name: DeleteStaleOwnerPasswordLoginAttempts :exec
DELETE FROM owner_password_login_attempt
WHERE window_start < now() - make_interval(secs => @older_than_seconds::int);
