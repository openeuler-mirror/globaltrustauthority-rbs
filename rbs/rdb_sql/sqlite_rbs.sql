-- Users table for the admin / user management module
CREATE TABLE IF NOT EXISTS t_user_info (
    user_id     TEXT NOT NULL,
    username    TEXT PRIMARY KEY NOT NULL,
    role        TEXT NOT NULL DEFAULT 'user',
    auth_type   TEXT NOT NULL DEFAULT 'jwt',
    auth_value  TEXT NOT NULL,
    auth_alg    TEXT NOT NULL,
    status      INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);