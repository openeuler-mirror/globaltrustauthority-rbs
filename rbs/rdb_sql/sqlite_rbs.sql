-- Unified RBS database schema
-- Source of truth for all table definitions.
-- Used by production (via config storage.sql_file_path) and tests.

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

CREATE TABLE IF NOT EXISTS t_res_policy (
    policy_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    policy_version INTEGER NOT NULL DEFAULT 1,
    policy_content TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'base64',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_res_policy_username ON t_res_policy(username);

CREATE TABLE IF NOT EXISTS t_res_info (
    username TEXT NOT NULL,
    provider_name TEXT NOT NULL,
    repo_name TEXT NOT NULL,
    res_type TEXT NOT NULL,
    res_name TEXT NOT NULL,
    res_info TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    content_type TEXT,
    export_mode TEXT NOT NULL DEFAULT 'jwe',
    policy_id TEXT NOT NULL,
    PRIMARY KEY (username, provider_name, repo_name, res_type, res_name)
);

CREATE INDEX IF NOT EXISTS idx_res_info_username ON t_res_info(username);
CREATE INDEX IF NOT EXISTS idx_res_info_policy_id ON t_res_info(policy_id);
