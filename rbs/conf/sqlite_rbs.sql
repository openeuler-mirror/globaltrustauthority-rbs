-- init sql file
SELECT name FROM sqlite_master WHERE type='table';
-----------------demo sql for reference only-------------------
-- CREATE TABLE IF NOT EXISTS users (
--    id INTEGER PRIMARY KEY,
--    name TEXT NOT NULL,
--    email TEXT NOT NULL UNIQUE
-- );
-- INSERT INTO users (name, email) VALUES ('Alice', 'alice@example.com');