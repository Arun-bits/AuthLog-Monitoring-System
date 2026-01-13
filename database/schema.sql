-- database/schema.sql

CREATE TABLE IF NOT EXISTS auth_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time TEXT NOT NULL,
    event_id INTEGER NOT NULL,
    event_category TEXT NOT NULL,
    username TEXT,
    logon_type TEXT,
    status TEXT,
    machine_id TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
