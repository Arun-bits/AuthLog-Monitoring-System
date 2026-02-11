CREATE TABLE IF NOT EXISTS auth_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_time TEXT,
    machine_id TEXT,
    user_id TEXT,
    event_id INTEGER,
    event_category TEXT
);

CREATE TABLE IF NOT EXISTS user_baseline (
    user_id TEXT,
    avg_logins REAL,
    avg_failures REAL,
    avg_privileges REAL,
    last_updated TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_time TEXT,
    machine_id TEXT,
    user_id TEXT,
    alert_level TEXT,
    alert_reason TEXT,
    confidence TEXT
);
