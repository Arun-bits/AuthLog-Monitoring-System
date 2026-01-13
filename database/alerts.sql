CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_time TEXT,
    machine_id TEXT,
    alert_level TEXT,
    alert_reason TEXT
);
