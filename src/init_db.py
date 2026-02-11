# src/init_db.py

import sqlite3
from pathlib import Path

DB_PATH = Path("database/auth_logs.db")
SCHEMA_PATH = Path("database/schema.sql")
ALERTS_PATH = Path("database/alerts.sql")

DB_PATH.parent.mkdir(exist_ok=True)

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

with open(SCHEMA_PATH, "r") as f:
    cursor.executescript(f.read())

with open(ALERTS_PATH, "r") as f:
    cursor.executescript(f.read())

conn.commit()
conn.close()

print("[OK] Database initialized successfully")
