# src/alert_engine.py

import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path("database/auth_logs.db")

def generate_alert(machine, level, reason):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (alert_time, machine_id, alert_level, alert_reason)
        VALUES (?, ?, ?, ?)
    """, (
        datetime.now().isoformat(),
        machine,
        level,
        reason
    ))

    conn.commit()
    conn.close()

    print(f"🚨 ALERT [{level}] | {machine} | {reason}")
