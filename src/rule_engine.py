# src/rule_engine.py

import sqlite3
from src.config import DB_PATH

def detect_three_failures_in_window():
    """
    Detects 3 or more failed logins in the last 5 minutes
    """

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM auth_events
        WHERE event_category = 'LOGIN_FAILURE'
          AND event_time >= datetime('now', '-5 minutes')
    """)

    count = cursor.fetchone()[0]
    conn.close()

    print("[DEBUG] Failed logins in last 5 minutes:", count)

    return count >= 3