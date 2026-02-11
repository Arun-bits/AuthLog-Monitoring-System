# src/ueba_baseline.py

import sqlite3
from datetime import datetime
from src.config import DB_PATH

def update_user_baseline():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT user_id,
               AVG(CASE WHEN event_category='LOGIN_SUCCESS' THEN 1 ELSE 0 END),
               AVG(CASE WHEN event_category='LOGIN_FAILURE' THEN 1 ELSE 0 END),
               AVG(CASE WHEN event_category='PRIVILEGE_CHECK' THEN 1 ELSE 0 END)
        FROM auth_events
        GROUP BY user_id
    """)

    rows = cursor.fetchall()

    for row in rows:
        cursor.execute("""
            INSERT OR REPLACE INTO user_baseline
            (user_id, avg_logins, avg_failures, avg_privileges, last_updated)
            VALUES (?, ?, ?, ?, ?)
        """, (
            row[0], row[1], row[2], row[3], datetime.now().isoformat()
        ))

    conn.commit()
    conn.close()
