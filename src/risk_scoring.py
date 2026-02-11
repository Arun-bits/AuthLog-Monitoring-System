# src/risk_scoring.py

import sqlite3
from src.config import DB_PATH

def calculate_ml_risk_score():
    """
    Calculates a simple ML-style risk score based on recent behavior.
    """

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            SUM(CASE WHEN event_category = 'LOGIN_FAILURE' THEN 1 ELSE 0 END) * 20 +
            SUM(CASE WHEN event_category = 'PRIVILEGE_CHECK' THEN 1 ELSE 0 END) * 10
        FROM auth_events
        WHERE event_time >= datetime('now', '-10 minutes')
    """)

    score = cursor.fetchone()[0]
    conn.close()

    return score if score else 0