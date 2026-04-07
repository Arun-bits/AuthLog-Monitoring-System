import sqlite3
from src.config import DB_PATH


def calculate_ml_risk_score():
    """
    Calculates a normalized ML-style risk score (0–100)
    based on recent authentication behavior.
    """

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            SUM(CASE WHEN event_category = 'LOGIN_FAILURE' THEN 1 ELSE 0 END) AS failures,
            SUM(CASE WHEN event_category = 'PRIVILEGE_CHECK' THEN 1 ELSE 0 END) AS privileges,
            SUM(CASE WHEN event_category = 'LOGIN_SUCCESS' THEN 1 ELSE 0 END) AS successes
        FROM auth_events
        WHERE event_time >= datetime('now', '-10 minutes')
    """)

    row = cursor.fetchone()
    conn.close()

    failures = row[0] if row[0] else 0
    privileges = row[1] if row[1] else 0
    successes = row[2] if row[2] else 0

    # ============================================
    # Weighted scoring logic
    # ============================================
    risk_score = 0

    # Failed logins contribute strongly
    risk_score += failures * 18

    # Privilege checks are suspicious but lighter
    risk_score += privileges * 10

    # Successful logins reduce suspicion slightly
    risk_score -= successes * 5

    # Extra escalation for repeated failures
    if failures >= 3:
        risk_score += 15
    if failures >= 5:
        risk_score += 10

    # Ensure score stays between 0 and 100
    risk_score = max(0, min(100, risk_score))

    return int(risk_score)