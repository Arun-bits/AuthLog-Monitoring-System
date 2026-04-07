import sqlite3
import pandas as pd
from src.config import DB_PATH


def detect_three_failures_in_window():
    """
    Detect suspicious repeated failed logins:
    3 or more failures by the same user + machine in the last 5 minutes.

    Returns:
        {
            "detected": bool,
            "user_id": str,
            "machine_id": str,
            "failure_count": int
        }
    """

    conn = sqlite3.connect(DB_PATH)

    query = """
        SELECT 
            user_id,
            machine_id,
            COUNT(*) AS failure_count
        FROM auth_events
        WHERE event_category = 'LOGIN_FAILURE'
          AND event_time >= datetime('now', '-5 minutes')
        GROUP BY user_id, machine_id
        HAVING COUNT(*) >= 3
        ORDER BY failure_count DESC
        LIMIT 1
    """

    df = pd.read_sql(query, conn)
    conn.close()

    if df.empty:
        print("[DEBUG] No suspicious repeated failures found in last 5 minutes.")
        return {
            "detected": False,
            "user_id": None,
            "machine_id": None,
            "failure_count": 0
        }

    suspicious = df.iloc[0]

    print(f"[DEBUG] Suspicious failed logins detected -> USER={suspicious['user_id']} | "
          f"MACHINE={suspicious['machine_id']} | COUNT={suspicious['failure_count']}")

    return {
        "detected": True,
        "user_id": suspicious["user_id"],
        "machine_id": suspicious["machine_id"],
        "failure_count": int(suspicious["failure_count"])
    }