# src/rule_engine.py

import sqlite3
from pathlib import Path

DB_PATH = Path("database/auth_logs.db")


def run_rule(query, rule_name):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(query)
    results = cursor.fetchall()

    conn.close()

    if results:
        print(f"\n🚨 ALERT: {rule_name}")
        for row in results:
            print("   ", row)


def run_all_rules():
    print("\n[INFO] Running Rule-Based Detection...")

    rules = {
        "Brute Force Detection": """
            SELECT machine_id, COUNT(*)
            FROM auth_events
            WHERE event_category = 'LOGIN_FAILURE'
            GROUP BY machine_id
            HAVING COUNT(*) >= 5;
        """,

        "Failure Followed by Success": """
            SELECT a.machine_id, a.event_time, b.event_time
            FROM auth_events a
            JOIN auth_events b
            ON a.machine_id = b.machine_id
            WHERE a.event_category = 'LOGIN_FAILURE'
              AND b.event_category = 'LOGIN_SUCCESS'
              AND b.event_time > a.event_time;
        """,

        "Excessive Privilege Checks": """
            SELECT machine_id, COUNT(*)
            FROM auth_events
            WHERE event_category = 'PRIVILEGE_CHECK'
            GROUP BY machine_id
            HAVING COUNT(*) > 20;
        """
    }

    for name, query in rules.items():
        run_rule(query, name)


if __name__ == "__main__":
    run_all_rules()
