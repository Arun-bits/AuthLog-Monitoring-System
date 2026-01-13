# src/risk_scoring.py

import sqlite3
from pathlib import Path

DB_PATH = Path("database/auth_logs.db")


def get_rule_signals():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    signals = {}

    # Rule 1: Brute force
    cursor.execute("""
        SELECT machine_id, COUNT(*)
        FROM auth_events
        WHERE event_category = 'LOGIN_FAILURE'
        GROUP BY machine_id
        HAVING COUNT(*) >= 5
    """)
    for row in cursor.fetchall():
        signals.setdefault(row[0], 0)
        signals[row[0]] += 40

    # Rule 2: Failure followed by success
    cursor.execute("""
        SELECT DISTINCT a.machine_id
        FROM auth_events a
        JOIN auth_events b
        ON a.machine_id = b.machine_id
        WHERE a.event_category = 'LOGIN_FAILURE'
          AND b.event_category = 'LOGIN_SUCCESS'
          AND b.event_time > a.event_time
    """)
    for row in cursor.fetchall():
        signals.setdefault(row[0], 0)
        signals[row[0]] += 30

    # Rule 3: Excessive privilege checks
    cursor.execute("""
        SELECT machine_id, COUNT(*)
        FROM auth_events
        WHERE event_category = 'PRIVILEGE_CHECK'
        GROUP BY machine_id
        HAVING COUNT(*) > 20
    """)
    for row in cursor.fetchall():
        signals.setdefault(row[0], 0)
        signals[row[0]] += 20

    conn.close()
    return signals


def get_ai_signals():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    ai_signals = {}

    cursor.execute("""
        SELECT machine_id,
               COUNT(*) AS total_events,
               SUM(CASE WHEN event_category = 'LOGIN_FAILURE' THEN 1 ELSE 0 END) AS failures,
               SUM(CASE WHEN event_category = 'PRIVILEGE_CHECK' THEN 1 ELSE 0 END) AS privileges
        FROM auth_events
        GROUP BY machine_id
    """)

    for row in cursor.fetchall():
        machine, total, failures, privileges = row
        if total > 100 and privileges > 50:
            ai_signals[machine] = 25

    conn.close()
    return ai_signals


def calculate_risk():
    rule_scores = get_rule_signals()
    ai_scores = get_ai_signals()

    machines = set(rule_scores.keys()) | set(ai_scores.keys())

    print("\n📊 FINAL RISK SCORES\n")

    for machine in machines:
        total_score = rule_scores.get(machine, 0) + ai_scores.get(machine, 0)

        if total_score >= 70:
            level = "HIGH RISK"
        elif total_score >= 40:
            level = "MEDIUM RISK"
        else:
            level = "LOW RISK"

        print(
            f"Machine={machine} | "
            f"RiskScore={total_score}/100 | "
            f"Level={level}"
        )


if __name__ == "__main__":
    calculate_risk()
