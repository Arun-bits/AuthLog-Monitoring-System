# src/excel_report.py

import sqlite3
import pandas as pd
from pathlib import Path

DB_PATH = Path("database/auth_logs.db")
REPORT_PATH = Path("reports/security_report.xlsx")


def export_all_events(writer):
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM auth_events", conn)
    conn.close()

    df.to_excel(writer, sheet_name="All_Auth_Events", index=False)


def export_rule_alerts(writer):
    conn = sqlite3.connect(DB_PATH)

    alerts = []

    # Brute force
    brute = pd.read_sql_query("""
        SELECT machine_id, COUNT(*) AS failed_attempts
        FROM auth_events
        WHERE event_category = 'LOGIN_FAILURE'
        GROUP BY machine_id
        HAVING COUNT(*) >= 5
    """, conn)
    brute["alert_type"] = "Brute Force Attempt"
    alerts.append(brute)

    # Excessive privilege checks
    privilege = pd.read_sql_query("""
        SELECT machine_id, COUNT(*) AS privilege_events
        FROM auth_events
        WHERE event_category = 'PRIVILEGE_CHECK'
        GROUP BY machine_id
        HAVING COUNT(*) > 20
    """, conn)
    privilege["alert_type"] = "Excessive Privilege Checks"
    alerts.append(privilege)

    conn.close()

    if alerts:
        alert_df = pd.concat(alerts, ignore_index=True)
        alert_df.to_excel(writer, sheet_name="Rule_Alerts", index=False)
    else:
        pd.DataFrame().to_excel(writer, sheet_name="Rule_Alerts")


def export_risk_scores(writer):
    conn = sqlite3.connect(DB_PATH)

    df = pd.read_sql_query("""
        SELECT
            machine_id,
            COUNT(*) AS total_events,
            SUM(CASE WHEN event_category = 'LOGIN_FAILURE' THEN 1 ELSE 0 END) AS failures,
            SUM(CASE WHEN event_category = 'PRIVILEGE_CHECK' THEN 1 ELSE 0 END) AS privileges
        FROM auth_events
        GROUP BY machine_id
    """, conn)

    conn.close()

    def calculate_risk(row):
        score = 0
        if row["failures"] >= 5:
            score += 40
        if row["privileges"] > 20:
            score += 20
        if row["total_events"] > 100:
            score += 15
        return score

    df["risk_score"] = df.apply(calculate_risk, axis=1)

    df["risk_level"] = df["risk_score"].apply(
        lambda x: "HIGH" if x >= 70 else "MEDIUM" if x >= 40 else "LOW"
    )

    df.to_excel(writer, sheet_name="Risk_Summary", index=False)


def generate_excel_report():
    REPORT_PATH.parent.mkdir(exist_ok=True)

    with pd.ExcelWriter(REPORT_PATH, engine="openpyxl") as writer:
        export_all_events(writer)
        export_rule_alerts(writer)
        export_risk_scores(writer)

    print(f"\n✅ Excel report generated: {REPORT_PATH.resolve()}")


if __name__ == "__main__":
    generate_excel_report()
