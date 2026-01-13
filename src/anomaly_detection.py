# src/anomaly_detection.py

import sqlite3
import pandas as pd
from sklearn.ensemble import IsolationForest
from pathlib import Path

DB_PATH = Path("database/auth_logs.db")


def load_features():
    conn = sqlite3.connect(DB_PATH)

    query = """
    SELECT
        machine_id,
        COUNT(*) AS total_events,
        SUM(CASE WHEN event_category = 'LOGIN_FAILURE' THEN 1 ELSE 0 END) AS failed_logins,
        SUM(CASE WHEN event_category = 'LOGIN_SUCCESS' THEN 1 ELSE 0 END) AS success_logins,
        SUM(CASE WHEN event_category = 'PRIVILEGE_CHECK' THEN 1 ELSE 0 END) AS privilege_checks
    FROM auth_events
    GROUP BY machine_id
    """

    df = pd.read_sql_query(query, conn)
    conn.close()

    # Avoid division errors
    df["login_fail_ratio"] = df["failed_logins"] / df["total_events"].replace(0, 1)

    return df


def run_isolation_forest(df):
    features = df[
        ["total_events", "failed_logins", "success_logins", "privilege_checks", "login_fail_ratio"]
    ]

    model = IsolationForest(
        n_estimators=100,
        contamination=0.2,  # 20% treated as anomalies (safe for small data)
        random_state=42
    )

    df["anomaly_score"] = model.fit_predict(features)

    return df


def show_anomalies(df):
    anomalies = df[df["anomaly_score"] == -1]

    if anomalies.empty:
        print("\n[INFO] No anomalous behavior detected")
    else:
        print("\n🚨 AI-DETECTED ANOMALIES")
        for _, row in anomalies.iterrows():
            print(
                f"Machine={row['machine_id']} | "
                f"Total={row['total_events']} | "
                f"Failures={row['failed_logins']} | "
                f"Privileges={row['privilege_checks']} | "
                f"FailRatio={row['login_fail_ratio']:.2f}"
            )


if __name__ == "__main__":
    print("[INFO] Running AI-based Anomaly Detection (Isolation Forest)")

    df = load_features()
    if df.empty:
        print("[INFO] Not enough data for anomaly detection")
    else:
        result = run_isolation_forest(df)
        show_anomalies(result)
