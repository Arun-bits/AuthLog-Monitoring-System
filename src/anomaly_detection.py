# src/anomaly_detection.py

import sqlite3
import pandas as pd
from sklearn.ensemble import IsolationForest
from src.config import DB_PATH

def run_anomaly_detection():
    conn = sqlite3.connect(DB_PATH)

    df = pd.read_sql("""
        SELECT user_id,
               COUNT(*) as total_events,
               SUM(event_category='LOGIN_FAILURE') as failures,
               SUM(event_category='PRIVILEGE_CHECK') as privileges
        FROM auth_events
        GROUP BY user_id
    """, conn)

    conn.close()

    if df.empty:
        return []

    model = IsolationForest(contamination=0.15, random_state=42)
    df["anomaly"] = model.fit_predict(
        df[["total_events", "failures", "privileges"]]
    )

    return df[df["anomaly"] == -1]["user_id"].tolist()
