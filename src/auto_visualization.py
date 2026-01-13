import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

DB_PATH = Path("database/auth_logs.db")
CHART_PATH = Path("reports/charts")
CHART_PATH.mkdir(exist_ok=True)

def generate_failed_login_chart():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql("""
        SELECT event_time FROM auth_events
        WHERE event_category='LOGIN_FAILURE'
    """, conn)
    conn.close()

    if df.empty:
        return

    df['event_time'] = pd.to_datetime(df['event_time'])
    df['hour'] = df['event_time'].dt.hour

    df.groupby('hour').size().plot(kind='bar')
    plt.title("Failed Login Attempts by Hour")
    plt.savefig(CHART_PATH / "failed_logins.png")
    plt.close()


def generate_privilege_chart():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql("""
        SELECT machine_id, COUNT(*) as count
        FROM auth_events
        WHERE event_category='PRIVILEGE_CHECK'
        GROUP BY machine_id
    """, conn)
    conn.close()

    if df.empty:
        return

    df.plot(kind='bar', x='machine_id', y='count')
    plt.title("Privilege Check Frequency")
    plt.savefig(CHART_PATH / "privilege_checks.png")
    plt.close()


if __name__ == "__main__":
    generate_failed_login_chart()
    generate_privilege_chart()
    print("📊 Auto charts generated")
