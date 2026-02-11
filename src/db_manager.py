# src/db_manager.py

import sqlite3
from src.config import DB_PATH


def initialize_database():
    """
    Ensures the database and tables exist.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS auth_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT,
            machine_id TEXT,
            user_id TEXT,
            event_id INTEGER,
            event_category TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_time TEXT,
            machine_id TEXT,
            user_id TEXT,
            alert_level TEXT,
            alert_reason TEXT,
            confidence TEXT
        )
    """)

    conn.commit()
    conn.close()


def insert_events(events):
    """
    Inserts parsed authentication events into the database.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    for event in events:
        cursor.execute("""
            INSERT INTO auth_events
            (event_time, machine_id, user_id, event_id, event_category)
            VALUES (?, ?, ?, ?, ?)
        """, (
            event["event_time"],
            event["machine_id"],
            event["user_id"],
            event["event_id"],
            event["event_category"]
        ))

    conn.commit()
    conn.close()
