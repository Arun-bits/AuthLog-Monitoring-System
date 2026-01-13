# src/db_manager.py

import sqlite3
from pathlib import Path

DB_PATH = Path("database/auth_logs.db")
SCHEMA_PATH = Path("database/schema.sql")


def get_connection():
    return sqlite3.connect(DB_PATH)


def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()

    with open(SCHEMA_PATH, "r") as f:
        schema_sql = f.read()

    cursor.executescript(schema_sql)
    conn.commit()
    conn.close()


def insert_event(event):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO auth_events (
            event_time,
            event_id,
            event_category,
            username,
            logon_type,
            status,
            machine_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        event["timestamp"].isoformat(),
        event["event_id"],
        event["event_category"],
        event.get("username"),
        event.get("logon_type"),
        event.get("status"),
        event.get("machine_id")
    ))

    conn.commit()
    conn.close()


def insert_events(events):
    for event in events:
        insert_event(event)
