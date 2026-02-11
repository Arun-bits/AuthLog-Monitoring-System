# src/log_collector.py

import win32evtlog
import win32evtlogutil
import socket
from datetime import datetime

# Windows Security log constants (OS-level, not config-level)
EVENT_LOG_SERVER = None
EVENT_LOG_TYPE = "Security"

TRACKED_EVENT_IDS = {
    4624,  # Successful logon
    4625,  # Failed logon
    4740,  # Account lockout
    4720,  # User created
    4726,  # User deleted
    4672   # Special privileges
}


def collect_authentication_logs():
    print("[INFO] Authentication Log Collector Started")

    server = EVENT_LOG_SERVER
    log_type = EVENT_LOG_TYPE
    machine_name = socket.gethostname()

    handle = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    events = win32evtlog.ReadEventLog(handle, flags, 0)

    collected = []

    for event in events:
        if event.EventID not in TRACKED_EVENT_IDS:
            continue

        record = {
            "time": event.TimeGenerated.Format(),
            "machine": machine_name,
            "user": event.StringInserts[1] if event.StringInserts else "UNKNOWN",
            "event_id": event.EventID
        }

        collected.append(record)

    return collected
