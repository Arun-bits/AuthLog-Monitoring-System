# src/log_collector.py

import win32evtlog
from src.config import (
    EVENT_LOG_SERVER,
    EVENT_LOG_TYPE,
    SUCCESS_LOGIN_EVENT_ID,
    FAILED_LOGIN_EVENT_ID,
    MACHINE_ID
)

_last_record_number = None  # global state


def collect_authentication_logs():
    handle = win32evtlog.OpenEventLog(EVENT_LOG_SERVER, EVENT_LOG_TYPE)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    events = win32evtlog.ReadEventLog(handle, flags, 0)
    collected_events = []

    if events:
        for event in events[:5]:  # show only latest 5
            collected_events.append({
                "event_id": event.EventID,
                "timestamp": event.TimeGenerated.Format(),
                "machine_id": MACHINE_ID,
                "event_type": "RAW",
                "raw_event": event
            })

    win32evtlog.CloseEventLog(handle)
    return collected_events
