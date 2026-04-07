import socket
import platform
from datetime import datetime
import random

# =========================================================
# WINDOWS SUPPORT
# =========================================================
IS_WINDOWS = platform.system().lower() == "windows"

if IS_WINDOWS:
    try:
        import win32evtlog
    except ImportError:
        win32evtlog = None
        IS_WINDOWS = False

# =========================================================
# WINDOWS SECURITY LOG CONFIG
# =========================================================
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

# =========================================================
# GLOBAL STATE TO PREVENT DUPLICATES
# =========================================================
LAST_RECORD_NUMBER = None


def map_event_category(event_id):
    """
    Map Windows Event ID to readable category
    """
    if event_id == 4624:
        return "LOGIN_SUCCESS"
    elif event_id == 4625:
        return "LOGIN_FAILURE"
    elif event_id == 4740:
        return "ACCOUNT_LOCKOUT"
    elif event_id == 4672:
        return "PRIVILEGE_CHECK"
    elif event_id == 4720:
        return "USER_CREATED"
    elif event_id == 4726:
        return "USER_DELETED"
    else:
        return "UNKNOWN_EVENT"


def safe_extract_user(event):
    """
    Safely extract user from event inserts
    """
    try:
        if event.StringInserts and len(event.StringInserts) > 5:
            return str(event.StringInserts[5]).strip()
        elif event.StringInserts and len(event.StringInserts) > 1:
            return str(event.StringInserts[1]).strip()
    except Exception:
        pass

    return "UNKNOWN_USER"


def collect_windows_logs():
    """
    Collect only NEW Windows authentication logs
    """
    global LAST_RECORD_NUMBER

    print("[INFO] Authentication Log Collector Started (Windows Mode)")

    machine_name = socket.gethostname()
    collected = []

    handle = win32evtlog.OpenEventLog(EVENT_LOG_SERVER, EVENT_LOG_TYPE)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    events = win32evtlog.ReadEventLog(handle, flags, 0)

    if not events:
        return []

    # Reverse so older → newer
    events = list(reversed(events))

    for event in events:
        event_id = event.EventID & 0xFFFF
        record_number = event.RecordNumber

        if event_id not in TRACKED_EVENT_IDS:
            continue

        # Skip already processed events
        if LAST_RECORD_NUMBER is not None and record_number <= LAST_RECORD_NUMBER:
            continue

        record = {
            "time": event.TimeGenerated.Format(),
            "machine": machine_name,
            "user": safe_extract_user(event),
            "event_id": event_id,
            "event_category": map_event_category(event_id),
            "record_number": record_number
        }

        collected.append(record)

    # Update last processed record number
    if collected:
        LAST_RECORD_NUMBER = max(r["record_number"] for r in collected)

    return collected


def collect_simulated_logs():
    """
    Fallback for non-Windows systems (demo/dev mode)
    """
    print("[INFO] Authentication Log Collector Started (Simulation Mode)")

    machine_name = socket.gethostname()
    users = ["ARUN", "SYSTEM", "ADMIN", "GUEST"]
    event_pool = [4624, 4625, 4672]

    collected = []

    for _ in range(random.randint(1, 3)):
        event_id = random.choice(event_pool)

        record = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "machine": machine_name,
            "user": random.choice(users),
            "event_id": event_id,
            "event_category": map_event_category(event_id),
            "record_number": random.randint(1000, 9999)
        }

        collected.append(record)

    return collected


def collect_authentication_logs():
    """
    Main collector entry point
    """
    if IS_WINDOWS and win32evtlog is not None:
        return collect_windows_logs()
    else:
        return collect_simulated_logs()