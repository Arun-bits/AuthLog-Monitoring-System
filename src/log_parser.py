# src/log_parser.py
EVENT_CATEGORY_MAP = {
    4624: "LOGIN_SUCCESS",
    4625: "LOGIN_FAILURE",
    4798: "PRIVILEGE_CHECK",
    4672: "PRIVILEGE_ASSIGNMENT",
    4634: "LOGOFF",
    4800: "LOCK",
    4801: "UNLOCK"
}

from datetime import datetime

# Windows Logon Type Mapping
LOGON_TYPE_MAP = {
    "2": "Interactive",
    "3": "Network",
    "10": "RemoteInteractive"
}

def parse_event(raw_event):
    """
    Parses a raw Windows authentication event
    Returns a cleaned dictionary
    """

    try:
        inserts = raw_event["raw_event"].StringInserts

        if not inserts:
            return None

        # Username position differs slightly, but this is reliable
        username = inserts[5] if len(inserts) > 5 else "UNKNOWN"

        # Logon Type (position is stable)
        logon_type_code = inserts[8] if len(inserts) > 8 else "UNKNOWN"
        logon_type = LOGON_TYPE_MAP.get(logon_type_code, "Other")

        parsed_event = {
    "event_id": raw_event["event_id"],
    "event_category": EVENT_CATEGORY_MAP.get(raw_event["event_id"], "OTHER"),
    "timestamp": datetime.strptime(
        raw_event["timestamp"], "%a %b %d %H:%M:%S %Y"
    ),
    "username": username,
    "logon_type": logon_type,
    "status": raw_event["event_type"],
    "machine_id": raw_event["machine_id"]
}


        return parsed_event

    except Exception:
        return None


def parse_events(raw_events):
    """
    Parses a list of raw events
    """

    parsed_events = []

    for event in raw_events:
        parsed = parse_event(event)
        if parsed:
            parsed_events.append(parsed)

    return parsed_events
