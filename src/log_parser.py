# src/log_parser.py

from src.config import EVENT_ID_MAP


def parse_events(raw_events):
    """
    Takes a list of raw Windows events and returns parsed auth events
    """
    parsed = []

    for raw_event in raw_events:
        event_id = raw_event.get("event_id")
        category = EVENT_ID_MAP.get(event_id, "OTHER")

        parsed.append({
            "event_time": raw_event["time"],
            "machine_id": raw_event["machine"],
            "user_id": raw_event.get("user", "UNKNOWN"),
            "event_id": event_id,
            "event_category": category
        })

    return parsed
