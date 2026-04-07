from datetime import datetime


def format_time(raw_time):
    """
    Convert Windows time format to standard format
    """
    try:
        # Example input: Tue Apr  7 15:54:13 2026
        dt = datetime.strptime(raw_time, "%a %b %d %H:%M:%S %Y")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return raw_time  # fallback


def parse_events(raw_events):
    """
    Takes raw events and converts to DB-ready format
    """
    parsed = []

    for raw_event in raw_events:
        try:
            event_id = raw_event.get("event_id")

            # ✅ Use collector category FIRST (more reliable)
            category = raw_event.get("event_category", "OTHER")

            parsed.append({
                "event_time": format_time(raw_event.get("time")),
                "machine_id": raw_event.get("machine", "UNKNOWN_MACHINE"),
                "user_id": raw_event.get("user", "UNKNOWN_USER"),
                "event_id": event_id,
                "event_category": category
            })

        except Exception as e:
            print(f"[WARNING] Failed to parse event: {e}")

    return parsed