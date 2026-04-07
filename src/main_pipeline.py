import time
from src.log_collector import collect_authentication_logs
from src.log_parser import parse_events
from src.db_manager import initialize_database, insert_events
from src.config import STREAM_INTERVAL
from src.alert_engine import run_alert_engine


def start_pipeline():
    print("[INFO] Initializing database...")
    initialize_database()

    print("[INFO] Main Pipeline Started")
    print("[INFO] Streaming authentication events...\n")

    while True:
        raw_logs = collect_authentication_logs()
        parsed_logs = parse_events(raw_logs)

        if parsed_logs:
            insert_events(parsed_logs)

            for event in parsed_logs:
                print(
                    f"[{event['event_time']}] "
                    f"{event['event_category']} | "
                    f"USER={event.get('username')} | "
                    f"MACHINE={event['machine_id']}"
                )

            # 🔥 Run alert engine after new logs are inserted
            run_alert_engine()

        time.sleep(STREAM_INTERVAL)


if __name__ == "__main__":
    start_pipeline()