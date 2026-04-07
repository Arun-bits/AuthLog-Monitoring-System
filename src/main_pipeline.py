import time
from src.log_collector import collect_authentication_logs
from src.log_parser import parse_events
from src.db_manager import initialize_database, insert_events
from src.config import STREAM_INTERVAL
from src.alert_engine import run_alert_engine


def start_pipeline():
    print("=" * 70)
    print("🔐 AUTHENTICATION LOG MONITORING SYSTEM STARTED")
    print("=" * 70)

    print("[INFO] Initializing database...")
    initialize_database()

    print("[INFO] Main Pipeline Started")
    print("[INFO] Streaming authentication events...\n")

    cycle = 1

    try:
        while True:
            print(f"\n[INFO] Monitoring Cycle #{cycle}")
            print("-" * 70)

            raw_logs = collect_authentication_logs()
            parsed_logs = parse_events(raw_logs)

            if parsed_logs:
                insert_events(parsed_logs)

                for event in parsed_logs:
                    print(
                        f"[{event['event_time']}] "
                        f"{event['event_category']} | "
                        f"USER={event.get('user_id')} | "
                        f"MACHINE={event['machine_id']}"
                    )

                # Run alert engine only if new logs exist
                run_alert_engine()
            else:
                print("[INFO] No new authentication events found.")

            cycle += 1
            time.sleep(STREAM_INTERVAL)

    except KeyboardInterrupt:
        print("\n" + "=" * 70)
        print("[INFO] Monitoring stopped by user.")
        print("=" * 70)


if __name__ == "__main__":
    start_pipeline()