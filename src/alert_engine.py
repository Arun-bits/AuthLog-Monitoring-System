import sqlite3
from datetime import datetime
from colorama import Fore, Style, init

from src.rule_engine import detect_three_failures_in_window
from src.risk_scoring import calculate_ml_risk_score
from src.config import DB_PATH

# Initialize colorama for Windows terminal compatibility
init(autoreset=True)


def insert_alert(machine_id, user_id, alert_level, alert_reason, confidence):
    """
    Insert generated alert into alerts table.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            alert_time,
            machine_id,
            user_id,
            alert_level,
            alert_reason,
            confidence
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        machine_id,
        user_id,
        alert_level,
        alert_reason,
        confidence
    ))

    conn.commit()
    conn.close()


def run_alert_engine():
    print(Fore.CYAN + "\n[INFO] Alert engine started")

    failure_detected = detect_three_failures_in_window()
    risk_score = calculate_ml_risk_score()

    print(Fore.YELLOW + f"[INFO] Failure detected: {failure_detected}")
    print(Fore.YELLOW + f"[INFO] Risk score: {risk_score}")

    alert_triggered = False
    alert_level = "LOW"
    alert_reason = "Normal authentication behavior"
    confidence = f"{risk_score}%"
    machine_id = "UNKNOWN_MACHINE"
    user_id = "UNKNOWN_USER"

    # 🔥 Final trigger logic
    if failure_detected and risk_score >= 80:
        alert_level = "CRITICAL"
        alert_reason = "Multiple failed logins + very high ML risk score"
        alert_triggered = True

    elif failure_detected and risk_score >= 60:
        alert_level = "HIGH"
        alert_reason = "Repeated failed logins + suspicious ML behavior"
        alert_triggered = True

    elif failure_detected:
        alert_level = "MEDIUM"
        alert_reason = "Three failed login attempts detected in short time window"
        alert_triggered = True

    elif risk_score >= 60:
        alert_level = "HIGH"
        alert_reason = "High ML risk score detected"
        alert_triggered = True

    if alert_triggered:
        print(Fore.RED + Style.BRIGHT + "\n" + "=" * 60)
        print(Fore.RED + Style.BRIGHT + "⚠️ SECURITY ALERT TRIGGERED")
        print(Fore.RED + Style.BRIGHT + "=" * 60)
        print(Fore.WHITE + f"🕒 Time       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(Fore.WHITE + f"👤 User       : {user_id}")
        print(Fore.WHITE + f"💻 Machine    : {machine_id}")
        print(Fore.WHITE + f"🚨 Level      : {alert_level}")
        print(Fore.WHITE + f"📌 Reason     : {alert_reason}")
        print(Fore.WHITE + f"📊 Confidence : {confidence}")
        print(Fore.RED + "=" * 60)

        # Save to DB
        insert_alert(machine_id, user_id, alert_level, alert_reason, confidence)

        print(Fore.GREEN + "[INFO] Alert inserted into database successfully")
    else:
        print(Fore.GREEN + "[INFO] No alert condition met")


if __name__ == "__main__":
    run_alert_engine()