import sqlite3
from datetime import datetime
from colorama import Fore, Style, init

from src.rule_engine import detect_three_failures_in_window
from src.risk_scoring import calculate_ml_risk_score
from src.config import DB_PATH

# Initialize colorama
init(autoreset=True)

# Try importing popup notifier safely
try:
    from win10toast import ToastNotifier
    TOAST_AVAILABLE = True
except ImportError:
    TOAST_AVAILABLE = False


def insert_alert(machine_id, user_id, alert_level, alert_reason, confidence):
    """
    Insert alert into alerts table
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


def show_popup(title, message):
    """
    Show Windows popup notification if available
    """
    if TOAST_AVAILABLE:
        try:
            toaster = ToastNotifier()
            toaster.show_toast(
                title,
                message,
                duration=8,
                threaded=True
            )
            print(Fore.GREEN + "[INFO] Popup notification shown successfully")
        except Exception as e:
            print(Fore.RED + f"[WARNING] Popup notification failed: {e}")
    else:
        print(Fore.YELLOW + "[WARNING] win10toast not installed. Popup skipped.")


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

    # You can improve later by fetching actual suspicious user/machine
    machine_id = "UNKNOWN_MACHINE"
    user_id = "UNKNOWN_USER"

    # ===============================
    # ALERT DECISION LOGIC
    # ===============================
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

    # ===============================
    # ALERT ACTIONS
    # ===============================
    if alert_triggered:
        print(Fore.RED + Style.BRIGHT + "\n" + "=" * 65)
        print(Fore.RED + Style.BRIGHT + "⚠️ SECURITY ALERT TRIGGERED")
        print(Fore.RED + Style.BRIGHT + "=" * 65)
        print(Fore.WHITE + f"🕒 Time       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(Fore.WHITE + f"👤 User       : {user_id}")
        print(Fore.WHITE + f"💻 Machine    : {machine_id}")
        print(Fore.WHITE + f"🚨 Level      : {alert_level}")
        print(Fore.WHITE + f"📌 Reason     : {alert_reason}")
        print(Fore.WHITE + f"📊 Confidence : {confidence}")
        print(Fore.RED + "=" * 65)

        # 1️⃣ Save to DB
        insert_alert(machine_id, user_id, alert_level, alert_reason, confidence)
        print(Fore.GREEN + "[INFO] Alert inserted into database successfully")

        # 2️⃣ Show popup notification
        popup_message = (
            f"Level: {alert_level}\n"
            f"Reason: {alert_reason}\n"
            f"Risk Score: {risk_score}"
        )
        show_popup("⚠️ Security Alert", popup_message)

    else:
        print(Fore.GREEN + "[INFO] No alert condition met")


if __name__ == "__main__":
    run_alert_engine()