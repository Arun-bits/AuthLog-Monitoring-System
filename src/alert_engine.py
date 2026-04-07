import sqlite3
from datetime import datetime
from colorama import Fore, Style, init

from src.rule_engine import detect_three_failures_in_window
from src.risk_scoring import calculate_ml_risk_score
from src.config import DB_PATH

# Initialize terminal colors
init(autoreset=True)


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
    Show desktop popup notification safely using plyer
    """
    try:
        from plyer import notification

        notification.notify(
            title=title,
            message=message,
            timeout=8,
            app_name="AuthLog Security Monitor"
        )
        print(Fore.GREEN + "[INFO] Popup notification shown successfully")

    except Exception as e:
        print(Fore.RED + f"[WARNING] Popup notification failed: {e}")


def run_alert_engine():
    print(Fore.CYAN + "\n[INFO] Alert engine started")

    failure_result = detect_three_failures_in_window()
    risk_score = calculate_ml_risk_score()

    failure_detected = failure_result["detected"]
    user_id = failure_result["user_id"] if failure_result["user_id"] else "UNKNOWN_USER"
    machine_id = failure_result["machine_id"] if failure_result["machine_id"] else "UNKNOWN_MACHINE"
    failure_count = failure_result["failure_count"]

    print(Fore.YELLOW + f"[INFO] Failure detected: {failure_detected}")
    print(Fore.YELLOW + f"[INFO] Risk score: {risk_score}")

    alert_triggered = False
    alert_level = "LOW"
    alert_reason = "Normal authentication behavior"
    confidence = f"{risk_score}%"

    if failure_detected and risk_score >= 80:
        alert_level = "CRITICAL"
        alert_reason = f"{failure_count} failed logins + very high ML risk score"
        alert_triggered = True

    elif failure_detected and risk_score >= 60:
        alert_level = "HIGH"
        alert_reason = f"{failure_count} failed logins + suspicious ML behavior"
        alert_triggered = True

    elif failure_detected:
        alert_level = "MEDIUM"
        alert_reason = f"{failure_count} failed login attempts detected in short time window"
        alert_triggered = True

    elif risk_score >= 60:
        alert_level = "HIGH"
        alert_reason = "High ML risk score detected"
        alert_triggered = True

    if alert_triggered:
        print(Fore.RED + Style.BRIGHT + "\n" + "=" * 68)
        print(Fore.RED + Style.BRIGHT + "⚠️ SECURITY ALERT TRIGGERED")
        print(Fore.RED + Style.BRIGHT + "=" * 68)
        print(Fore.WHITE + f"🕒 Time       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(Fore.WHITE + f"👤 User       : {user_id}")
        print(Fore.WHITE + f"💻 Machine    : {machine_id}")
        print(Fore.WHITE + f"🚨 Level      : {alert_level}")
        print(Fore.WHITE + f"📌 Reason     : {alert_reason}")
        print(Fore.WHITE + f"📊 Confidence : {confidence}")
        print(Fore.RED + "=" * 68)

        insert_alert(machine_id, user_id, alert_level, alert_reason, confidence)
        print(Fore.GREEN + "[INFO] Alert inserted into database successfully")

        popup_message = (
            f"User: {user_id}\n"
            f"Machine: {machine_id}\n"
            f"Level: {alert_level}\n"
            f"Risk Score: {risk_score}"
        )
        show_popup("⚠️ Security Alert", popup_message)

    else:
        print(Fore.GREEN + "[INFO] No alert condition met")


if __name__ == "__main__":
    run_alert_engine()