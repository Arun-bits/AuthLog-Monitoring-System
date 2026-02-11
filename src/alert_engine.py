from win10toast import ToastNotifier
from src.rule_engine import detect_three_failures_in_window
from src.risk_scoring import calculate_ml_risk_score

def run_alert_engine():
    print("[INFO] Alert engine started")

    failure_detected = detect_three_failures_in_window()
    risk_score = calculate_ml_risk_score()

    print("[INFO] Failure detected:", failure_detected)
    print("[INFO] Risk score:", risk_score)

    # 🔥 FINAL TRIGGER LOGIC
    if failure_detected or risk_score >= 60:
        toaster = ToastNotifier()
        toaster.show_toast(
            "⚠️ Security Alert",
            f"Suspicious authentication activity detected\n"
            f"Risk Score: {risk_score}",
            duration=8,
            threaded=True
        )
        print("[INFO] Alert triggered")
    else:
        print("[INFO] No alert condition met")

if __name__ == "__main__":
    run_alert_engine()