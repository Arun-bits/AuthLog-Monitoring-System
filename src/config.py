DB_PATH = "database/auth_logs.db"

# Stream control (seconds)
STREAM_INTERVAL = 5

# Adaptive threshold parameters
BASELINE_WINDOW_DAYS = 7
STD_DEV_MULTIPLIER = 2

# Risk scoring weights
RISK_WEIGHTS = {
    "BRUTE_FORCE": 40,
    "PRIVILEGE_ABUSE": 25,
    "FAILURE_SUCCESS_PATTERN": 30,
    "AI_ANOMALY": 20
}

# Alert thresholds
HIGH_RISK_SCORE = 40
MEDIUM_RISK_SCORE = 25  

# Windows Event IDs to track
EVENT_ID_MAP = {
    4624: "LOGIN_SUCCESS",
    4625: "LOGIN_FAILURE",
    4740: "ACCOUNT_LOCKOUT",
    4720: "USER_CREATED",
    4726: "USER_DELETED",
    4672: "PRIVILEGE_CHECK"
}
