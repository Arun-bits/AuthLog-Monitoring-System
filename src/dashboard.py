import os
import sqlite3
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from streamlit_autorefresh import st_autorefresh

# =========================================================
# PAGE CONFIG
# =========================================================
st.set_page_config(
    page_title="AuthLog Security Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =========================================================
# AUTO REFRESH
# =========================================================
REFRESH_INTERVAL_MS = 30000
st_autorefresh(interval=REFRESH_INTERVAL_MS, key="authlog_dashboard_refresh")

# =========================================================
# DATABASE PATH
# =========================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "..", "database", "auth_logs.db")

# =========================================================
# CUSTOM CSS
# =========================================================
st.markdown("""
<style>
    .block-container {
        padding-top: 1.2rem;
        padding-bottom: 1rem;
    }

    .main-header {
        background: linear-gradient(135deg, #0b1220 0%, #111827 45%, #1f2937 100%);
        border: 1px solid rgba(255,255,255,0.08);
        padding: 1.5rem 1.8rem;
        border-radius: 20px;
        color: white;
        margin-bottom: 1.2rem;
        box-shadow: 0 10px 28px rgba(0,0,0,0.25);
    }

    .kpi-card {
        background: linear-gradient(135deg, #111827 0%, #1f2937 100%);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 18px;
        padding: 1rem 1rem;
        box-shadow: 0 6px 20px rgba(0,0,0,0.18);
        min-height: 140px;
    }

    .kpi-title {
        color: #94a3b8;
        font-size: 0.95rem;
        font-weight: 600;
        margin-bottom: 0.6rem;
    }

    .kpi-value {
        color: white;
        font-size: 2rem;
        font-weight: 800;
        line-height: 1;
        margin-bottom: 0.45rem;
    }

    .kpi-sub {
        color: #cbd5e1;
        font-size: 0.9rem;
    }

    .section-card {
        background: #0f172a;
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 18px;
        padding: 1rem 1rem 0.5rem 1rem;
        box-shadow: 0 6px 20px rgba(0,0,0,0.16);
        margin-bottom: 1rem;
    }

    .section-title {
        color: white;
        font-size: 1.15rem;
        font-weight: 700;
        margin-bottom: 0.8rem;
    }

    .alert-critical {
        background: linear-gradient(135deg, #7f1d1d 0%, #dc2626 100%);
        color: white;
        padding: 1rem;
        border-radius: 16px;
        margin-bottom: 0.8rem;
        border-left: 6px solid #fecaca;
    }

    .alert-high {
        background: linear-gradient(135deg, #9a3412 0%, #f97316 100%);
        color: white;
        padding: 1rem;
        border-radius: 16px;
        margin-bottom: 0.8rem;
        border-left: 6px solid #fed7aa;
    }

    .alert-medium {
        background: linear-gradient(135deg, #854d0e 0%, #eab308 100%);
        color: white;
        padding: 1rem;
        border-radius: 16px;
        margin-bottom: 0.8rem;
        border-left: 6px solid #fef08a;
    }

    .alert-low {
        background: linear-gradient(135deg, #14532d 0%, #22c55e 100%);
        color: white;
        padding: 1rem;
        border-radius: 16px;
        margin-bottom: 0.8rem;
        border-left: 6px solid #bbf7d0;
    }

    .small-note {
        color: #94a3b8;
        font-size: 0.85rem;
    }

    .status-ok {
        color: #22c55e;
        font-weight: 700;
    }

    .status-warn {
        color: #f59e0b;
        font-weight: 700;
    }

    .status-bad {
        color: #ef4444;
        font-weight: 700;
    }
</style>
""", unsafe_allow_html=True)

# =========================================================
# HELPERS
# =========================================================
def get_db_connection():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def map_time_range_to_hours(selection):
    mapping = {
        "Last 24 Hours": 24,
        "Last 7 Days": 24 * 7,
        "Last 30 Days": 24 * 30,
        "All Time": None
    }
    return mapping.get(selection, 24)

def classify_alert_type(reason):
    if pd.isna(reason):
        return "Unknown Alert"

    text = str(reason).lower()

    if "failed" in text or "failure" in text or "brute" in text:
        return "Brute Force / Failed Login"
    elif "privilege" in text or "escalation" in text:
        return "Privilege Abuse"
    elif "risk" in text or "ml" in text:
        return "ML Risk Detection"
    elif "suspicious" in text:
        return "Suspicious Activity"
    else:
        return "Security Alert"

def normalize_event_category(value):
    if pd.isna(value):
        return "UNKNOWN"

    v = str(value).strip().upper()

    if "FAIL" in v:
        return "LOGIN_FAILURE"
    elif "SUCCESS" in v or "LOGIN_SUCCESS" in v:
        return "LOGIN_SUCCESS"
    elif "PRIV" in v:
        return "PRIVILEGE_CHECK"
    elif "LOGOUT" in v:
        return "LOGOUT"
    else:
        return v

# =========================================================
# LOAD DATA
# =========================================================
@st.cache_data(ttl=20)
def load_data(time_range_hours=None):
    if not os.path.exists(DB_PATH):
        return pd.DataFrame(), pd.DataFrame()

    conn = get_db_connection()

    logs = pd.read_sql_query("SELECT * FROM auth_events ORDER BY event_time DESC", conn)
    alerts = pd.read_sql_query("SELECT * FROM alerts ORDER BY alert_time DESC", conn)

    conn.close()

    # -----------------------------
    # Normalize logs
    # -----------------------------
    if not logs.empty:
        if "event_time" in logs.columns:
            logs["event_time"] = pd.to_datetime(logs["event_time"], errors="coerce")

        if "event_category" in logs.columns:
            logs["event_category"] = logs["event_category"].apply(normalize_event_category)

        logs = logs.dropna(subset=["event_time"])

        if time_range_hours is not None:
            cutoff = datetime.now() - timedelta(hours=time_range_hours)
            logs = logs[logs["event_time"] >= cutoff]

    # -----------------------------
    # Normalize alerts
    # -----------------------------
    if not alerts.empty:
        alerts = alerts.rename(columns={
            "alert_time": "timestamp",
            "alert_level": "severity",
            "alert_reason": "description"
        })

        if "timestamp" in alerts.columns:
            alerts["timestamp"] = pd.to_datetime(alerts["timestamp"], errors="coerce")

        if "description" in alerts.columns:
            alerts["alert_type"] = alerts["description"].apply(classify_alert_type)
        else:
            alerts["alert_type"] = "Security Alert"

        if "severity" in alerts.columns:
            alerts["severity"] = alerts["severity"].astype(str).str.upper()

        alerts = alerts.dropna(subset=["timestamp"])

        if time_range_hours is not None:
            cutoff = datetime.now() - timedelta(hours=time_range_hours)
            alerts = alerts[alerts["timestamp"] >= cutoff]

    return logs, alerts

# =========================================================
# SIDEBAR FILTERS
# =========================================================
with st.sidebar:
    st.markdown("## ⚙️ Control Center")

    time_range = st.selectbox(
        "Select Time Range",
        ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"],
        index=0
    )

    severity_filter = st.multiselect(
        "Filter Alert Severity",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )

    auto_refresh_enabled = st.toggle("Live Auto Refresh", value=True)

    st.divider()

time_range_hours = map_time_range_to_hours(time_range)
logs, alerts = load_data(time_range_hours=time_range_hours)

# Build dynamic user filter AFTER loading data
all_users = []
if not logs.empty and "user_id" in logs.columns:
    all_users.extend(logs["user_id"].dropna().astype(str).unique().tolist())
if not alerts.empty and "user_id" in alerts.columns:
    all_users.extend(alerts["user_id"].dropna().astype(str).unique().tolist())

all_users = sorted(list(set(all_users)))

with st.sidebar:
    selected_users = st.multiselect(
        "Filter Users",
        options=all_users,
        default=[]
    )

    st.divider()

    # Status panel
    total_alerts_now = len(alerts)
    critical_now = len(alerts[alerts["severity"] == "CRITICAL"]) if not alerts.empty and "severity" in alerts.columns else 0
    high_now = len(alerts[alerts["severity"] == "HIGH"]) if not alerts.empty and "severity" in alerts.columns else 0

    if critical_now > 0:
        sys_status = "🔴 Critical"
        sys_class = "status-bad"
    elif high_now > 0:
        sys_status = "🟠 Elevated"
        sys_class = "status-warn"
    else:
        sys_status = "🟢 Stable"
        sys_class = "status-ok"

    st.markdown("### 🖥️ System Status")
    st.markdown(f"<p class='{sys_class}'>{sys_status}</p>", unsafe_allow_html=True)
    st.caption(f"DB Path: {DB_PATH}")
    st.caption(f"Last refresh: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# =========================================================
# APPLY FILTERS
# =========================================================
if not logs.empty and selected_users:
    logs = logs[logs["user_id"].astype(str).isin(selected_users)]

if not alerts.empty:
    if severity_filter:
        alerts = alerts[alerts["severity"].isin(severity_filter)]
    if selected_users:
        alerts = alerts[alerts["user_id"].astype(str).isin(selected_users)]

# =========================================================
# HEADER
# =========================================================
st.markdown(f"""
<div class="main-header">
    <h1 style="margin:0; display:flex; align-items:center; gap:10px;">
        <span>🛡️</span>
        <span>Authentication Security Intelligence Dashboard</span>
    </h1>
    <p style="margin-top:0.5rem; opacity:0.92; font-size:1.02rem;">
        Real-time monitoring, threat visibility, alert analytics, and authentication event intelligence
    </p>
</div>
""", unsafe_allow_html=True)

# =========================================================
# KPI METRICS
# =========================================================
total_events = len(logs)
failed_logins = len(logs[logs["event_category"] == "LOGIN_FAILURE"]) if not logs.empty else 0
success_logins = len(logs[logs["event_category"] == "LOGIN_SUCCESS"]) if not logs.empty else 0
priv_checks = len(logs[logs["event_category"] == "PRIVILEGE_CHECK"]) if not logs.empty else 0
active_alerts = len(alerts[alerts["severity"].isin(["CRITICAL", "HIGH"])]) if not alerts.empty else 0

success_rate = (
    (success_logins / (success_logins + failed_logins)) * 100
    if (success_logins + failed_logins) > 0 else 0
)

health_score = max(0, min(100, int(
    100
    - (failed_logins * 0.8)
    - (active_alerts * 8)
    - (priv_checks * 0.4)
)))
health_status = (
    "Secure" if health_score >= 85 else
    "Watchlist" if health_score >= 60 else
    "At Risk"
)

st.markdown("## 📊 Security Overview")

k1, k2, k3, k4, k5 = st.columns(5)

with k1:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Total Events</div>
        <div class="kpi-value">{total_events:,}</div>
        <div class="kpi-sub">Authentication records loaded</div>
    </div>
    """, unsafe_allow_html=True)

with k2:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Failed Logins</div>
        <div class="kpi-value">{failed_logins}</div>
        <div class="kpi-sub">Potential unauthorized attempts</div>
    </div>
    """, unsafe_allow_html=True)

with k3:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Active Threats</div>
        <div class="kpi-value">{active_alerts}</div>
        <div class="kpi-sub">Critical + High severity alerts</div>
    </div>
    """, unsafe_allow_html=True)

with k4:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">Login Success Rate</div>
        <div class="kpi-value">{success_rate:.1f}%</div>
        <div class="kpi-sub">{success_logins} successful login events</div>
    </div>
    """, unsafe_allow_html=True)

with k5:
    st.markdown(f"""
    <div class="kpi-card">
        <div class="kpi-title">System Health</div>
        <div class="kpi-value">{health_score}</div>
        <div class="kpi-sub">{health_status}</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# =========================================================
# TOP VISUALS
# =========================================================
left_col, right_col = st.columns([2, 1])

# -------------------------
# Authentication Timeline
# -------------------------
with left_col:
    st.markdown('<div class="section-card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">📈 Authentication Event Timeline</div>', unsafe_allow_html=True)

    if not logs.empty:
        timeline_df = logs.copy()
        timeline_df["hour_bucket"] = timeline_df["event_time"].dt.floor("H")
        timeline_counts = (
            timeline_df.groupby(["hour_bucket", "event_category"])
            .size()
            .reset_index(name="count")
        )

        fig_timeline = px.area(
            timeline_counts,
            x="hour_bucket",
            y="count",
            color="event_category",
            line_group="event_category",
            markers=True,
            title=""
        )

        fig_timeline.update_layout(
            template="plotly_dark",
            height=420,
            xaxis_title="Time",
            yaxis_title="Event Count",
            legend_title="Event Category",
            margin=dict(l=10, r=10, t=10, b=10)
        )

        st.plotly_chart(fig_timeline, use_container_width=True)
    else:
        st.info("No authentication event data available.")
    st.markdown('</div>', unsafe_allow_html=True)

# -------------------------
# Event Distribution
# -------------------------
with right_col:
    st.markdown('<div class="section-card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">🎯 Event Distribution</div>', unsafe_allow_html=True)

    if not logs.empty:
        event_counts = logs["event_category"].value_counts().reset_index()
        event_counts.columns = ["event_category", "count"]

        fig_pie = px.pie(
            event_counts,
            names="event_category",
            values="count",
            hole=0.55
        )

        fig_pie.update_layout(
            template="plotly_dark",
            height=420,
            margin=dict(l=10, r=10, t=10, b=10),
            showlegend=True
        )

        st.plotly_chart(fig_pie, use_container_width=True)
    else:
        st.info("No event distribution available.")
    st.markdown('</div>', unsafe_allow_html=True)

# =========================================================
# SECOND ROW
# =========================================================
col_a, col_b = st.columns([1, 1])

# -------------------------
# Alert Severity Breakdown
# -------------------------
with col_a:
    st.markdown('<div class="section-card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">🚨 Alert Severity Breakdown</div>', unsafe_allow_html=True)

    if not alerts.empty:
        sev_counts = alerts["severity"].value_counts().reset_index()
        sev_counts.columns = ["severity", "count"]

        fig_alerts = px.bar(
            sev_counts,
            x="severity",
            y="count",
            color="severity",
            text="count"
        )

        fig_alerts.update_layout(
            template="plotly_dark",
            height=380,
            margin=dict(l=10, r=10, t=10, b=10),
            xaxis_title="Severity",
            yaxis_title="Alert Count"
        )

        st.plotly_chart(fig_alerts, use_container_width=True)
    else:
        st.info("No alert records available.")
    st.markdown('</div>', unsafe_allow_html=True)

# -------------------------
# Suspicious Users Leaderboard
# -------------------------
with col_b:
    st.markdown('<div class="section-card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">👤 Suspicious User Leaderboard</div>', unsafe_allow_html=True)

    if not logs.empty and "user_id" in logs.columns:
        user_risk = logs.groupby("user_id").agg(
            total_attempts=("event_category", "count"),
            failures=("event_category", lambda x: (x == "LOGIN_FAILURE").sum()),
            successes=("event_category", lambda x: (x == "LOGIN_SUCCESS").sum()),
            privilege_checks=("event_category", lambda x: (x == "PRIVILEGE_CHECK").sum()),
            last_active=("event_time", "max")
        ).reset_index()

        user_risk["failure_rate"] = (
            user_risk["failures"] / user_risk["total_attempts"] * 100
        ).fillna(0).round(2)

        user_risk["risk_score"] = (
            user_risk["failures"] * 8
            + user_risk["privilege_checks"] * 6
            + (user_risk["failure_rate"] * 0.6)
        ).round(1)

        top_risk = user_risk.sort_values("risk_score", ascending=False).head(10)

        fig_users = px.bar(
            top_risk,
            x="user_id",
            y="risk_score",
            color="risk_score",
            text="risk_score"
        )

        fig_users.update_layout(
            template="plotly_dark",
            height=380,
            margin=dict(l=10, r=10, t=10, b=10),
            xaxis_title="User",
            yaxis_title="Risk Score"
        )

        st.plotly_chart(fig_users, use_container_width=True)
    else:
        st.info("No user activity available.")
    st.markdown('</div>', unsafe_allow_html=True)

# =========================================================
# ALERT FEED
# =========================================================
st.markdown("## 🚨 Live Security Alert Feed")

if not alerts.empty:
    latest_alerts = alerts.sort_values("timestamp", ascending=False).head(8)

    for _, alert in latest_alerts.iterrows():
        severity = str(alert.get("severity", "LOW")).upper()

        if severity == "CRITICAL":
            card_class = "alert-critical"
            icon = "🔴"
        elif severity == "HIGH":
            card_class = "alert-high"
            icon = "🟠"
        elif severity == "MEDIUM":
            card_class = "alert-medium"
            icon = "🟡"
        else:
            card_class = "alert-low"
            icon = "🟢"

        timestamp_text = alert.get("timestamp", "")
        if pd.notna(timestamp_text):
            timestamp_text = pd.to_datetime(timestamp_text).strftime("%Y-%m-%d %H:%M:%S")

        st.markdown(f"""
        <div class="{card_class}">
            <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
                <div>
                    <div style="font-size:1.05rem; font-weight:800;">{icon} {alert.get("alert_type", "Security Alert")}</div>
                    <div style="opacity:0.92; font-size:0.92rem;">
                        User: <b>{alert.get("user_id", "Unknown")}</b> &nbsp; | &nbsp;
                        Machine: <b>{alert.get("machine_id", "Unknown")}</b>
                    </div>
                </div>
                <div style="text-align:right;">
                    <div style="font-weight:800;">{severity}</div>
                    <div style="font-size:0.85rem;">{timestamp_text}</div>
                </div>
            </div>
            <div style="margin-top:0.8rem; font-size:0.96rem;">
                {alert.get("description", "No description")}
            </div>
            <div style="margin-top:0.5rem; font-size:0.85rem; opacity:0.95;">
                Confidence: <b>{alert.get("confidence", "N/A")}</b>
            </div>
        </div>
        """, unsafe_allow_html=True)
else:
    st.success("No alerts found for the selected filters and time range.")

st.divider()

# =========================================================
# USER ANALYTICS + HEATMAP
# =========================================================
ua_col1, ua_col2 = st.columns([1.2, 1])

# -------------------------
# User Behavior Table
# -------------------------
with ua_col1:
    st.markdown('<div class="section-card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">👥 User Behavior Analytics</div>', unsafe_allow_html=True)

    if not logs.empty and "user_id" in logs.columns:
        user_profile = logs.groupby("user_id").agg(
            total_attempts=("event_category", "count"),
            failures=("event_category", lambda x: (x == "LOGIN_FAILURE").sum()),
            successes=("event_category", lambda x: (x == "LOGIN_SUCCESS").sum()),
            privilege_checks=("event_category", lambda x: (x == "PRIVILEGE_CHECK").sum()),
            last_active=("event_time", "max")
        ).reset_index()

        user_profile["failure_rate"] = (
            user_profile["failures"] / user_profile["total_attempts"] * 100
        ).fillna(0).round(2)

        user_profile["success_rate"] = (
            user_profile["successes"] / user_profile["total_attempts"] * 100
        ).fillna(0).round(2)

        user_profile["risk_score"] = (
            user_profile["failures"] * 8
            + user_profile["privilege_checks"] * 6
            + user_profile["failure_rate"] * 0.6
        ).round(1)

        user_profile = user_profile.sort_values("risk_score", ascending=False)

        st.dataframe(user_profile, use_container_width=True, height=360)

        csv_user = user_profile.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Download User Analytics CSV",
            data=csv_user,
            file_name="user_behavior_analytics.csv",
            mime="text/csv"
        )
    else:
        st.info("No user analytics data available.")
    st.markdown('</div>', unsafe_allow_html=True)

# -------------------------
# Login Activity Heatmap
# -------------------------
with ua_col2:
    st.markdown('<div class="section-card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">🕒 Hourly Login Activity Heatmap</div>', unsafe_allow_html=True)

    if not logs.empty:
        heatmap_df = logs.copy()
        heatmap_df["hour"] = heatmap_df["event_time"].dt.hour
        heatmap_df["day"] = heatmap_df["event_time"].dt.day_name()

        day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        heatmap_df["day"] = pd.Categorical(heatmap_df["day"], categories=day_order, ordered=True)

        heat = heatmap_df.groupby(["day", "hour"]).size().reset_index(name="count")

        fig_heat = px.density_heatmap(
            heat,
            x="hour",
            y="day",
            z="count",
            text_auto=True
        )

        fig_heat.update_layout(
            template="plotly_dark",
            height=400,
            margin=dict(l=10, r=10, t=10, b=10),
            xaxis_title="Hour of Day",
            yaxis_title="Day"
        )

        st.plotly_chart(fig_heat, use_container_width=True)
    else:
        st.info("No heatmap data available.")
    st.markdown('</div>', unsafe_allow_html=True)

# =========================================================
# RECENT ALERTS TABLE + RECENT EVENTS
# =========================================================
t1, t2 = st.columns([1, 1])

with t1:
    st.markdown('<div class="section-card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">📋 Recent Alerts Table</div>', unsafe_allow_html=True)

    if not alerts.empty:
        alert_table = alerts[[
            "timestamp", "severity", "user_id", "machine_id", "alert_type", "description", "confidence"
        ]].sort_values("timestamp", ascending=False).head(20)

        st.dataframe(alert_table, use_container_width=True, height=350)

        csv_alerts = alert_table.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Download Alerts CSV",
            data=csv_alerts,
            file_name="security_alerts.csv",
            mime="text/csv"
        )
    else:
        st.info("No alert table data available.")
    st.markdown('</div>', unsafe_allow_html=True)

with t2:
    st.markdown('<div class="section-card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">📡 Recent Authentication Event Stream</div>', unsafe_allow_html=True)

    if not logs.empty:
        event_stream = logs[[
            "event_time", "machine_id", "user_id", "event_id", "event_category"
        ]].sort_values("event_time", ascending=False).head(25)

        st.dataframe(event_stream, use_container_width=True, height=350)

        csv_logs = event_stream.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Download Event Stream CSV",
            data=csv_logs,
            file_name="auth_event_stream.csv",
            mime="text/csv"
        )
    else:
        st.info("No recent event stream available.")
    st.markdown('</div>', unsafe_allow_html=True)

# =========================================================
# FOOTER
# =========================================================
st.divider()

f1, f2, f3, f4 = st.columns(4)

with f1:
    st.caption("🔄 Auto-refresh")
    st.caption("Every 30 seconds")

with f2:
    st.caption("🛡️ Dashboard Version")
    st.caption("AuthLog SOC v1.0")

with f3:
    st.caption("📅 Time Range")
    st.caption(time_range)

with f4:
    st.caption("🕒 Last Rendered")
    st.caption(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))