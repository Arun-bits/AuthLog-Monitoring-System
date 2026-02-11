# src/dashboard.py

import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import numpy as np
from streamlit_autorefresh import st_autorefresh

# Set page config - MUST be first Streamlit command
st.set_page_config(
    page_title="AuthLog Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Auto-refresh every 30 seconds
st_autorefresh(interval=30000, key="dashboard_refresh")

# Custom CSS for better styling
st.markdown("""
<style>
    /* Main styling */
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 10px;
        color: white;
        margin-bottom: 2rem;
    }
    
    .metric-card {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        border-left: 4px solid #667eea;
        transition: transform 0.3s ease;
    }
    
    .metric-card:hover {
        transform: translateY(-5px);
    }
    
    .alert-card {
        background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 0.5rem;
    }
    
    .success-card {
        background: linear-gradient(135deg, #20bf6b 0%, #26de81 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 0.5rem;
    }
    
    .warning-card {
        background: linear-gradient(135deg, #f7b731 0%, #fa8231 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin-bottom: 0.5rem;
    }
    
    /* Chart containers */
    .chart-container {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        margin-bottom: 1.5rem;
    }
    
    /* Sidebar */
    .sidebar-header {
        font-size: 1.5rem;
        font-weight: bold;
        color: #667eea;
        margin-bottom: 1rem;
    }
    
    /* DataTables */
    .dataframe {
        width: 100%;
    }
    
    /* Status indicators */
    .status-dot {
        height: 10px;
        width: 10px;
        border-radius: 50%;
        display: inline-block;
        margin-right: 5px;
    }
    
    .status-critical { background-color: #ff4757; }
    .status-high { background-color: #ffa502; }
    .status-medium { background-color: #ffd32a; }
    .status-low { background-color: #2ed573; }
    
    /* Animations */
    @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.05); }
        100% { transform: scale(1); }
    }
    
    .pulse {
        animation: pulse 2s infinite;
    }
</style>
""", unsafe_allow_html=True)

DB_PATH = "database/auth_logs.db"

# ===============================
# SIDEBAR - Filters & Controls
# ===============================
with st.sidebar:
    st.markdown('<div class="sidebar-header">⚙️ Dashboard Controls</div>', unsafe_allow_html=True)
    
    # Time Range Filter
    st.subheader("Time Range")
    time_range = st.selectbox(
        "Select Time Range",
        ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"],
        index=0
    )
    
    # Severity Filter
    st.subheader("Alert Severity")
    severities = st.multiselect(
        "Filter Alerts by Severity",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH"]
    )
    
    # User Filter
    st.subheader("User Filter")
    show_users = st.multiselect(
        "Select Users to Display",
        ["All Users"]  # Will be populated with actual users
    )
    
    # Auto-refresh toggle
    st.subheader("Settings")
    auto_refresh = st.toggle("Live Auto-Refresh", value=True)
    
    st.divider()
    
    # System Status
    st.markdown("### 🖥️ System Status")
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Database", "✅ Online", delta=None)
    with col2:
        st.metric("API", "✅ Online", delta=None)
    
    # Last Updated
    st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# ===============================
# HEADER - Main Title
# ===============================
st.markdown("""
<div class="main-header">
    <h1 style="margin:0; display:flex; align-items:center; gap:10px;">
        <span>🛡️</span>
        <span>Authentication Security Intelligence Dashboard</span>
    </h1>
    <p style="margin:0; opacity:0.9; font-size:1.1rem;">
        Real-time monitoring & threat detection for authentication events
    </p>
</div>
""", unsafe_allow_html=True)

# ===============================
# LOAD DATA
# ===============================
@st.cache_data(ttl=30)
def load_data():
    conn = sqlite3.connect(DB_PATH)
    
    # Load logs with timestamp filtering based on sidebar selection
    logs_query = "SELECT * FROM auth_events"
    logs = pd.read_sql_query(logs_query, conn)
    
    if not logs.empty and 'event_time' in logs.columns:
        logs['event_time'] = pd.to_datetime(logs['event_time'])
    
    alerts = pd.read_sql_query("SELECT * FROM alerts", conn)
    
    # Add simulated data for demonstration if tables are empty
    if logs.empty:
        logs = pd.DataFrame({
            'event_time': pd.date_range(end=datetime.now(), periods=100, freq='H'),
            'user_id': np.random.choice(['user1', 'user2', 'user3', 'admin', 'guest'], 100),
            'event_category': np.random.choice(['LOGIN_SUCCESS', 'LOGIN_FAILURE', 'PRIVILEGE_CHECK', 'LOGOUT'], 100, p=[0.6, 0.2, 0.15, 0.05]),
            'ip_address': np.random.choice(['192.168.1.1', '10.0.0.1', '172.16.0.1'], 100),
            'details': ['Sample event'] * 100
        })
    
    if alerts.empty:
        alerts = pd.DataFrame({
            'timestamp': pd.date_range(end=datetime.now(), periods=5, freq='D'),
            'alert_type': ['Brute Force Attempt', 'Privilege Escalation', 'Suspicious Login', 'Multiple Failures', 'Geo-Anomaly'],
            'severity': ['CRITICAL', 'HIGH', 'MEDIUM', 'HIGH', 'MEDIUM'],
            'user_id': ['admin', 'user1', 'user2', 'user3', 'guest'],
            'description': ['10 failed attempts in 5 minutes', 'Unauthorized privilege access', 'Login from new location', 'Multiple failed logins', 'Login from unusual country']
        })
    
    conn.close()
    return logs, alerts

logs, alerts = load_data()

# ===============================
# TOP METRICS ROW
# ===============================
st.markdown("## 📊 Security Overview")

col1, col2, col3, col4 = st.columns(4)

# Calculate metrics
total_events = len(logs)
failed_logins = len(logs[logs["event_category"] == "LOGIN_FAILURE"])
success_logins = len(logs[logs["event_category"] == "LOGIN_SUCCESS"])
priv_checks = len(logs[logs["event_category"] == "PRIVILEGE_CHECK"])
active_alerts = len(alerts[alerts['severity'].isin(['CRITICAL', 'HIGH'])])

with col1:
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.metric(
        label="Total Events",
        value=f"{total_events:,}",
        delta=f"{(total_events - 1000):+,}" if total_events > 1000 else None
    )
    st.caption("Last 30 days")
    st.markdown('</div>', unsafe_allow_html=True)

with col2:
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.metric(
        label="Failed Logins",
        value=failed_logins,
        delta=f"-{failed_logins * 0.1:.0f}" if failed_logins > 0 else None,
        delta_color="inverse"
    )
    st.caption(f"{(failed_logins/total_events*100):.1f}% of total")
    st.markdown('</div>', unsafe_allow_html=True)

with col3:
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.metric(
        label="Active Threats",
        value=active_alerts,
        delta=f"+{active_alerts}" if active_alerts > 0 else None,
        delta_color="inverse"
    )
    st.caption("Critical & High severity")
    st.markdown('</div>', unsafe_allow_html=True)

with col4:
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    success_rate = (success_logins/(success_logins+failed_logins)*100) if (success_logins+failed_logins) > 0 else 0
    st.metric(
        label="Success Rate",
        value=f"{success_rate:.1f}%",
        delta=f"+{success_rate*0.01:.1f}%" if success_rate > 95 else None
    )
    st.caption(f"{success_logins} successful logins")
    st.markdown('</div>', unsafe_allow_html=True)

st.divider()

# ===============================
# CHARTS ROW
# ===============================
col_left, col_right = st.columns([2, 1])

with col_left:
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    st.markdown("### 📈 Authentication Events Timeline")
    
    if not logs.empty and 'event_time' in logs.columns:
        # Prepare time series data
        logs['hour'] = logs['event_time'].dt.floor('H')
        timeline_data = logs.groupby(['hour', 'event_category']).size().unstack(fill_value=0)
        
        # Create Plotly figure
        fig = go.Figure()
        
        colors = {
            'LOGIN_SUCCESS': '#2ed573',
            'LOGIN_FAILURE': '#ff4757',
            'PRIVILEGE_CHECK': '#ffa502',
            'LOGOUT': '#70a1ff'
        }
        
        for category in timeline_data.columns:
            if category in colors:
                fig.add_trace(go.Scatter(
                    x=timeline_data.index,
                    y=timeline_data[category],
                    name=category.replace('_', ' ').title(),
                    line=dict(color=colors[category], width=3),
                    stackgroup='one',
                    mode='lines'
                ))
        
        fig.update_layout(
            height=400,
            hovermode='x unified',
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            )
        )
        
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No timeline data available")
    st.markdown('</div>', unsafe_allow_html=True)

with col_right:
    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
    st.markdown("### 🎯 Event Distribution")
    
    if not logs.empty:
        # Event distribution pie chart
        event_counts = logs['event_category'].value_counts()
        
        fig_pie = px.pie(
            values=event_counts.values,
            names=event_counts.index,
            hole=0.4,
            color_discrete_sequence=px.colors.qualitative.Set3
        )
        
        fig_pie.update_traces(
            textposition='inside',
            textinfo='percent+label',
            hovertemplate="<b>%{label}</b><br>Count: %{value}<extra></extra>"
        )
        
        fig_pie.update_layout(
            height=400,
            showlegend=False,
            margin=dict(t=0, b=0, l=0, r=0)
        )
        
        st.plotly_chart(fig_pie, use_container_width=True)
    else:
        st.info("No distribution data available")
    st.markdown('</div>', unsafe_allow_html=True)

# ===============================
# ALERTS SECTION
# ===============================
st.markdown("## 🚨 Real-time Security Alerts")

if not alerts.empty:
    # Filter alerts based on sidebar selection
    filtered_alerts = alerts[alerts['severity'].isin(severities)] if severities else alerts
    
    # Display alerts in cards
    for _, alert in filtered_alerts.iterrows():
        severity = alert.get('severity', 'MEDIUM')
        
        if severity == 'CRITICAL':
            alert_class = "alert-card pulse"
            icon = "🔴"
        elif severity == 'HIGH':
            alert_class = "alert-card"
            icon = "🟠"
        elif severity == 'MEDIUM':
            alert_class = "warning-card"
            icon = "🟡"
        else:
            alert_class = "success-card"
            icon = "🟢"
        
        st.markdown(f"""
        <div class="{alert_class}">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <strong>{icon} {alert.get('alert_type', 'Alert')}</strong>
                    <br>
                    <small>User: {alert.get('user_id', 'Unknown')} | {alert.get('timestamp', '')}</small>
                </div>
                <span class="status-dot status-{severity.lower()}"></span>
                <strong>{severity}</strong>
            </div>
            <p style="margin: 0.5rem 0 0 0;">{alert.get('description', 'No description')}</p>
        </div>
        """, unsafe_allow_html=True)
else:
    st.success("🎉 No active security alerts. System is secure.")

st.divider()

# ===============================
# USER BEHAVIOR PROFILES
# ===============================
st.markdown("## 👥 User Behavior Analytics")

if not logs.empty:
    # Calculate user metrics
    user_profile = logs.groupby("user_id").agg(
        total_attempts=("event_category", "count"),
        failures=("event_category", lambda x: (x == "LOGIN_FAILURE").sum()),
        successes=("event_category", lambda x: (x == "LOGIN_SUCCESS").sum()),
        privilege_checks=("event_category", lambda x: (x == "PRIVILEGE_CHECK").sum()),
        last_active=("event_time", "max")
    ).reset_index()

    user_profile["failure_rate"] = (user_profile["failures"] / user_profile["total_attempts"] * 100).round(1)
    user_profile["success_rate"] = (user_profile["successes"] / user_profile["total_attempts"] * 100).round(1)
    user_profile["risk_score"] = (user_profile["failure_rate"] * 0.7 + 
                                  user_profile["privilege_checks"] * 0.3).round(1)

    # Sort by risk score
    user_profile = user_profile.sort_values("risk_score", ascending=False)

    # Display user profiles
    tab1, tab2, tab3 = st.tabs(["📋 User Table", "📊 Risk Analysis", "🌍 Geolocation"])

    with tab1:
        st.dataframe(
            user_profile.style.background_gradient(subset=['risk_score'], cmap='RdYlGn_r'),
            use_container_width=True,
            height=400
        )

    with tab2:
        col1, col2 = st.columns(2)
        
        with col1:
            # Risk distribution bar chart
            fig_risk = px.bar(
                user_profile.head(10),
                x='user_id',
                y='risk_score',
                color='risk_score',
                color_continuous_scale='RdYlGn_r',
                title="Top 10 Users by Risk Score"
            )
            st.plotly_chart(fig_risk, use_container_width=True)
        
        with col2:
            # Success vs Failure scatter
            fig_scatter = px.scatter(
                user_profile,
                x='success_rate',
                y='failure_rate',
                size='total_attempts',
                color='risk_score',
                hover_name='user_id',
                title="Success vs Failure Rates",
                color_continuous_scale='RdYlGn_r'
            )
            st.plotly_chart(fig_scatter, use_container_width=True)

    with tab3:
        # Simulated geolocation data
        geo_data = pd.DataFrame({
            'country': ['USA', 'Germany', 'Japan', 'India', 'Brazil', 'Australia'],
            'login_attempts': [45, 28, 19, 32, 15, 12],
            'failed_logins': [12, 4, 2, 8, 3, 1]
        })
        
        fig_map = px.choropleth(
            geo_data,
            locations='country',
            locationmode='country names',
            color='failed_logins',
            hover_name='country',
            color_continuous_scale='RdYlGn_r',
            title="Failed Logins by Country"
        )
        st.plotly_chart(fig_map, use_container_width=True)

else:
    st.info("No user behavior data available")

# ===============================
# FOOTER
# ===============================
st.divider()
footer_col1, footer_col2, footer_col3 = st.columns(3)

with footer_col1:
    st.caption("🔄 Data refreshes every 30 seconds")
    st.caption(f"Total records: {total_events:,}")

with footer_col2:
    st.caption("🛡️ Security Dashboard v2.0")
    st.caption("Powered by Streamlit & Plotly")

with footer_col3:
    st.caption("📅 Last data update")
    st.caption(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# ===============================
# SYSTEM STATUS INDICATOR
# ===============================
status_emoji = "🟢" if active_alerts == 0 else "🟠" if active_alerts < 3 else "🔴"
status_text = "All Systems Normal" if active_alerts == 0 else f"{active_alerts} Active Alerts"

st.sidebar.markdown("---")
st.sidebar.markdown(f"### {status_emoji} System Status")
st.sidebar.info(status_text)