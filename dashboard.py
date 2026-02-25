# ============================================================
# SSH MINI SIEM - ADVANCED SOC VERSION
# Features:
# - Default + Upload logs
# - Severity scoring
# - Timeline graph
# - Raw log viewer
# - Auto refresh
# ============================================================

import streamlit as st
import re
import json
from datetime import datetime, timedelta
from collections import defaultdict
import pandas as pd
import time

# ------------------------------------------------------------
# PAGE CONFIGURATION
# ------------------------------------------------------------

st.set_page_config(page_title="SSH Mini SIEM", layout="wide")

st.title("🔐 SSH Brute Force Detection - Advanced Mini SIEM")

st.write("Real-time log analysis with severity scoring and attack visualization.")


# ------------------------------------------------------------
# AUTO REFRESH OPTION
# ------------------------------------------------------------

auto_refresh = st.checkbox("Enable Auto Refresh (every 10 seconds)")

if auto_refresh:
    time.sleep(10)
    st.rerun()


# ------------------------------------------------------------
# DETECTION CONFIGURATION
# ------------------------------------------------------------

THRESHOLD = 5
TIME_WINDOW = 60


# ------------------------------------------------------------
# FILE UPLOAD OPTION
# ------------------------------------------------------------

uploaded_file = st.file_uploader(
    "Optional: Upload auth.log file",
    type=["log", "txt"]
)


# ------------------------------------------------------------
# LOAD LOG SOURCE
# ------------------------------------------------------------

if uploaded_file is not None:
    st.success("Using uploaded log file.")
    content = uploaded_file.read().decode("utf-8")
else:
    st.info("Using default sample_auth.log")
    with open("sample_auth.log", "r") as file:
        content = file.read()

lines = content.split("\n")


# ------------------------------------------------------------
# RAW LOG VIEWER PANEL
# ------------------------------------------------------------

with st.expander("📜 View Raw Logs"):
    st.text(content)


# ------------------------------------------------------------
# LOG PARSING
# ------------------------------------------------------------

failed_attempts = defaultdict(list)

pattern = r"(\d+:\d+:\d+).*Failed password for .* from (\d+\.\d+\.\d+\.\d+)"

for line in lines:
    match = re.search(pattern, line)
    if match:
        time_str = match.group(1)
        ip = match.group(2)

        try:
            log_time = datetime.strptime(time_str, "%H:%M:%S")
            failed_attempts[ip].append(log_time)
        except:
            continue


# ------------------------------------------------------------
# DETECTION ENGINE WITH SEVERITY
# ------------------------------------------------------------

alerts = []
timeline_data = []

for ip, timestamps in failed_attempts.items():
    timestamps.sort()

    for i in range(len(timestamps)):
        window_start = timestamps[i]
        window_end = window_start + timedelta(seconds=TIME_WINDOW)

        count = sum(1 for t in timestamps if window_start <= t <= window_end)

        if count >= THRESHOLD:

            # Severity Scoring Logic
            if count >= 10:
                severity = "High"
            elif count >= 7:
                severity = "Medium"
            else:
                severity = "Low"

            alert = {
                "Detected At": str(datetime.now()),
                "Source IP": ip,
                "Failed Attempts": count,
                "Severity": severity,
                "MITRE Technique": "T1110 - Brute Force"
            }

            alerts.append(alert)

            # Add timeline record
            timeline_data.append({
                "Time": window_start,
                "Attempts": count
            })

            break


# ------------------------------------------------------------
# DASHBOARD OUTPUT
# ------------------------------------------------------------

st.subheader("📊 Analysis Summary")

col1, col2 = st.columns(2)

col1.metric("Unique Source IPs", len(failed_attempts))
col2.metric("Detected Threats", len(alerts))


# ------------------------------------------------------------
# ALERT DISPLAY
# ------------------------------------------------------------

if alerts:

    df = pd.DataFrame(alerts)

    st.subheader("🚨 Alert Details")
    st.dataframe(df)

    st.subheader("📈 Attack Distribution by IP")
    st.bar_chart(df["Source IP"].value_counts())

    # Timeline Graph
    if timeline_data:
        timeline_df = pd.DataFrame(timeline_data)
        timeline_df = timeline_df.set_index("Time")

        st.subheader("⏳ Attack Timeline (Attempts Over Time)")
        st.line_chart(timeline_df)

    # Severity breakdown pie chart
    severity_counts = df["Severity"].value_counts()
    st.subheader("🛑 Severity Distribution")
    st.bar_chart(severity_counts)

    st.download_button(
        label="Download Alert Report (JSON)",
        data=json.dumps(alerts, indent=4),
        file_name="alert_report.json",
        mime="application/json"
    )

else:
    st.success("✅ No brute force activity detected.")