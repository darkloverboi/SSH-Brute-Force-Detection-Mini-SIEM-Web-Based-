# ===============================
# SSH MINI SIEM DETECTOR ENGINE
# ===============================

import re  # For pattern matching
import json  # For structured logging
from datetime import datetime, timedelta
from collections import defaultdict

LOG_FILE = "sample_auth.log"
ALERT_FILE = "alerts.json"
EMAIL_LOG = "alert_email.log"

THRESHOLD = 5  # 5 attempts
TIME_WINDOW = 60  # Within 60 seconds

# Store failed attempts per IP with timestamps
failed_attempts = defaultdict(list)

# Regex pattern to extract timestamp + IP
pattern = r"Jan 10 (\d+:\d+:\d+).*Failed password for .* from (\d+\.\d+\.\d+\.\d+)"

# Clear previous alerts
open(ALERT_FILE, "w").close()

with open(LOG_FILE, "r") as file:
    for line in file:
        match = re.search(pattern, line)
        if match:
            time_str = match.group(1)
            ip = match.group(2)

            # Convert time string to datetime object
            log_time = datetime.strptime(time_str, "%H:%M:%S")

            # Store timestamp under IP
            failed_attempts[ip].append(log_time)

alerts = []

# Time-window detection logic
for ip, timestamps in failed_attempts.items():

    # Sort timestamps
    timestamps.sort()

    for i in range(len(timestamps)):
        window_start = timestamps[i]
        window_end = window_start + timedelta(seconds=TIME_WINDOW)

        # Count attempts within window
        count = sum(1 for t in timestamps if window_start <= t <= window_end)

        if count >= THRESHOLD:
            alert = {
                "timestamp": str(datetime.now()),
                "source_ip": ip,
                "attempts": count,
                "technique": "Brute Force",
                "mitre_id": "T1110"
            }

            alerts.append(alert)

            # Write to JSON alert file
            with open(ALERT_FILE, "a") as af:
                af.write(json.dumps(alert) + "\n")

            # Simulate email alert
            with open(EMAIL_LOG, "a") as ef:
                ef.write(f"Email Alert Sent for {ip} with {count} attempts\n")

            break  # Avoid duplicate alerts

print("Detection complete. Alerts generated if threshold met.")