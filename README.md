# SSH Brute Force Detection – Mini SIEM (Web-Based)

A lightweight SOC-style detection system that analyzes Linux SSH authentication logs to detect brute-force attacks using rolling time-window logic.

This project simulates core detection engineering workflows used in enterprise SIEM platforms.

This project is deployed on Streamlit Cloud for demonstration purposes. For development use or full control, it is recommended to run the application locally

webview : https://cyberminisiem.streamlit.app/
---

<img width="1272" height="1663" alt="screencapture-localhost-8501-2026-02-25-18_12_15" src="https://github.com/user-attachments/assets/9354efc8-872f-4ac1-b1a2-53cc427113a4" />

## Project Objective

To design and implement a web-based detection engine that:

- Ingests SSH authentication logs  
- Detects brute-force attempts (5+ failed logins within 60 seconds)  
- Assigns severity levels (Low / Medium / High)  
- Maps findings to MITRE ATT&CK (T1110 – Brute Force)  
- Provides interactive visualization  
- Exports structured alert reports in JSON format  

---

## Architecture Overview

```
Log Source (auth.log)
        ↓
Regex-Based Log Parser
        ↓
Sliding Time-Window Detection Engine
        ↓
Severity Scoring Module
        ↓
Alert Generator (JSON Structured Output)
        ↓
Web Dashboard (Streamlit Visualization)
```

---

## Detection Rule Logic

Primary Detection Rule:

If:
- 5 or more failed login attempts  
- From the same source IP  
- Within a 60-second time window  

Then:
- Generate brute-force alert  
- Assign severity  
- Display alert in dashboard  
- Allow JSON export  

---

## Severity Classification Model

| Failed Attempts | Severity |
|-----------------|----------|
| 5–6             | Low      |
| 7–9             | Medium   |
| 10 or more      | High     |

This simulates SOC alert prioritization and triage logic.

---

## Features

- Default sample log analysis  
- Drag-and-drop log upload  
- Rolling time-window detection  
- Severity-based alert classification  
- Attack timeline visualization  
- IP distribution chart  
- Raw log viewer panel  
- Auto-refresh monitoring mode  
- Downloadable JSON alert report  

---

## Technology Stack

- Python  
- Streamlit  
- Pandas  
- Regular Expressions (Regex)  
- Datetime (Time-based correlation logic)  

---

## Project Structure

```
ssh-mini-siem/
│
├── dashboard.py
├── sample_auth.log
├── README.md
├── LICENSE
└── .gitignore
└── screenshots/
```

## Installation and Setup

### 1. Clone Repository

```
git clone https://github.com/YOUR_USERNAME/ssh-mini-siem.git

cd ssh-mini-siem
```

### 2. Install Dependencies

```
pip install streamlit pandas
```

### 3. Run the Application

```
streamlit run dashboard.py
```

The dashboard will open automatically in your browser.

---

## How to Use

1. Launch the application  
2. View analysis of the default sample_auth.log  
3. Optionally upload your own auth.log file  
4. Review detected brute-force activity  
5. Export alert report in JSON format  

---

## Screenshots

Example structure:

```
screenshots/
    dashboard_overview.png
    alert_table.png
    severity_chart.png
    timeline_graph.png
    raw_log_view.png
```

## Use Case Scenario

This project simulates a SOC analyst workflow where:

- Authentication logs are reviewed  
- Failed login patterns are analyzed  
- Suspicious IP activity is detected  
- Threats are classified by severity  
- Alerts are mapped to MITRE ATT&CK  
- Incident reports are exported  

It demonstrates detection engineering fundamentals in a controlled lab environment.

---

## Skills Demonstrated

- Log parsing and regex analysis  
- Time-based anomaly detection  
- Detection engineering fundamentals  
- MITRE ATT&CK alignment  
- Threat classification and prioritization  
- Security dashboard development  

---

## Future Enhancements

- Real-time log streaming integration  
- Email alerting  
- Geo-IP enrichment  
- Docker deployment  
- Multi-log source ingestion  
- Integration with real Linux systems  

---

## Author

WEBSITE DEMO : 
Blue Team / SOC Simulation
NAME : SHEBIN K BABU (DARKLOVERBOI)

CONTACT : KSHEBIN86@GMAIL.COM

