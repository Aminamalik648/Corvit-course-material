# 🛡️ Log Analyzer — SSH Brute Force Detector

A SOC-analyst-focused desktop tool that parses SSH authentication logs, detects brute force attempts, and generates triage-ready reports.

---

## 📌 Features

- 📂 Load any standard `auth.log` file
- 🔍 Detects **failed SSH login attempts** using regex parsing
- 🚨 Flags IPs exceeding the brute-force threshold (default: 5 failures)
- 🎯 Severity scoring — CRITICAL / HIGH / MEDIUM per IP
- 📊 Live dashboard with stat cards (total lines, failures, brute IPs, accepted logins)
- ✅ Separate panel showing legitimate accepted logins
- ⬇️ Export flagged IPs to CSV report

---

## 🛠️ Tech Stack

| Tool | Purpose |
|------|---------|
| Python 3.10+ | Core language |
| CustomTkinter | Dark-themed GUI dashboard |
| re (regex) | Log pattern matching |
| csv | Report export |
| collections.defaultdict | IP aggregation |

---

## 🚀 Setup & Run

```bash
# Install dependency
pip install customtkinter

# Run the app
python log_analyzer.py
```

Then click **"Load Log File"** and select `sample_auth.log` (included) to see results immediately.

---

## 📁 Project Structure

```
log_analyzer/
├── log_analyzer.py     ← Main application
├── sample_auth.log     ← Sample log for testing
└── README.md
```

---

## 📋 How it Works

1. **Parse** — Reads the log line by line using two regex patterns:
   - `Failed password for <user> from <IP>` → failed attempts
   - `Accepted password for <user> from <IP>` → successful logins

2. **Aggregate** — Groups failed attempts by source IP, counts occurrences, collects targeted usernames

3. **Score** — Assigns severity:
   - `MEDIUM` — 1–4 failed attempts
   - `HIGH` — 5–9 failed attempts (brute force threshold)
   - `CRITICAL` — 10+ failed attempts

4. **Display** — Renders results in a color-coded dashboard

5. **Export** — Saves flagged IPs to CSV for incident documentation

---

## 💼 Resume / CV Description

> "Developed a Python desktop tool for SOC analysts that parses SSH authentication logs, detects brute-force login attempts using regex-based pattern matching, applies severity scoring (Critical/High/Medium), and exports analyst-ready triage reports — built with CustomTkinter for a professional dark-themed dashboard."

---

## 🔮 Possible Extensions (to grow the project later)

- Add support for Windows Event Log `.evtx` files
- Integrate GeoIP lookup to map attacker IPs to countries
- Add time-based analysis (attacks per hour chart)
- Email alert when critical IPs are detected
