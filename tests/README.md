# Keylogger Detector

A Python-based Windows process monitoring and detection engine that identifies suspicious process behavior using modular detection rules.

---

## Features

- Monitor all running Windows processes
- Analyze executable locations
- Detect process name masquerading
- Detect missing executable paths
- Detect suspicious parent-child process relationships
- Modular detection engine
- Rule-based detection framework
- Unit-tested detection modules
- Git version control
- Structured project documentation

---

## Detection Modules

| Rule ID | Detection | Status |
|----------|-----------|--------|
| KD-001 | Suspicious Executable Location | ✅ PASS |
| KD-002 | Process Name Masquerading | ✅ PASS |
| KD-003 | Missing Executable Path | ✅ PASS |
| KD-004 | Suspicious Parent Process | ✅ PASS |

---

## Project Structure

```
keylogger-detector/
│
├── detector/
│   ├── process_monitor.py
│   ├── process_analyzer.py
│   └── rules.py
│
├── docs/
│
├── logs/
│
├── reports/
│
├── tests/
│   ├── KD001/
│   ├── KD002/
│   ├── KD003/
│   └── KD004/
│
├── main.py
├── requirements.txt
├── README.md
├── CHANGELOG.md
└── PROJECT_PLAN.md
```

---

## Technologies Used

- Python 3.12
- psutil
- Git
- VS Code

---

## Future Improvements

- KD-005 Suspicious PowerShell Detection
- Risk Scoring Engine
- Network Connection Detection
- JSON Report Generation
- Real-Time Monitoring
- GUI Dashboard

---

## Version

Current Version: **v0.5.0**