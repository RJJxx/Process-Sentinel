# Process Sentinel

A Python-based Windows process monitoring and detection engine that identifies suspicious process activity using modular detection rules.

---

## Overview

Process Sentinel is a lightweight Endpoint Detection prototype developed in Python.

The project continuously analyzes Windows processes and applies multiple detection modules to identify suspicious behavior. Each detection rule is independently implemented, tested, and documented, making the project easy to extend with additional threat detection capabilities.

The project demonstrates concepts commonly used in Endpoint Detection and Response (EDR) solutions, including process analysis, behavioral detection, and rule-based threat identification.

---

# Features

- Monitor running Windows processes
- Collect detailed process information
- Analyze executable locations
- Detect process name masquerading
- Detect missing executable paths
- Detect suspicious parent-child process relationships
- Detect suspicious PowerShell execution
- Rule-based detection engine
- Modular architecture
- Unit-tested detection modules
- Structured project documentation
- Git version control

---

# Detection Modules

| Rule ID | Detection Module | Category | Status |
|----------|------------------|----------|--------|
| KD-001 | Suspicious Executable Location | File System | ✅ PASS |
| KD-002 | Process Masquerading | Process Analysis | ✅ PASS |
| KD-003 | Missing Executable Path | Process Analysis | ✅ PASS |
| KD-004 | Suspicious Parent Process | Behavior Detection | ✅ PASS |
| KD-005 | Suspicious PowerShell Execution | Behavior Detection | ✅ PASS |
| KD-006 | Suspicious LOLBin Usage | Behavior Detection | ✅ PASS |
| KD-007 | Suspicious Command-Line Activity | Behavior Detection | ✅ PASS |

---

# Project Structure

```
Process-Sentinel/
│
├── detector/
│   ├── process_monitor.py
│   ├── process_analyzer.py
│   └── rules.py
│
├── docs/
│   ├── architecture.md
│   └── detection_rules.md
│
├── logs/
│
├── reports/
│
├── tests/
│   ├── KD001/
│   ├── KD002/
│   ├── KD003/
│   ├── KD004/
│   └── KD005/
│
├── main.py
├── requirements.txt
├── README.md
├── CHANGELOG.md
└── PROJECT_PLAN.md
```

---

# Detection Workflow

```
Running Processes
        │
        ▼
Process Monitor
        │
        ▼
Process Analyzer
        │
        ▼
Detection Modules
        │
        ├── KD-001
        ├── KD-002
        ├── KD-003
        ├── KD-004
        └── KD-005
        │
        ▼
Detection Findings
```

---

# Technologies Used

- Python 3.12
- psutil
- Git
- VS Code
- Windows Process APIs

---

# Current Version

**v0.8.0**

---

# Roadmap

## Completed

- ✅ Process Monitoring
- ✅ Process Analysis
- ✅ Rule Configuration
- ✅ Unit Testing Framework
- ✅ Documentation
- ✅ KD-001
- ✅ KD-002
- ✅ KD-003
- ✅ KD-004
- ✅ KD-005
- ✅ KD-006

## Planned

- KD-006 Living-off-the-Land Binary Detection
- KD-007 Suspicious Command Line Detection
- KD-008 Network Connection Analysis
- KD-009 Startup Persistence Detection
- KD-010 Risk Scoring Engine
- HTML & PDF Report Generation
- Real-time Process Monitoring
- Graphical User Interface (GUI)

---

# Project Goals

The primary objectives of this project are:

- Learn Windows process analysis
- Build a modular detection engine
- Implement behavior-based detection techniques
- Reduce false positives through rule refinement
- Apply secure software engineering practices
- Gain practical experience with cybersecurity detection logic

---

# Author

**Rohith Jacob**

Computer Science Engineer

Cybersecurity & Software Development Enthusiast

---

# License

This project is intended for educational and research purposes.