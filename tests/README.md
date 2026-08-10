# Keylogger Detector

A Python-based endpoint monitoring and detection framework designed
to identify suspicious process activity using multiple behavioral
detection rules.

The project uses `psutil` to collect process information and applies
modular detection rules to identify potentially suspicious activity.

---

## Project Overview

The Keylogger Detector started as a process monitoring project and
has evolved into a modular security detection engine.

The system analyzes running processes using information such as:

- Process name
- Process ID
- Parent process
- Executable path
- Command line
- Process status
- Network connections

The collected information is passed through multiple detection rules.

---

## Current Detection Rules

| Rule ID | Detection | Severity | Status |
|---|---|---|---|
| KD-001 | Suspicious Executable Location | Medium | PASS ✅ |
| KD-002 | Process Name Masquerading | High | PASS ✅ |
| KD-003 | Missing Executable Path | Medium | PASS ✅ |
| KD-004 | Suspicious Parent Process | High | PASS ✅ |
| KD-005 | Suspicious PowerShell Activity | High | PASS ✅ |
| KD-006 | Suspicious LOLBin Usage | High | PASS ✅ |
| KD-007 | Suspicious Command-Line Activity | Medium | PASS ✅ |
| KD-008 | Suspicious Network Connection | Medium | PASS ✅ |
| KD-009 | Process + Network Correlation | High | PASS ✅ |
| KD-010 | Suspicious Persistence Location | High | PASS ✅ |

---

## Detection Capabilities

### Process Analysis

The system collects information about running processes including:

```text
PID
PPID
Process Name
Parent Process
Executable Path
Command Line
Username
Process Status
```

### Network Analysis

The process monitor also collects network connection information:

```text
Local Address
Remote IP
Remote Port
Connection Status
```

This information is used by KD-008 and KD-009.

---

## Detection Architecture

```text
                    Running Processes
                           |
                           v
                    Process Monitor
                           |
                           v
                  Process Information
                           |
                           v
                   Detection Engine
                           |
        +------------------+------------------+
        |                  |                  |
        v                  v                  v
   Process Rules      Behavior Rules     Network Rules
        |                  |                  |
        +------------------+------------------+
                           |
                           v
                       Findings
                           |
                           v
                    Console Output
```

---

## Detection Rules

### KD-001 — Suspicious Executable Location

Detects executables or scripts running from suspicious locations such
as Temp or Downloads.

---

### KD-002 — Process Name Masquerading

Detects process names that closely resemble trusted Windows process
names.

The detector uses process-name similarity comparison to identify
potential masquerading.

---

### KD-003 — Missing Executable Path

Detects processes that do not expose an executable path.

Known Windows system processes are excluded to reduce false positives.

---

### KD-004 — Suspicious Parent Process

Detects suspicious parent-child process relationships.

The detector compares the current process with its parent process
against configured suspicious relationships.

---

### KD-005 — Suspicious PowerShell Activity

Detects PowerShell processes using configured suspicious command-line
flags.

Only PowerShell processes are evaluated by this rule.

---

### KD-006 — Suspicious LOLBin Usage

Detects suspicious usage of legitimate Windows utilities that can be
abused for malicious purposes.

The current configuration includes:

```text
certutil.exe
mshta.exe
regsvr32.exe
rundll32.exe
bitsadmin.exe
```

The detector does not automatically consider every execution of a
LOLBin suspicious. It checks the command line for configured
suspicious usage patterns.

---

### KD-007 — Suspicious Command-Line Activity

Detects configured suspicious command-line patterns.

The current configuration includes:

```text
schtasks /create
reg add
net user
net localgroup
```

Multiple matching patterns are combined into a single finding to
reduce duplicate alerts.

---

### KD-008 — Suspicious Network Connection

Detects processes making connections to configured suspicious remote
network ports.

The detector analyzes:

- Remote IP address
- Remote port
- Connection information

Example:

```text
Remote IP: 192.168.1.20
Remote Port: 4444
Status: ESTABLISHED
```

---

### KD-009 — Process + Network Correlation

Detects processes exhibiting multiple suspicious characteristics.

KD-009 correlates:

1. Suspicious executable location
2. Established network connection
3. Suspicious remote network port

For example:

```text
Executable:
C:\Users\ASUS\Downloads\suspicious_test.exe

Remote endpoint:
192.168.1.20:4444

Status:
ESTABLISHED
```

This rule provides a stronger signal than relying on a single
indicator.

---

### KD-010 — Suspicious Persistence Location

Detects processes whose executable path or command line references
locations associated with Windows persistence mechanisms.

The current configuration includes locations associated with:

```text
Startup
Start Menu Startup
Run
RunOnce
```

Example:

```text
C:\Users\ASUS\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\suspicious_startup.exe
```

---

## Project Structure

```text
keylogger-detector/
│
├── detector/
│   ├── __init__.py
│   ├── rules.py
│   ├── process_monitor.py
│   ├── process_analyzer.py
│   └── detection_engine.py
│
├── tests/
│   ├── KD006/
│   │   ├── test_kd006.py
│   │   └── test_kd006_negative.py
│   │
│   ├── KD007/
│   │   ├── test_kd007.py
│   │   └── test_kd007_negative.py
│   │
│   ├── KD008/
│   │   └── test_kd008.py
│   │
│   ├── KD009/
│   │   └── test_kd009.py
│   │
│   ├── KD010/
│   │   └── test_kd010.py
│   │
│   └── test_cases.md
│
├── docs/
│   └── detection_rules.md
│
├── main.py
├── requirements.txt
├── CHANGELOG.md
└── README.md
```

---

## Testing

The project uses controlled fake process data to test individual
detection rules.

This allows detection logic to be tested without requiring actual
malicious processes or external systems.

Positive tests verify that suspicious activity is detected.

Negative tests verify that legitimate activity is not incorrectly
flagged.

---

## Current Testing Status

```text
KD-001  PASS ✅
KD-002  PASS ✅
KD-003  PASS ✅
KD-004  PASS ✅
KD-005  PASS ✅
KD-006  PASS ✅
KD-007  PASS ✅
KD-008  PASS ✅
KD-009  PASS ✅
KD-010  PASS ✅
```

---

## Technologies Used

- Python
- psutil
- Git
- Visual Studio Code

---

## Running the Detector

### 1. Activate the virtual environment

On Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

### 2. Run the detector

```powershell
python main.py
```

The detector scans running processes and applies the configured
detection rules.

---

## Running Individual Tests

Individual detection tests can be executed from the project root.

### KD-006

```powershell
python -m tests.KD006.test_kd006
```

### KD-007

```powershell
python -m tests.KD007.test_kd007
```

### KD-008

```powershell
python -m tests.KD008.test_kd008
```

### KD-009

```powershell
python -m tests.KD009.test_kd009
```

### KD-010

```powershell
python -m tests.KD010.test_kd010
```

---

## Development Roadmap

### Completed

```text
KD-001  Suspicious Executable Location       ✅
KD-002  Process Name Masquerading            ✅
KD-003  Missing Executable Path              ✅
KD-004  Suspicious Parent Process            ✅
KD-005  Suspicious PowerShell Activity       ✅
KD-006  Suspicious LOLBin Usage              ✅
KD-007  Suspicious Command-Line Activity     ✅
KD-008  Suspicious Network Connection        ✅
KD-009  Process + Network Correlation        ✅
KD-010  Suspicious Persistence Location      ✅
```

### Planned

```text
KD-011  Detection Confidence Improvements
KD-012  Detection Result Logging
KD-013  Alert / Report Generation
KD-014  Real-Time Monitoring Improvements
KD-015  Dashboard / GUI
```

---

## Future Improvements

Future development can focus on improving the detector's ability to
correlate multiple indicators and reduce false positives.

Potential improvements include:

- Detection confidence scoring
- Risk-based alert prioritization
- Structured detection logs
- Alert history
- Real-time monitoring
- Improved persistence detection
- Expanded network analysis
- Detection result export
- Dashboard and visualization
- Automated regression testing

---

## Disclaimer

This project is intended for educational, defensive security,
endpoint monitoring, and authorized security testing purposes only.

Do not use the detector or its testing components against systems
without appropriate authorization.