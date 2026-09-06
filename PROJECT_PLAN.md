Here is the **complete `project_plan.md`** with the full project roadmap through the final dashboard stage.

````markdown
# Keylogger Detector — Project Plan

## Project Overview

The Keylogger Detector is a Python-based endpoint monitoring and
detection framework designed to identify suspicious process activity
using multiple behavioral detection rules.

The project uses `psutil` to collect process information and applies
modular detection logic to identify potentially suspicious activity.

The long-term goal is to evolve the project from a basic process
monitor into a more complete endpoint detection and monitoring
platform.

---

# Phase 1 — Project Foundation

**Status: COMPLETE ✅**

### Tasks

- [x] Create project structure
- [x] Set up Python virtual environment
- [x] Initialize Git repository
- [x] Create `requirements.txt`
- [x] Create initial `README.md`
- [x] Create `CHANGELOG.md`
- [x] Create documentation structure
- [x] Create testing structure

---

# Phase 2 — Process Monitoring

**Status: COMPLETE ✅**

Build the foundation for collecting Windows process information.

### Process Information

- [x] Process enumeration using `psutil`
- [x] PID collection
- [x] PPID collection
- [x] Process name collection
- [x] Parent process collection
- [x] Executable path collection
- [x] Command-line collection
- [x] Username collection
- [x] Process status collection

### Network Information

- [x] Network connection collection
- [x] Local address collection
- [x] Remote IP collection
- [x] Remote port collection
- [x] Connection status collection

---

# Phase 3 — Detection Engine

**Status: COMPLETE ✅**

Create a modular architecture for analyzing processes.

### Detection Architecture

- [x] Centralized rule configuration
- [x] Process analyzer
- [x] Detection functions
- [x] Detection IDs
- [x] Severity levels
- [x] Finding structure
- [x] Modular detection architecture
- [x] Detection module registration

### Testing Architecture

- [x] Testing framework
- [x] Fake process generation
- [x] Individual detection tests
- [x] Positive test cases
- [x] Negative test cases

---

# Phase 4 — Detection Rules

**Status: COMPLETE ✅**

Ten detection rules have currently been implemented.

---

## KD-001 — Suspicious Executable Location

**Status: COMPLETE ✅**

Detect executables or scripts running from suspicious locations.

### Detection

- Suspicious executable paths
- Suspicious command-line paths
- Configured suspicious folders

---

## KD-002 — Process Name Masquerading

**Status: COMPLETE ✅**

Detect process names that are highly similar to trusted process names.

### Detection

- Process name comparison
- Trusted process comparison
- Similarity scoring
- Masquerading detection

---

## KD-003 — Missing Executable Path

**Status: COMPLETE ✅**

Detect processes that do not expose an executable path.

### Detection

- Missing executable path
- System-process exclusions
- False-positive reduction

---

## KD-004 — Suspicious Parent Process

**Status: COMPLETE ✅**

Detect suspicious parent-child process relationships.

### Detection

- Parent process identification
- Child process identification
- Suspicious parent-child combinations

---

## KD-005 — Suspicious PowerShell Activity

**Status: COMPLETE ✅**

Detect PowerShell processes using configured suspicious command-line
flags.

### Detection

- PowerShell process identification
- Command-line analysis
- Suspicious PowerShell flags

---

## KD-006 — Suspicious LOLBin Usage

**Status: COMPLETE ✅**

Detect suspicious usage of legitimate Windows utilities that can be
abused for malicious purposes.

### Current LOLBins

- `certutil.exe`
- `mshta.exe`
- `regsvr32.exe`
- `rundll32.exe`
- `bitsadmin.exe`

### Detection

- LOLBin identification
- Command-line pattern matching
- Context-aware detection
- False-positive reduction

---

## KD-007 — Suspicious Command-Line Activity

**Status: COMPLETE ✅**

Detect suspicious command-line patterns.

### Current Patterns

- `schtasks /create`
- `reg add`
- `net user`
- `net localgroup`

### Detection

- Command-line normalization
- Pattern matching
- Multiple-pattern correlation
- Duplicate finding reduction

---

## KD-008 — Suspicious Network Connection

**Status: COMPLETE ✅**

Detect processes connecting to configured suspicious network ports.

### Detection

- Remote IP analysis
- Remote port analysis
- Connection status analysis
- Suspicious port detection

---

## KD-009 — Process + Network Correlation

**Status: COMPLETE ✅**

Correlate suspicious process execution locations with suspicious
network activity.

### Detection Conditions

A process must exhibit:

1. Suspicious executable location
2. Established network connection
3. Suspicious remote network port

### Purpose

Improve detection confidence by combining multiple indicators instead
of relying on a single suspicious characteristic.

---

## KD-010 — Suspicious Persistence Location

**Status: COMPLETE ✅**

Detect processes whose executable path or command line references
locations associated with Windows persistence mechanisms.

### Current Persistence Locations

- Startup
- Start Menu Startup
- Run
- RunOnce

### Detection

- Executable path analysis
- Command-line analysis
- Persistence location matching

---

# Phase 5 — Testing & Validation

**Status: IN PROGRESS 🟡**

The individual detection rules have been tested. The next objective is
to validate the complete detection system and prevent regressions.

## Completed Tests

- [x] KD-001 test
- [x] KD-002 test
- [x] KD-003 test
- [x] KD-004 test
- [x] KD-005 test
- [x] KD-006 positive test
- [x] KD-006 negative test
- [x] KD-007 positive test
- [x] KD-007 negative test
- [x] KD-008 test
- [x] KD-009 test
- [x] KD-010 test

## Remaining Testing

- [x] Detection-engine alerting and batch-processing tests
- [x] Legitimate-process and false-positive tests

## Future Testing

- [ ] Align risk-scoring test expectations with the implemented risk thresholds
- [ ] Add more malformed-process-data coverage
- [ ] Add more inaccessible and terminated-process coverage
- [ ] Expand regression coverage as new rules are added

---

# Phase 6 — Detection Quality

**Status: PLANNED ⏳**

Improve detection accuracy before significantly expanding the number
of rules.

## False-Positive Reduction

- [ ] Identify common legitimate processes
- [ ] Expand trusted process list
- [ ] Improve system-process exclusions
- [ ] Improve suspicious-path detection
- [ ] Improve LOLBin contextual detection
- [ ] Improve network detection context
- [ ] Improve persistence detection
- [ ] Add additional negative test cases

## Detection Evidence

Each finding should eventually contain enough information to explain
why the process was flagged.

Example:

```text
Rule       : KD-009
Severity   : HIGH

Process    : suspicious.exe
PID        : 4820

Evidence:
- Executable located in Downloads
- Connection to 192.168.1.20:4444
- Connection state: ESTABLISHED
```

---

# Phase 7 — Detection Confidence

**Status: COMPLETE ✅**

Introduce confidence values for individual detections.

Instead of:

```text
Detected = YES
```

the system should eventually provide:

```text
Detection:
KD-009

Severity:
HIGH

Confidence:
87%
```

## Tasks

- [x] Define confidence model and thresholds
- [x] Assign confidence to detection results
- [x] Increase confidence when multiple findings provide corroborating evidence
- [x] Include confidence in detection results, events, and dashboard analysis

The current confidence values are Low, Medium, High, and Very High.
They are calculated from the number and severity of findings and are
kept separate from the overall risk level.

---

# Phase 8 — Detection Result Management

**Status: COMPLETE ✅**

Standardize and improve detection findings.

## Finding Information

- [x] Detection ID
- [x] Rule name
- [x] Severity
- [x] Confidence
- [x] Process ID and process name
- [x] Parent process
- [x] Executable path
- [x] Evidence
- [x] Alert state and alert reason

## Example

```text
==================================================
DETECTION ALERT
==================================================

Rule       : KD-009
Severity   : HIGH
Confidence : 87%

Process    : suspicious.exe
PID        : 4820
Parent     : explorer.exe

Evidence:
- Executable located in Downloads
- Connection to 192.168.1.20:4444
- Connection state: ESTABLISHED

==================================================
```

---

# Phase 9 — Logging

**Status: COMPLETE ✅**

Move from terminal-only output to persistent detection logging.

## Tasks

- [x] Create event-logging module
- [x] Save alerts as persistent JSON detection events
- [x] Add UTC timestamps and event IDs
- [x] Preserve detection history
- [x] Prevent identical consecutive detection events
- [x] Retrieve events by event ID
- [x] Track investigation status and updates

## Future Logging

- [ ] Add CSV export
- [ ] Add log rotation
- [ ] Add log filtering and search

## Planned Structure

```text
logs/
├── detector.log
├── detections.json
└── detections.csv
```

---

# Phase 10 — Real-Time Monitoring

**Status: COMPLETE ✅**

Convert the current process analyzer into a continuous monitoring
system.

## Architecture

```text
Windows System
      |
      v
Process Monitor
      |
      v
New Process Detected
      |
      v
Detection Engine
      |
      v
KD-001 → KD-010
      |
      v
Finding
      |
      v
Logger
      |
      v
Alert
```

## Tasks

- [x] Continuous process monitoring
- [x] Analyze collected processes through the detection engine
- [x] Collect network-connection information
- [x] Generate alerts for High/Critical risk, high-severity findings, or qualifying scores
- [x] Persist non-duplicate alerts as detection events
- [x] Handle process-access errors during collection

## Future Monitoring

- [ ] Detect newly created and terminated processes explicitly
- [ ] Monitor network changes between scans
- [ ] Optimize monitoring performance

---

# Phase 11 — Additional Detection Rules

**Status: PLANNED ⏳**

After the existing rules are fully validated, continue expanding
detection coverage.

### KD-011

**Planned: Detection Confidence Improvements**

- [ ] Define rule confidence
- [ ] Add evidence scoring
- [ ] Improve finding context

### Future Rules

Additional detection rules can be added after KD-011 based on gaps
identified during testing.

Possible areas include:

- Process injection indicators
- Suspicious service activity
- Additional persistence mechanisms
- Unusual process execution patterns
- Suspicious file activity
- Additional network behavior
- Process ancestry anomalies

New rules should only be added after defining:

1. Detection logic
2. Configuration
3. Positive test
4. Negative test
5. Documentation
6. Changelog entry

---

# Phase 12 — Risk Engine

**Status: COMPLETE ✅**

The risk engine should be implemented only after the detection rules
and confidence system are stable.

## Example

```text
KD-001 → Medium
KD-008 → Medium
KD-009 → High
KD-010 → High
```

These findings can be combined into an overall process assessment.

```text
Process Risk Score: 86 / 100

Risk Level: HIGH
```

## Tasks

- [x] Define severity-based scoring model
- [x] Combine unique rule findings into an overall score
- [x] Cap overall risk score at 100
- [x] Define Low, Medium, High, and Critical risk levels
- [ ] Align risk-scoring test expectations with the implemented risk thresholds

---

# Phase 13 — Reporting

**Status: PLANNED ⏳**

Create structured reports from detected activity.

## Report Contents

- [ ] Detection summary
- [ ] Process information
- [ ] Detection evidence
- [ ] Severity
- [ ] Confidence
- [ ] Risk score
- [ ] Timeline
- [ ] Network information
- [ ] Recommended response

## Planned Workflow

```text
Detection
    |
    v
Process Information
    |
    v
Triggered Rules
    |
    v
Evidence
    |
    v
Confidence
    |
    v
Risk Assessment
    |
    v
Recommended Action
    |
    v
Report
```

---

# Phase 14 — Dashboard

**Status: COMPLETE ✅**

Create a graphical interface for monitoring detections.

## Dashboard Concept

```text
+------------------------------------------------+
|              KEYLOGGER DETECTOR                |
+------------------------------------------------+
| Processes | Detections | High Risk | Network  |
+------------------------------------------------+
|                                                |
| Recent Detections                              |
|                                                |
| KD-009   suspicious.exe     HIGH               |
| KD-010   updater.exe        HIGH               |
| KD-007   cmd.exe            MEDIUM             |
|                                                |
+------------------------------------------------+
```

## Potential Technologies

- Flask
- HTML
- CSS
- JavaScript
- React
- SQLite

## Dashboard Features

- [x] Process list and detection list
- [x] Severity, confidence, risk-score, and risk-level indicators
- [x] Detection history and detailed detection view
- [x] Detailed process view with security analysis from the process-details API
- [x] Investigation status badges and controls
- [x] Mark Investigated, Dismiss, and Reopen actions
- [x] Re-analyze Process action

## Future Dashboard

- [ ] Add search and filtering
- [ ] Add report views

---

# Phase 15 — Final Architecture

**Status: LONG-TERM GOAL 🎯**

The final system should eventually follow this architecture:

```text
                +-------------------+
                |   Windows System  |
                +---------+---------+
                          |
                          v
                +-------------------+
                |  Process Monitor  |
                +---------+---------+
                          |
                          v
                +-------------------+
                | Detection Engine  |
                +---------+---------+
                          |
             +------------+------------+
             |            |            |
             v            v            v
        Process       Behavior      Network
         Rules          Rules         Rules
             |            |            |
             +------------+------------+
                          |
                          v
                +-------------------+
                | Findings / Alerts |
                +---------+---------+
                          |
                          v
                +-------------------+
                | Detection         |
                | Confidence        |
                +---------+---------+
                          |
                          v
                +-------------------+
                | Risk Engine       |
                +---------+---------+
                          |
                          v
                +-------------------+
                | Logging / Reports |
                +---------+---------+
                          |
                          v
                +-------------------+
                | Dashboard / GUI   |
                +-------------------+
```

---

# Current Project Progress

```text
Phase 1   Project Foundation          COMPLETE ✅
Phase 2   Process Monitoring          COMPLETE ✅
Phase 3   Detection Engine            COMPLETE ✅
Phase 4   Detection Rules             COMPLETE ✅
Phase 5   Testing & Validation        IN PROGRESS 🟡
Phase 6   Detection Quality           PLANNED ⏳
Phase 7   Detection Confidence        COMPLETE ✅
Phase 8   Result Management           COMPLETE ✅
Phase 9   Logging                     COMPLETE ✅
Phase 10  Real-Time Monitoring        COMPLETE ✅
Phase 11  Additional Detection Rules  PLANNED ⏳
Phase 12  Risk Engine                 COMPLETE ✅
Phase 13  Reporting                   PLANNED ⏳
Phase 14  Dashboard                   COMPLETE ✅
Phase 15  Final Architecture          LONG-TERM 🎯
```

---

# Immediate Next Steps

The immediate development sequence is:

1. Expand regression and edge-case coverage as detection logic changes.
2. Improve detection quality and reduce false positives.
3. Build KD-011 only after defining its detection logic and tests.
4. Add reporting.
5. Add dashboard search, filtering, and report views.

---

# Development Principles

The project should follow these principles as development continues.

### 1. Every Rule Must Be Testable

Every new detection rule should have at least:

- One positive test
- One negative test

### 2. Avoid Unnecessary False Positives

A legitimate process should not be considered suspicious solely because
it matches a weak indicator.

### 3. Use Multiple Indicators

Correlation between multiple suspicious characteristics should be
preferred where possible.

### 4. Keep Detection Rules Modular

Each detection rule should remain independently testable and
maintainable.

### 5. Document Every Change

Every major feature should update:

- `README.md`
- `test_cases.md`
- `detection_rules.md`
- `CHANGELOG.md`
- `project_plan.md`

### 6. Test Before Expanding

Existing functionality should be tested before introducing new
detection rules or major architectural changes.

---

# Long-Term Goal

The ultimate goal is to evolve the Keylogger Detector into a modular
endpoint detection and monitoring platform capable of:

- Monitoring processes in real time
- Detecting suspicious behavior
- Correlating multiple indicators
- Reducing false positives
- Assigning confidence levels
- Calculating risk scores
- Recording detection history
- Generating structured reports
- Providing real-time alerts
- Providing a visual monitoring dashboard
````
