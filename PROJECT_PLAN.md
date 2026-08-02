# Keylogger Detector

## Project Goal

Develop a lightweight Windows security tool that monitors running processes,
detects suspicious behavior commonly associated with keyloggers,
and generates security findings.

---

# Current Architecture

Windows
    ↓
Process Monitor
    ↓
Process Analyzer
    ↓
Risk Engine
    ↓
Logger
    ↓
Report Generator
    ↓
GUI

---

# Completed Milestones

✅ Project setup

✅ Virtual environment

✅ Git repository

✅ Process monitoring

✅ Process analyzer

✅ Suspicious executable path detection

---

# Upcoming Milestones
# Development Roadmap

## Phase 1 - Foundation ✅

- [x] Project setup
- [x] Git repository
- [x] Process monitor
- [x] Process analyzer
- [x] Detection rules
- [x] Testing framework

---

## Phase 2 - Detection Rules 🚧

- [x] KD-001 Suspicious executable path
- [x] KD-002 Process name masquerading
- [ ] KD-003 Missing executable
- [ ] KD-004 User-writable directory detection
- [ ] KD-005 Duplicate process detection
- [ ] KD-006 Suspicious parent process
- [ ] KD-007 High CPU usage
- [ ] KD-008 High memory usage
- [ ] KD-009 Network connection monitoring
- [ ] KD-010 Startup persistence detection

---

## Phase 3 - Intelligence Engine

- [ ] Risk Engine
- [ ] Risk scoring
- [ ] Threat classification

---

## Phase 4 - Reporting

- [ ] JSON reports
- [ ] Log files
- [ ] Scan history

---

## Phase 5 - User Interface

- [ ] Console improvements
- [ ] GUI dashboard
- [ ] Real-time monitoring

# Detection Rules

Current

- Executable running from Temp
- Executable running from Downloads

Future

- Unsigned executable
- Suspicious parent process
- Startup persistence
- Hidden executable
- High CPU usage
- Active network connection