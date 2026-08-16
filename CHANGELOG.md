# Changelog

All notable changes to this project are documented here.

---

## v0.11.0

### Added

- Detection event investigation workflow
- Persistent investigation status for detection events
- New investigation statuses:
  - New
  - Investigated
  - Dismissed
- Ability to reopen dismissed or investigated events
- Event lookup by event ID
- Investigation status tracking with update timestamp
- Investigation status tracking with updated-by information
- Investigation statistics
- API endpoint for retrieving individual detection events
- API endpoint for marking events as Investigated
- API endpoint for dismissing events
- API endpoint for reopening events

### API

Added the following endpoints:

- `GET /api/events/<event_id>`
- `POST /api/events/<event_id>/investigate`
- `POST /api/events/<event_id>/dismiss`
- `POST /api/events/<event_id>/reopen`

### Dashboard

- Added investigation status badges to recent detections
- Added investigation controls to the detection details view
- Added Mark as Investigated action
- Added Dismiss action
- Added Reopen action
- Added automatic investigation status refresh
- Added investigation status styling
- Added investigation action loading/disabled states
- Detection details now retrieve the latest event information from the API

### Improved

- Detection event management
- Detection event persistence
- Dashboard event synchronization
- Detection investigation workflow
- Event status visibility
- Analyst workflow for reviewing security detections

### Testing

- Detection event retrieval tested
- Investigation status update tested
- Investigated status persistence tested
- Dismissed status tested
- Reopen functionality tested
- Dashboard investigation controls tested
- Investigation status displayed correctly after refresh
- Investigation API endpoints tested
- Existing detection and monitoring functionality verified

---

## v0.10.0

### Added

- KD-010 Suspicious Persistence Location
- Detection of suspicious Windows persistence locations
- Detection based on executable paths
- Detection based on process command lines
- KD-010 positive test case

### Improved

- Persistence-related process analysis
- Detection of suspicious Startup, Run, and RunOnce locations

### Testing

- KD-010 PASS ✅

---

## v0.9.0

### Added

- KD-009 Suspicious Process and Network Correlation
- Correlation between suspicious executable locations and network activity
- Detection of established connections to suspicious network ports
- KD-009 positive test case

### Improved

- Behavioral correlation between process and network indicators
- Detection confidence through multiple suspicious indicators

### Testing

- KD-009 PASS ✅

---

## v0.8.0

### Added

- KD-008 Suspicious Network Connection
- Process network connection collection
- Detection of suspicious remote network ports
- KD-008 test case

### Improved

- Process monitoring with network information
- Network-based detection capabilities

### Testing

- KD-008 PASS ✅

---

## v0.7.0

### Added

- KD-007 Suspicious Command-Line Activity
- Detection of suspicious command-line patterns
- Positive KD-007 test case
- Negative KD-007 test case

### Improved

- Reduced duplicate command-line findings
- Improved false-positive resistance

### Testing

- KD-007 positive test PASS ✅
- KD-007 negative test PASS ✅

---

## v0.6.0

### Added

- KD-006 Suspicious LOLBin Usage
- LOLBin detection configuration
- Suspicious LOLBin command-line patterns
- Positive KD-006 test case
- Negative KD-006 test case

### Improved

- Context-aware LOLBin detection
- Reduced false positives by checking command-line usage

### Testing

- KD-006 positive test PASS ✅
- KD-006 negative test PASS ✅

---

## v0.5.0

### Added

- KD-003 Missing Executable Path
- KD-004 Suspicious Parent Process

### Improved

- Parent process collection
- Centralized rule configuration
- Reduced false positives for Windows system processes

### Testing

- KD-003 PASS ✅
- KD-004 PASS ✅

---

## v0.4.0

### Added

- Testing framework
- Unit tests
- Fake process generator

---

## v0.3.0

### Added

- KD-001 Suspicious Executable Location
- KD-002 Process Name Masquerading

### Improved

- Modular detection architecture

---

## v0.2.0

### Added

- Process monitoring using psutil
- Process information collection
- Executable path collection

---

## v0.1.0

### Added

- Initial project structure
- Virtual environment
- Git repository
- README
- Requirements