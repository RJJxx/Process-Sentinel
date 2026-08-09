# Changelog

All notable changes to this project are documented here.

---

## v0.7.0

### Added

- KD-006 Suspicious LOLBin Usage
- Detection for suspicious use of legitimate Windows utilities
- LOLBin detection patterns for certutil.exe, mshta.exe, regsvr32.exe, rundll32.exe, and bitsadmin.exe
- Positive and negative test cases for KD-006

### Improved

- Behavioral detection capabilities
- False-positive resistance through contextual LOLBin analysis

### Testing

- KD-006 positive test PASS ✅
- KD-006 negative test PASS ✅

## v0.6.0

### Added

- KD-005 Suspicious PowerShell Execution
- Detection of suspicious PowerShell command-line arguments
- Support for detecting encoded PowerShell execution
- Unit tests for KD-005

### Improved

- Expanded behavior-based detection capabilities
- Updated project documentation
- Updated detection rule documentation
- Updated test cases

### Testing

- KD-005 PASS ✅

---

## v0.5.0

### Added

- KD-003 Missing Executable Path
- KD-004 Suspicious Parent Process

### Improved

- Parent process collection
- Centralized rule configuration (RULES)
- Reduced false positives for Windows system processes
- Added parent process name collection

### Testing

- KD-003 PASS ✅
- KD-004 PASS ✅

---

## v0.4.0

### Added

- Testing framework
- Unit tests
- Fake process generator
- Documentation for detection modules

---

## v0.3.0

### Added

- KD-001 Suspicious Executable Location
- KD-002 Process Masquerading

### Improved

- Modular detection architecture

### Testing

- KD-001 PASS ✅
- KD-002 PASS ✅

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