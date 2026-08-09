# Changelog

All notable changes to this project are documented here.

---

## v0.8.0

### Added

- KD-007 Suspicious Command-Line Activity
- Detection of suspicious command-line patterns
- Positive and negative test cases for KD-007

### Improved

- Reduced duplicate KD-007 findings by combining multiple matched patterns into a single finding
- Improved false-positive resistance
- Separated PowerShell-specific detection from general command-line detection

### Testing

- KD-007 positive test PASS ✅
- KD-007 negative test PASS ✅

---

## v0.7.0

### Added

- KD-006 Suspicious LOLBin Usage
- Detection of suspicious use of legitimate Windows utilities
- LOLBin detection patterns
- Positive and negative test cases for KD-006

### Improved

- Behavioral detection capabilities
- False-positive resistance through contextual LOLBin analysis

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
- KD-002 Process Masquerading

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