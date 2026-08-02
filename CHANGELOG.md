# Changelog

All notable changes to this project will be documented here.

---

## v0.1.0 - Initial Setup

### Added
- Project structure
- Virtual environment
- Git repository
- README
- requirements.txt

---

## v0.2.0 - Process Monitoring

### Added
- Process monitoring using psutil
- Process information collection
- Executable path collection

---

## v0.3.0 - Detection Engine

### Added
- Process analyzer
- Suspicious executable path detection (KD-001)
- Process name masquerading detection (KD-002)

### Improved
- Modular detection rule architecture
- Detection rule configuration using `rules.py`

---

## v0.4.0 - Testing Framework

### Added
- `tests/` directory
- Detection test cases
- Fake test process