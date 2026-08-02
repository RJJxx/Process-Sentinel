# Detection Test Cases

---

## KD-001

Rule

Suspicious Executable Path

Description

Detect executables running from suspicious folders.

Test

Run executable from Downloads folder.

Expected

Detector reports:

- Suspicious Executable Location

Status

PASS ✅

---

## KD-002

Rule

Process Name Masquerading

Description

Detect process names similar to trusted applications.

Test

Run a process named:

chrome1.exe

Expected

Detector reports:

Possible Masquerading

Status

Not Tested