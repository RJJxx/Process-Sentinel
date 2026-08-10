Got you — you want the **entire `test_cases.md`**, with **nothing cut out or abbreviated in the middle**. Copy everything below directly into `test_cases.md`:

````markdown
# Detection Test Cases

This document contains test cases for all detection rules implemented
in the Keylogger Detector project.

---

## KD-001

### Rule

Suspicious Executable Location

### Description

Detect executables or scripts running from suspicious folders such as
Temp and Downloads.

### Test

Run a simulated executable from the Downloads folder.

### Expected

Detector reports:

- Suspicious Executable Location

### Status

PASS ✅

---

## KD-002

### Rule

Process Name Masquerading

### Description

Detect process names that are highly similar to trusted Windows
process names.

### Test

Create a simulated process named:

```text
chrome1.exe
```

### Expected

Detector reports:

- Possible Masquerading

### Status

PASS ✅

---

## KD-003

### Rule

Missing Executable Path

### Description

Detect processes that do not expose an executable path while
excluding known legitimate Windows system processes.

### Test

Create a simulated process with an empty executable path.

### Expected

Detector reports:

- Missing Executable Path

### Status

PASS ✅

---

## KD-004

### Rule

Suspicious Parent Process

### Description

Detect suspicious parent-child process relationships.

### Test

Create a simulated process with a parent process that is configured
as suspicious.

### Expected

Detector reports:

- Suspicious Parent Process

### Status

PASS ✅

---

## KD-005

### Rule

Suspicious PowerShell Activity

### Description

Detect PowerShell processes executed with suspicious command-line
flags.

### Test

Create a simulated PowerShell process containing a configured
suspicious PowerShell flag.

### Expected

Detector reports:

- Suspicious PowerShell Activity

### Status

PASS ✅

---

## KD-006

### Rule

Suspicious LOLBin Usage

### Description

Detect suspicious usage of legitimate Windows utilities that can be
abused by attackers.

### LOLBins Tested

- `certutil.exe`
- `mshta.exe`
- `regsvr32.exe`
- `rundll32.exe`
- `bitsadmin.exe`

### Positive Test

Process:

```text
certutil.exe
```

Command line:

```text
certutil.exe -decode input.txt output.exe
```

### Expected

Detector reports:

- Suspicious LOLBin Usage

### Status

PASS ✅

### Negative Test

Process:

```text
certutil.exe
```

Command line:

```text
certutil.exe -dump certificate.cer
```

### Expected

No KD-006 finding should be generated.

### Status

PASS ✅

---

## KD-007

### Rule

Suspicious Command-Line Activity

### Description

Detect specific command-line patterns that may indicate suspicious
administrative or system activity.

### Detection Patterns

- `schtasks /create`
- `reg add`
- `net user`
- `net localgroup`

### Positive Test

Process:

```text
cmd.exe
```

Command line:

```text
cmd.exe /c net user
```

### Expected

Detector reports:

- Suspicious Command-Line Activity

### Status

PASS ✅

### Negative Test

Process:

```text
cmd.exe
```

Command line:

```text
cmd.exe /c ipconfig
```

### Expected

No KD-007 finding should be generated.

### Status

PASS ✅

---

## KD-008

### Rule

Suspicious Network Connection

### Description

Detect processes making connections to configured suspicious remote
network ports.

### Test

Create a simulated process with an established network connection
to a suspicious test port.

### Example

```text
Remote IP: 192.168.1.20
Remote Port: 4444
Status: ESTABLISHED
```

### Expected

Detector reports:

- Suspicious Network Connection

### Status

PASS ✅

---

## KD-009

### Rule

Suspicious Process and Network Correlation

### Description

Detect processes that combine suspicious execution location with
suspicious network activity.

### Test

Create a simulated process that:

1. Runs from a suspicious folder.
2. Has an established network connection.
3. Connects to a configured suspicious port.

### Example

```text
Executable:
C:\Users\ASUS\Downloads\suspicious_test.exe

Remote endpoint:
192.168.1.20:4444

Status:
ESTABLISHED
```

### Expected

Detector reports:

- Suspicious Process and Network Correlation

### Status

PASS ✅

---

## KD-010

### Rule

Suspicious Persistence Location

### Description

Detect processes whose executable path or command line references
locations associated with Windows persistence mechanisms.

### Test

Create a simulated process running from a Startup location.

### Example

```text
C:\Users\ASUS\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\suspicious_startup.exe
```

### Expected

Detector reports:

- Suspicious Persistence Location

### Status

PASS ✅

---

# Detection Test Summary

| Rule | Detection | Status |
|---|---|---|
| KD-001 | Suspicious Executable Location | PASS ✅ |
| KD-002 | Process Name Masquerading | PASS ✅ |
| KD-003 | Missing Executable Path | PASS ✅ |
| KD-004 | Suspicious Parent Process | PASS ✅ |
| KD-005 | Suspicious PowerShell Activity | PASS ✅ |
| KD-006 | Suspicious LOLBin Usage | PASS ✅ |
| KD-007 | Suspicious Command-Line Activity | PASS ✅ |
| KD-008 | Suspicious Network Connection | PASS ✅ |
| KD-009 | Suspicious Process and Network Correlation | PASS ✅ |
| KD-010 | Suspicious Persistence Location | PASS ✅ |
````
