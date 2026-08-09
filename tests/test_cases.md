---

## KD-003

Rule

Missing Executable Path

Description

Detect processes that do not expose an executable path, excluding known Windows system processes.

Test

Analyze a process with:

exe = ""

Expected

Detector reports:

- Missing Executable Path

Status

PASS ✅

---

## KD-004

Rule

Suspicious Parent Process

Description

Detect suspicious parent-child process relationships.

Test

Analyze a process where:

Parent Process : winword.exe

Child Process : powershell.exe

Expected

Detector reports:

- Suspicious Parent Process

Status

PASS ✅

---

## KD-005

### Rule Name

Suspicious PowerShell Execution

### Category

Behavior Detection

### Severity

High

### Description

Detect suspicious PowerShell execution using command-line arguments commonly associated with malicious activity.

### Test Input

Process Name:

powershell.exe

Command Line:

powershell.exe -EncodedCommand SQBFAFgA

### Expected Result

Rule Triggered:

KD-005

Severity:

High

### Result

PASS ✅

---

## KD-006

### Rule Name

Suspicious LOLBin Usage

### Category

Behavior Detection

### Severity

High

### Description

Detect suspicious usage of legitimate Windows utilities commonly abused by attackers.

### LOLBins Tested

- certutil.exe
- mshta.exe
- regsvr32.exe
- rundll32.exe
- bitsadmin.exe

### Positive Test

Process:

certutil.exe

Command Line:

certutil.exe -decode input.txt output.exe

Expected:

KD-006 triggered

Result:

PASS ✅

### Negative Test

Process:

certutil.exe

Command Line:

certutil.exe -dump certificate.cer

Expected:

No KD-006 finding

Result:

PASS ✅