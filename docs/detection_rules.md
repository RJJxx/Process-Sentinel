# Detection Rule Documentation

---

# KD-001

## Name

Suspicious Executable Location

## Category

File System Detection

## Severity

Medium

## Purpose

Detect executables launched from suspicious locations.

## Current Locations

- Temp
- Downloads

## Status

PASS ✅

---

# KD-002

## Name

Possible Masquerading

## Category

Process Detection

## Severity

High

## Purpose

Detect process names similar to trusted Windows applications.

## Detection Method

SequenceMatcher

Similarity Threshold:
90%

## Status

PASS ✅

---

# KD-003

## Name

Missing Executable Path

## Category

Process Detection

## Severity

Medium

## Purpose

Detect processes that do not expose an executable path.

## False Positives

Known Windows system processes are ignored.

## Status

PASS ✅

---

# KD-004

## Name

Suspicious Parent Process

## Category

Behavior Detection

## Severity

High

## Purpose

Detect suspicious parent-child process relationships.

## Current Rules

winword.exe
    ↓
powershell.exe

excel.exe
    ↓
cmd.exe

winword.exe
    ↓
wscript.exe

excel.exe
    ↓
cscript.exe

## Status

PASS ✅

---

# KD-005

## Name

Suspicious PowerShell Execution

## Category

Behavior Detection

## Severity

High

## Purpose

Detect suspicious PowerShell execution techniques commonly used in malware, phishing attacks and post-exploitation.

## Detection Logic

The detector checks whether:

- Process Name = powershell.exe

AND

The command line contains one or more suspicious PowerShell flags.

Current Flags:

- -enc
- -EncodedCommand
- -ExecutionPolicy Bypass
- FromBase64String
- -NoProfile
- -WindowStyle Hidden
- -w hidden
- -nop

## False Positives

Low

System administrators may occasionally use these arguments legitimately.

## Status

PASS ✅

---

# KD-006

## Name

Suspicious LOLBin Usage

## Category

Behavior Detection

## Severity

High

## Purpose

Detect suspicious usage of legitimate Windows utilities that may be abused during attacks.

## Detection Logic

The detector first checks whether the process is a known LOLBin.

It then examines the command line for suspicious usage patterns.

Current LOLBins:

- certutil.exe
- mshta.exe
- regsvr32.exe
- rundll32.exe
- bitsadmin.exe

The rule does not automatically flag a LOLBin simply because it is running.

A finding is generated only when a suspicious usage pattern is detected.

## Testing

Positive test:

certutil.exe -decode input.txt output.exe

Result:

PASS ✅

Negative test:

certutil.exe -dump certificate.cer

Result:

PASS ✅

## Status

PASS ✅