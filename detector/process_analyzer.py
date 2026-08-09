from detector.rules import (
    SUSPICIOUS_FOLDERS,
    TRUSTED_PROCESS_NAMES,
    SYSTEM_PROCESSES,
    RULES,
    SUSPICIOUS_PARENT_CHILD,
    SUSPICIOUS_POWERSHELL_FLAGS,
    SUSPICIOUS_LOLBINS,
    SUSPICIOUS_LOLBIN_PATTERNS,
    SUSPICIOUS_COMMAND_PATTERNS,
)

from difflib import SequenceMatcher


def check_suspicious_path(process):
    """
    Detect executables or scripts running from suspicious locations.
    """

    findings = []

    exe_path = process.get("exe", "")
    cmdline = " ".join(process.get("cmdline", []))

    for folder in SUSPICIOUS_FOLDERS:

        # Check executable path
        if exe_path and folder.lower() in exe_path.lower():

            rule = RULES["KD-001"]

            findings.append({
                "id": "KD-001",
                "rule": rule["name"],
                "severity": rule["severity"],
                "description": (
                    f"Executable is running from '{folder}'."
                )
            })

        # Check command line
        elif cmdline and folder.lower() in cmdline.lower():

            rule = RULES["KD-001"]

            findings.append({
                "id": "KD-001",
                "rule": rule["name"],
                "severity": rule["severity"],
                "description": (
                    f"Command line references '{folder}'."
                )
            })

    return findings


def check_process_name(process):
    """
    Detect process names that resemble trusted Windows processes.
    """

    findings = []

    process_name = process.get("name", "").lower()

    for trusted_name in TRUSTED_PROCESS_NAMES:

        similarity = SequenceMatcher(
            None,
            process_name,
            trusted_name.lower()
        ).ratio()

        if similarity >= 0.90 and process_name != trusted_name.lower():

            rule = RULES["KD-002"]

            findings.append({
                "id": "KD-002",
                "rule": rule["name"],
                "severity": rule["severity"],
                "description": (
                    f"Process '{process_name}' is very similar to "
                    f"trusted process '{trusted_name}' "
                    f"({similarity:.2f} similarity)."
                )
            })

    return findings


def check_missing_executable(process):
    """
    Detect processes that do not expose an executable path.
    Ignore known Windows system processes.
    """

    findings = []

    exe_path = process.get("exe", "")
    process_name = process.get("name", "").lower()

    if process_name in SYSTEM_PROCESSES:
        return findings

    if not exe_path:

        rule = RULES["KD-003"]

        findings.append({
            "id": "KD-003",
            "rule": rule["name"],
            "severity": rule["severity"],
            "description": (
                f"Process '{process_name}' does not expose an executable path."
            )
        })

    return findings


def check_suspicious_parent(process):
    """
    Detect suspicious parent-child process relationships.
    """

    findings = []

    process_name = process.get("name", "").lower()
    parent_name = process.get("parent_name", "").lower()

    if process_name in SUSPICIOUS_PARENT_CHILD:

        suspicious_parents = SUSPICIOUS_PARENT_CHILD[process_name]

        if parent_name in suspicious_parents:

            rule = RULES["KD-004"]

            findings.append({
                "id": "KD-004",
                "rule": rule["name"],
                "severity": rule["severity"],
                "description": (
                    f"'{process_name}' was launched by "
                    f"'{parent_name}'."
                )
            })

    return findings


def check_suspicious_powershell(process):
    """
    Detect suspicious PowerShell execution.
    """

    findings = []

    process_name = process.get("name", "").lower()

    if process_name != "powershell.exe":
        return findings

    cmdline = " ".join(process.get("cmdline", [])).lower()

    for flag in SUSPICIOUS_POWERSHELL_FLAGS:

        if flag in cmdline:

            rule = RULES["KD-005"]

            findings.append({
                "id": "KD-005",
                "rule": rule["name"],
                "severity": rule["severity"],
                "description": (
                    f"PowerShell executed with suspicious flag '{flag}'."
                )
            })

    return findings


def check_suspicious_lolbin(process):
    """
    Detect suspicious usage of legitimate Windows LOLBins.
    """

    findings = []

    process_name = process.get("name", "").lower()
    cmdline = " ".join(process.get("cmdline", [])).lower()

    # Ignore processes that are not in our LOLBin list
    if process_name not in SUSPICIOUS_LOLBINS:
        return findings

    suspicious_patterns = SUSPICIOUS_LOLBIN_PATTERNS.get(
        process_name,
        []
    )

    for pattern in suspicious_patterns:

        if pattern.lower() in cmdline:

            rule = RULES["KD-006"]

            findings.append({
                "id": "KD-006",
                "rule": rule["name"],
                "severity": rule["severity"],
                "description": (
                    f"LOLBin '{process_name}' was executed "
                    f"with suspicious argument '{pattern}'."
                )
            })

    return findings


def check_suspicious_command_line(process):
    """
    Detect suspicious command-line patterns.

    Generates one finding per process and records
    all suspicious patterns that were detected.
    """

    findings = []

    cmdline = " ".join(
        process.get("cmdline", [])
    ).lower()

    if not cmdline:
        return findings

    matched_patterns = []

    for pattern in SUSPICIOUS_COMMAND_PATTERNS:

        if pattern.lower() in cmdline:
            matched_patterns.append(pattern)

    if matched_patterns:

        rule = RULES["KD-007"]

        findings.append({
            "id": "KD-007",
            "rule": rule["name"],
            "severity": rule["severity"],
            "description": (
                "Command line contains suspicious pattern(s): "
                + ", ".join(matched_patterns)
            )
        })

    return findings

def analyze_process(process):
    """
    Run every detection module against a process.
    """

    analysis = {
        "process": process,
        "findings": []
    }

    analysis["findings"].extend(
        check_suspicious_path(process)
    )

    analysis["findings"].extend(
        check_process_name(process)
    )

    analysis["findings"].extend(
        check_missing_executable(process)
    )

    analysis["findings"].extend(
        check_suspicious_parent(process)
    )

    analysis["findings"].extend(
    check_suspicious_powershell(process)
    )

    analysis["findings"].extend(
    check_suspicious_lolbin(process)
    )

    analysis["findings"].extend(
    check_suspicious_command_line(process)
)
    


    return analysis