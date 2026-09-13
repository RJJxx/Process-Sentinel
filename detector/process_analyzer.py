from detector.rules import (
    SUSPICIOUS_FOLDERS,
    TRUSTED_PROCESS_NAMES,
    SYSTEM_PROCESSES,
    RULES,
    SUSPICIOUS_PARENT_CHILD,
    SUSPICIOUS_LOLBINS,
    SUSPICIOUS_NETWORK_PORTS,
    SUSPICIOUS_POWERSHELL_FLAGS,
    SUSPICIOUS_LOLBIN_PATTERNS,
    SUSPICIOUS_COMMAND_PATTERNS,
    SUSPICIOUS_PERSISTENCE_LOCATIONS,
    calculate_risk_score,
    get_risk_level,
)

from difflib import SequenceMatcher


def check_suspicious_path(process):
    """
    KD-001:
    Detect executables or scripts running from suspicious
    Windows user-writable locations.

    The check is based on actual path components rather than
    simply matching a word anywhere in the path.
    """

    findings = []

    exe_path = str(
        process.get("exe", "") or ""
    )

    cmdline = " ".join(
        process.get("cmdline") or []
    )

    # --------------------------------------------------------
    # Normalize Windows paths
    # --------------------------------------------------------

    exe_normalized = exe_path.replace(
        "/",
        "\\"
    ).lower()

    cmdline_normalized = cmdline.replace(
        "/",
        "\\"
    ).lower()

    # --------------------------------------------------------
    # Check executable path
    # --------------------------------------------------------

    matched_locations = []

    for folder in SUSPICIOUS_FOLDERS:

        folder_name = folder.strip(
            "\\/"
        ).lower()

        path_parts = [
            part
            for part in exe_normalized.split("\\")
            if part
        ]

        if folder_name in path_parts:

            matched_locations.append(
                folder
            )

    # --------------------------------------------------------
    # Check command line
    #
    # We keep command-line detection because a script or
    # executable may be referenced there even when the actual
    # process executable is elsewhere.
    # --------------------------------------------------------

    command_matches = []

    for folder in SUSPICIOUS_FOLDERS:

        folder_name = folder.strip(
            "\\/"
        ).lower()

        if (
            f"\\{folder_name}\\" in
            cmdline_normalized
            or
            cmdline_normalized.endswith(
                f"\\{folder_name}"
            )
        ):

            command_matches.append(
                folder
            )

    # --------------------------------------------------------
    # Build one KD-001 finding
    # --------------------------------------------------------

    matched_locations.extend(
        command_matches
    )

    # Remove duplicates while preserving order
    matched_locations = list(
        dict.fromkeys(
            matched_locations
        )
    )

    if matched_locations:

        rule = RULES["KD-001"]

        findings.append({
            "id": "KD-001",
            "rule": rule["name"],
            "severity": rule["severity"],
            "description": (
                "Process references suspicious "
                "user-writable location(s): "
                + ", ".join(
                    matched_locations
                )
                + "."
            )
        })

    return findings


def check_process_name(process):
    """
    KD-002:
    Detect process names that resemble trusted Windows processes.
    """

    findings = []

    process_name = (
        process.get("name") or ""
    ).lower()

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
    KD-003:
    Detect processes that do not expose an executable path.
    Ignore known Windows system processes.
    """

    findings = []

    exe_path = process.get("exe", "") or ""

    process_name = (
        process.get("name") or ""
    ).lower()

    if process_name in SYSTEM_PROCESSES:
        return findings

    if not exe_path:

        rule = RULES["KD-003"]

        findings.append({
            "id": "KD-003",
            "rule": rule["name"],
            "severity": rule["severity"],
            "description": (
                f"Process '{process_name}' does not expose "
                f"an executable path."
            )
        })

    return findings


def check_suspicious_parent(process):
    """
    KD-004:
    Detect suspicious parent-child process relationships.
    """

    findings = []

    process_name = (
        process.get("name") or ""
    ).lower()

    parent_name = (
        process.get("parent_name") or ""
    ).lower()

    if process_name in SUSPICIOUS_PARENT_CHILD:

        suspicious_parents = SUSPICIOUS_PARENT_CHILD[
            process_name
        ]

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
    KD-005:
    Detect suspicious PowerShell execution.
    """

    findings = []

    process_name = (
        process.get("name") or ""
    ).lower()

    if process_name != "powershell.exe":
        return findings

    cmdline = " ".join(
        process.get("cmdline") or []
    ).lower()

    for flag in SUSPICIOUS_POWERSHELL_FLAGS:

        if flag in cmdline:

            rule = RULES["KD-005"]

            findings.append({
                "id": "KD-005",
                "rule": rule["name"],
                "severity": rule["severity"],
                "description": (
                    f"PowerShell executed with suspicious flag "
                    f"'{flag}'."
                )
            })

    return findings


def check_suspicious_lolbin(process):
    """
    KD-006:
    Detect suspicious usage of legitimate Windows LOLBins.
    """

    findings = []

    process_name = (
        process.get("name") or ""
    ).lower()

    cmdline = " ".join(
        process.get("cmdline") or []
    ).lower()

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
    KD-007:
    Detect suspicious command-line patterns.

    Generates one finding per process and records
    all suspicious patterns that were detected.
    """

    findings = []

    cmdline = " ".join(
        process.get("cmdline") or []
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


def check_suspicious_network(process):
    """
    KD-008:
    Detect processes making connections to suspicious
    remote network ports.
    """

    findings = []

    process_name = (
        process.get("name") or "Unknown"
    )

    connections = process.get(
        "network_connections"
    ) or []

    if not connections:
        return findings

    matched_ports = []

    for connection in connections:

        remote_port = connection.get(
            "remote_port"
        )

        remote_ip = connection.get(
            "remote_ip",
            ""
        ) or ""

        # Ignore connections without a remote endpoint
        if not remote_ip or not remote_port:
            continue

        if remote_port in SUSPICIOUS_NETWORK_PORTS:

            matched_ports.append(
                f"{remote_ip}:{remote_port}"
            )

    if matched_ports:

        rule = RULES["KD-008"]

        findings.append({
            "id": "KD-008",
            "rule": rule["name"],
            "severity": rule["severity"],
            "description": (
                f"Process '{process_name}' is connected "
                f"to suspicious network endpoint(s): "
                f"{', '.join(matched_ports)}."
            )
        })

    return findings


def check_process_network_correlation(process):
    """
    KD-009:
    Detect processes that combine suspicious execution
    location with suspicious outbound network activity.
    """

    findings = []

    exe_path = (
        process.get("exe") or ""
    )

    process_name = (
        process.get("name") or "Unknown"
    )

    connections = process.get(
        "network_connections"
    ) or []

    # Check whether the executable is in a suspicious folder
    suspicious_location = False
    matched_folder = None

        # Check whether the executable is in a suspicious folder
    suspicious_location = False
    matched_folder = None

    if exe_path:

        exe_normalized = exe_path.replace(
            "/",
            "\\"
        ).lower()

        path_parts = [
            part
            for part in exe_normalized.split("\\")
            if part
        ]

        for folder in SUSPICIOUS_FOLDERS:

            folder_name = folder.strip(
                "\\/"
            ).lower()

            if folder_name in path_parts:

                suspicious_location = True
                matched_folder = folder

                break

    if not suspicious_location:
        return findings

    # Check network connections
    suspicious_connections = []

    for connection in connections:

        remote_ip = connection.get(
            "remote_ip",
            ""
        ) or ""

        remote_port = connection.get(
            "remote_port"
        )

        status = connection.get(
            "status",
            ""
        ) or ""

        if (
            remote_ip
            and remote_port in SUSPICIOUS_NETWORK_PORTS
            and status.upper() == "ESTABLISHED"
        ):

            suspicious_connections.append(
                f"{remote_ip}:{remote_port}"
            )

    if suspicious_connections:

        rule = RULES["KD-009"]

        findings.append({
            "id": "KD-009",
            "rule": rule["name"],
            "severity": rule["severity"],
            "description": (
                f"Process '{process_name}' is running from "
                f"suspicious location '{matched_folder}' "
                f"and has an established connection to "
                f"suspicious endpoint(s): "
                f"{', '.join(suspicious_connections)}."
            )
        })

    return findings


def check_suspicious_persistence(process):
    """
    KD-010:
    Detect processes whose executable path or command line
    references suspicious Windows persistence locations.
    """

    findings = []

    process_name = (
        process.get(
            "name"
        ) or "Unknown"
    )

    exe_path = (
        process.get(
            "exe"
        ) or ""
    )

    cmdline = " ".join(
        process.get(
            "cmdline"
        ) or []
    )

    combined_data = (
        f"{exe_path} {cmdline}"
    ).lower()

    if not combined_data.strip():
        return findings

    matched_locations = []

    for location in SUSPICIOUS_PERSISTENCE_LOCATIONS:

        if location.lower() in combined_data:

            matched_locations.append(
                location
            )

    if matched_locations:

        rule = RULES["KD-010"]

        findings.append({
            "id": "KD-010",
            "rule": rule["name"],
            "severity": rule["severity"],
            "description": (
                f"Process '{process_name}' references "
                f"suspicious persistence location(s): "
                f"{', '.join(matched_locations)}."
            )
        })

    return findings


# ============================================================
# EVIDENCE AND CONFIDENCE
# ============================================================

def build_evidence(findings):
    """
    Build a structured evidence list from detection findings.

    Evidence keeps the original detection information while
    making it easier for later reporting and investigation.
    """

    evidence = []

    for finding in findings:

        evidence.append({
            "id": finding.get("id"),
            "rule": finding.get("rule"),
            "severity": finding.get("severity"),
            "description": finding.get("description")
        })

    return evidence


def calculate_confidence(findings):
    """
    Calculate detection confidence based on the available evidence.

    Confidence is intentionally separate from risk level.

    No findings:
        Low

    One low/medium finding:
        Medium

    One high-severity finding:
        High

    Multiple findings:
        High

    Multiple independent high/medium findings:
        Very High
    """

    if not findings:
        return "Low"

    severities = [
        str(
            finding.get(
                "severity",
                ""
            )
        ).lower()
        for finding in findings
    ]

    high_count = severities.count("high")
    medium_count = severities.count("medium")

    # Multiple independent findings provide stronger evidence.
    if len(findings) >= 3:
        return "Very High"

    # Two findings, especially if one is high severity.
    if len(findings) >= 2 and (
        high_count >= 1 or medium_count >= 2
    ):
        return "Very High"

    # A single high-severity detection.
    if high_count >= 1:
        return "High"

    # A single medium-severity detection.
    if medium_count >= 1:
        return "Medium"

    return "Low"


def analyze_process(process):
    """
    Run every detection module against a process.

    Returns:
        process
        findings
        risk_score
        risk_level
        confidence
        evidence
    """

    analysis = {
        "process": process,
        "findings": []
    }

    # ========================================================
    # DETECTION MODULES
    # ========================================================

    # KD-001
    analysis["findings"].extend(
        check_suspicious_path(process)
    )

    # KD-002
    analysis["findings"].extend(
        check_process_name(process)
    )

    # KD-003
    analysis["findings"].extend(
        check_missing_executable(process)
    )

    # KD-004
    analysis["findings"].extend(
        check_suspicious_parent(process)
    )

    # KD-005
    analysis["findings"].extend(
        check_suspicious_powershell(process)
    )

    # KD-006
    analysis["findings"].extend(
        check_suspicious_lolbin(process)
    )

    # KD-007
    analysis["findings"].extend(
        check_suspicious_command_line(process)
    )

    # KD-008
    analysis["findings"].extend(
        check_suspicious_network(process)
    )

    # KD-009
    analysis["findings"].extend(
        check_process_network_correlation(process)
    )

    # KD-010
    analysis["findings"].extend(
        check_suspicious_persistence(process)
    )

    # ========================================================
    # RISK SCORING
    # ========================================================

    risk_score = calculate_risk_score(
        analysis["findings"]
    )

    risk_level = get_risk_level(
        risk_score
    )

    analysis["risk_score"] = risk_score
    analysis["risk_level"] = risk_level

    # ========================================================
    # EVIDENCE
    # ========================================================

    analysis["evidence"] = build_evidence(
        analysis["findings"]
    )

    # ========================================================
    # CONFIDENCE
    # ========================================================

    analysis["confidence"] = calculate_confidence(
        analysis["findings"]
    )

    return analysis