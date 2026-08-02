from detector.rules import (
    SUSPICIOUS_FOLDERS,
    TRUSTED_PROCESS_NAMES
)

from difflib import SequenceMatcher


def check_suspicious_path(process):
    findings = []

    exe_path = process.get("exe", "")
    cmdline = " ".join(process.get("cmdline", []))

    for folder in SUSPICIOUS_FOLDERS:

        # Check executable path
        if exe_path and folder.lower() in exe_path.lower():

            findings.append({
                "id": "KD-001",
                "rule": "Suspicious Executable Location",
                "severity": "Medium",
                "description": f"Executable is running from '{folder}'."
            })

        # Check command line
        elif cmdline and folder.lower() in cmdline.lower():

            findings.append({
                "id": "KD-001",
                "rule": "Suspicious Script Location",
                "severity": "Medium",
                "description": f"Command line references '{folder}'."
            })

    return findings


def check_process_name(process):
    findings = []

    process_name = process.get("name", "").lower()

    for trusted_name in TRUSTED_PROCESS_NAMES:

        similarity = SequenceMatcher(
            None,
            process_name,
            trusted_name.lower()
        ).ratio()

        if similarity >= 0.90 and process_name != trusted_name.lower():

            findings.append({
                "id": "KD-002",
                "rule": "Possible Masquerading",
                "severity": "High",
                "description": (
                    f"Process '{process_name}' is very similar to "
                    f"trusted process '{trusted_name}' "
                    f"({similarity:.2f} similarity)."
                )
            })

    return findings


def analyze_process(process):
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

    return analysis