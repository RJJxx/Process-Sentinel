"""
Detection Engine
================

Central orchestration layer for the Keylogger Detector.

Responsibilities:
    1. Receive a process
    2. Run the process through the analysis engine
    3. Collect findings
    4. Calculate/return risk information
    5. Determine whether an alert should be generated
    6. Return a consistent detection result
"""

from detector.process_analyzer import analyze_process


# ============================================================
# ALERT CONFIGURATION
# ============================================================

# A process reaching this risk level should generate an alert.
ALERT_RISK_LEVELS = {
    "High",
    "Critical",
}


# A numerical score at or above this value should generate
# an alert even if the textual risk level is not available.
ALERT_SCORE_THRESHOLD = 50


# ============================================================
# DETECTION ENGINE
# ============================================================

def run_detection(process):
    """
    Run the complete detection pipeline against one process.

    Parameters
    ----------
    process : dict
        Process information collected by the process monitor.

    Returns
    -------
    dict
        Structured detection result containing:

            process
            findings
            risk_score
            risk_level
            confidence
            evidence
            alert
            alert_reason
    """

    # --------------------------------------------------------
    # Basic input validation
    # --------------------------------------------------------

    if not isinstance(process, dict):
        raise TypeError(
            "process must be a dictionary"
        )

    # --------------------------------------------------------
    # Run the complete analyzer
    # --------------------------------------------------------

    analysis = analyze_process(process)

    # --------------------------------------------------------
    # Extract analysis information
    # --------------------------------------------------------

    findings = analysis.get(
        "findings",
        []
    )

    risk_score = analysis.get(
        "risk_score",
        0
    )

    risk_level = analysis.get(
        "risk_level",
        "Low"
    )

    confidence = analysis.get(
        "confidence",
        "Low"
    )

    evidence = analysis.get(
        "evidence",
        []
    )

    # --------------------------------------------------------
    # Determine whether an alert should be generated
    # --------------------------------------------------------

    alert = False
    alert_reason = None

    # High/Critical risk automatically generates an alert.
    if risk_level in ALERT_RISK_LEVELS:

        alert = True

        alert_reason = (
            f"Risk level is {risk_level}."
        )

    # Score threshold provides an additional safety check.
    elif isinstance(risk_score, (int, float)):

        if risk_score >= ALERT_SCORE_THRESHOLD:

            alert = True

            alert_reason = (
                f"Risk score {risk_score} reached "
                f"the alert threshold of "
                f"{ALERT_SCORE_THRESHOLD}."
            )

    # Findings with high severity should also generate
    # an alert.
    if not alert:

        for finding in findings:

            severity = str(
                finding.get(
                    "severity",
                    ""
                )
            ).lower()

            if severity == "high":

                alert = True

                alert_reason = (
                    "A high-severity detection finding "
                    "was generated."
                )

                break

    # --------------------------------------------------------
    # Build final engine result
    # --------------------------------------------------------

    result = {
        "process": process,
        "findings": findings,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "evidence": evidence,
        "alert": alert,
        "alert_reason": alert_reason,
    }

    return result


# ============================================================
# CONVENIENCE FUNCTIONS
# ============================================================

def is_suspicious(result):
    """
    Return True if the detection engine considers the
    process suspicious enough to require attention.
    """

    if not isinstance(result, dict):
        return False

    return bool(
        result.get("alert", False)
    )


def get_alert_summary(result):
    """
    Generate a compact summary suitable for logging
    or future reporting.
    """

    process = result.get(
        "process",
        {}
    )

    process_name = process.get(
        "name",
        "Unknown"
    )

    pid = process.get(
        "pid",
        "Unknown"
    )

    risk_score = result.get(
        "risk_score",
        0
    )

    risk_level = result.get(
        "risk_level",
        "Low"
    )

    confidence = result.get(
        "confidence",
        "Low"
    )

    findings = result.get(
        "findings",
        []
    )

    alert = result.get(
        "alert",
        False
    )

    return {
        "process_name": process_name,
        "pid": pid,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "finding_count": len(findings),
        "alert": alert,
        "alert_reason": result.get(
            "alert_reason"
        ),
    }


# ============================================================
# BATCH PROCESSING
# ============================================================

def run_detection_batch(processes):
    """
    Run the detection engine against multiple processes.

    Parameters
    ----------
    processes : list
        List of process dictionaries.

    Returns
    -------
    list
        Detection results for every process.
    """

    if not isinstance(processes, list):
        raise TypeError(
            "processes must be a list"
        )

    results = []

    for process in processes:

        try:

            result = run_detection(
                process
            )

            results.append(result)

        except Exception as error:

            # Keep one malformed process from stopping
            # analysis of the remaining processes.
            results.append({
                "process": process,
                "findings": [],
                "risk_score": 0,
                "risk_level": "Unknown",
                "confidence": "Unknown",
                "evidence": [],
                "alert": False,
                "alert_reason": None,
                "error": str(error),
            })

    return results


def get_alerts(results):
    """
    Return only results that generated an alert.
    """

    if not isinstance(results, list):
        return []

    return [
        result
        for result in results
        if result.get("alert", False)
    ]