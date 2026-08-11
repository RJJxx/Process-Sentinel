from detector.detection_engine import (
    run_detection,
    is_suspicious,
    run_detection_batch,
    get_alerts,
)


# ============================================================
# LEGITIMATE PROCESS FACTORIES
# ============================================================

def create_svchost_process():
    """
    Normal Windows svchost.exe process.
    """

    return {
        "pid": 10001,
        "ppid": 500,
        "parent_name": "services.exe",
        "name": "svchost.exe",
        "exe": r"C:\Windows\System32\svchost.exe",
        "cmdline": [
            r"C:\Windows\System32\svchost.exe",
            "-k",
            "LocalService",
        ],
        "username": r"NT AUTHORITY\SYSTEM",
        "status": "running",
        "network_connections": [],
    }


def create_explorer_process():
    """
    Normal Windows explorer.exe process.
    """

    return {
        "pid": 10002,
        "ppid": 500,
        "parent_name": "userinit.exe",
        "name": "explorer.exe",
        "exe": r"C:\Windows\explorer.exe",
        "cmdline": [
            r"C:\Windows\explorer.exe",
        ],
        "username": "ASUS",
        "status": "running",
        "network_connections": [],
    }


def create_services_process():
    """
    Normal Windows services.exe process.
    """

    return {
        "pid": 10003,
        "ppid": 500,
        "parent_name": "wininit.exe",
        "name": "services.exe",
        "exe": r"C:\Windows\System32\services.exe",
        "cmdline": [
            r"C:\Windows\System32\services.exe",
        ],
        "username": r"NT AUTHORITY\SYSTEM",
        "status": "running",
        "network_connections": [],
    }


def create_legitimate_network_process():
    """
    Legitimate process with a normal HTTPS connection.
    """

    return {
        "pid": 10004,
        "ppid": 500,
        "parent_name": "userinit.exe",
        "name": "explorer.exe",
        "exe": r"C:\Windows\explorer.exe",
        "cmdline": [
            r"C:\Windows\explorer.exe",
        ],
        "username": "ASUS",
        "status": "running",
        "network_connections": [
            {
                "local_address": "192.168.1.10:50001",
                "remote_ip": "142.250.72.14",
                "remote_port": 443,
                "status": "ESTABLISHED",
            }
        ],
    }


def create_legitimate_commandline_process():
    """
    Legitimate Windows command-line activity.
    """

    return {
        "pid": 10005,
        "ppid": 500,
        "parent_name": "explorer.exe",
        "name": "cmd.exe",
        "exe": r"C:\Windows\System32\cmd.exe",
        "cmdline": [
            r"C:\Windows\System32\cmd.exe",
            "/c",
            "ipconfig",
        ],
        "username": "ASUS",
        "status": "running",
        "network_connections": [],
    }


# ============================================================
# TEST 1 - SVCHOST
# ============================================================

def test_svchost_no_alert():

    process = create_svchost_process()

    result = run_detection(process)

    print("=" * 60)
    print("DETECTION ENGINE NEGATIVE TEST 1")
    print("PROCESS: svchost.exe")
    print("=" * 60)

    print(result)

    assert result["alert"] is False
    assert result["risk_score"] == 0
    assert result["risk_level"] == "Low"
    assert result["findings"] == []

    print("PASS: svchost.exe generated no alert.")


# ============================================================
# TEST 2 - EXPLORER
# ============================================================

def test_explorer_no_alert():

    process = create_explorer_process()

    result = run_detection(process)

    print("=" * 60)
    print("DETECTION ENGINE NEGATIVE TEST 2")
    print("PROCESS: explorer.exe")
    print("=" * 60)

    print(result)

    assert result["alert"] is False
    assert result["risk_score"] == 0
    assert result["risk_level"] == "Low"
    assert result["findings"] == []

    print("PASS: explorer.exe generated no alert.")


# ============================================================
# TEST 3 - SERVICES
# ============================================================

def test_services_no_alert():

    process = create_services_process()

    result = run_detection(process)

    print("=" * 60)
    print("DETECTION ENGINE NEGATIVE TEST 3")
    print("PROCESS: services.exe")
    print("=" * 60)

    print(result)

    assert result["alert"] is False
    assert result["risk_score"] == 0
    assert result["risk_level"] == "Low"
    assert result["findings"] == []

    print("PASS: services.exe generated no alert.")


# ============================================================
# TEST 4 - LEGITIMATE NETWORK
# ============================================================

def test_legitimate_network_no_alert():

    process = create_legitimate_network_process()

    result = run_detection(process)

    print("=" * 60)
    print("DETECTION ENGINE NEGATIVE TEST 4")
    print("LEGITIMATE NETWORK ACTIVITY")
    print("=" * 60)

    print(result)

    assert result["alert"] is False
    assert result["risk_score"] == 0
    assert result["risk_level"] == "Low"
    assert result["findings"] == []

    print("PASS: Legitimate network activity generated no alert.")


# ============================================================
# TEST 5 - LEGITIMATE COMMAND LINE
# ============================================================

def test_legitimate_commandline_no_alert():

    process = create_legitimate_commandline_process()

    result = run_detection(process)

    print("=" * 60)
    print("DETECTION ENGINE NEGATIVE TEST 5")
    print("LEGITIMATE COMMAND-LINE ACTIVITY")
    print("=" * 60)

    print(result)

    assert result["alert"] is False
    assert result["risk_score"] == 0
    assert result["risk_level"] == "Low"
    assert result["findings"] == []

    print("PASS: Legitimate command-line activity generated no alert.")


# ============================================================
# TEST 6 - is_suspicious()
# ============================================================

def test_legitimate_process_is_not_suspicious():

    processes = [
        create_svchost_process(),
        create_explorer_process(),
        create_services_process(),
        create_legitimate_network_process(),
        create_legitimate_commandline_process(),
    ]

    print("=" * 60)
    print("DETECTION ENGINE NEGATIVE TEST 6")
    print("IS SUSPICIOUS CHECK")
    print("=" * 60)

    for process in processes:

        result = run_detection(process)

        assert is_suspicious(result) is False

        print(
            f"PASS: {process['name']} "
            f"is not considered suspicious."
        )


# ============================================================
# TEST 7 - LEGITIMATE BATCH
# ============================================================

def test_legitimate_batch_no_alerts():

    processes = [
        create_svchost_process(),
        create_explorer_process(),
        create_services_process(),
        create_legitimate_network_process(),
        create_legitimate_commandline_process(),
    ]

    results = run_detection_batch(processes)

    print("=" * 60)
    print("DETECTION ENGINE NEGATIVE TEST 7")
    print("LEGITIMATE BATCH PROCESSING")
    print("=" * 60)

    assert len(results) == 5

    for result in results:

        print(result)

        assert result["alert"] is False
        assert result["risk_score"] == 0
        assert result["risk_level"] == "Low"
        assert result["findings"] == []

    print("PASS: All legitimate processes remained low risk.")


# ============================================================
# TEST 8 - GET ALERTS
# ============================================================

def test_legitimate_batch_has_no_alerts():

    processes = [
        create_svchost_process(),
        create_explorer_process(),
        create_services_process(),
        create_legitimate_network_process(),
        create_legitimate_commandline_process(),
    ]

    results = run_detection_batch(processes)

    alerts = get_alerts(results)

    print("=" * 60)
    print("DETECTION ENGINE NEGATIVE TEST 8")
    print("ALERT FILTER")
    print("=" * 60)

    print("Alerts:", alerts)

    assert alerts == []

    print("PASS: No alerts generated for legitimate processes.")


# ============================================================
# RUN ALL TESTS DIRECTLY
# ============================================================

if __name__ == "__main__":

    test_svchost_no_alert()

    test_explorer_no_alert()

    test_services_no_alert()

    test_legitimate_network_no_alert()

    test_legitimate_commandline_no_alert()

    test_legitimate_process_is_not_suspicious()

    test_legitimate_batch_no_alerts()

    test_legitimate_batch_has_no_alerts()

    print("=" * 60)
    print("ALL DETECTION ENGINE NEGATIVE TESTS PASSED")
    print("=" * 60)