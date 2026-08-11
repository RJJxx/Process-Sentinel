from detector.detection_engine import (
    run_detection,
    is_suspicious,
    get_alert_summary,
    run_detection_batch,
    get_alerts,
)


def create_suspicious_process():
    """
    Create a controlled suspicious process for testing
    the detection engine.
    """

    return {
        "pid": 9999,
        "ppid": 1000,
        "parent_name": "explorer.exe",
        "name": "suspicious_test.exe",
        "exe": r"C:\Users\ASUS\Downloads\suspicious_test.exe",
        "cmdline": [],
        "username": "ASUS",
        "status": "running",
        "network_connections": [
            {
                "local_address": "192.168.1.10:50000",
                "remote_ip": "192.168.1.20",
                "remote_port": 4444,
                "status": "ESTABLISHED",
            }
        ],
    }


def create_legitimate_process():
    """
    Create a normal Windows process.
    """

    return {
        "pid": 10000,
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


# ============================================================
# TEST 1 - SUSPICIOUS PROCESS
# ============================================================

def test_suspicious_process_generates_alert():

    process = create_suspicious_process()

    result = run_detection(process)

    print("=" * 60)
    print("DETECTION ENGINE TEST 1")
    print("SUSPICIOUS PROCESS")
    print("=" * 60)

    print(result)

    assert result["alert"] is True

    assert result["risk_level"] in (
        "High",
        "Critical",
    )

    assert result["risk_score"] > 0

    assert len(result["findings"]) > 0

    assert len(result["evidence"]) > 0

    print("PASS: Suspicious process generated an alert.")


# ============================================================
# TEST 2 - is_suspicious()
# ============================================================

def test_is_suspicious():

    process = create_suspicious_process()

    result = run_detection(process)

    print("=" * 60)
    print("DETECTION ENGINE TEST 2")
    print("IS SUSPICIOUS")
    print("=" * 60)

    assert is_suspicious(result) is True

    print("PASS: Suspicious process correctly identified.")


# ============================================================
# TEST 3 - ALERT SUMMARY
# ============================================================

def test_alert_summary():

    process = create_suspicious_process()

    result = run_detection(process)

    summary = get_alert_summary(result)

    print("=" * 60)
    print("DETECTION ENGINE TEST 3")
    print("ALERT SUMMARY")
    print("=" * 60)

    print(summary)

    assert summary["process_name"] == "suspicious_test.exe"

    assert summary["pid"] == 9999

    assert summary["risk_score"] > 0

    assert summary["finding_count"] > 0

    assert summary["alert"] is True

    print("PASS: Alert summary generated correctly.")


# ============================================================
# TEST 4 - BATCH PROCESSING
# ============================================================

def test_batch_processing():

    suspicious_process = create_suspicious_process()

    legitimate_process = create_legitimate_process()

    processes = [
        suspicious_process,
        legitimate_process,
    ]

    results = run_detection_batch(processes)

    print("=" * 60)
    print("DETECTION ENGINE TEST 4")
    print("BATCH PROCESSING")
    print("=" * 60)

    print(results)

    assert len(results) == 2

    assert results[0]["alert"] is True

    assert results[1]["alert"] is False

    print("PASS: Batch processing handled both processes correctly.")


# ============================================================
# TEST 5 - GET ALERTS
# ============================================================

def test_get_alerts():

    suspicious_process = create_suspicious_process()

    legitimate_process = create_legitimate_process()

    results = run_detection_batch([
        suspicious_process,
        legitimate_process,
    ])

    alerts = get_alerts(results)

    print("=" * 60)
    print("DETECTION ENGINE TEST 5")
    print("GET ALERTS")
    print("=" * 60)

    print(alerts)

    assert len(alerts) == 1

    assert alerts[0]["alert"] is True

    assert (
        alerts[0]["process"]["name"]
        == "suspicious_test.exe"
    )

    print("PASS: Alert filtering works correctly.")


# ============================================================
# RUN TESTS DIRECTLY
# ============================================================

if __name__ == "__main__":

    test_suspicious_process_generates_alert()

    test_is_suspicious()

    test_alert_summary()

    test_batch_processing()

    test_get_alerts()

    print("=" * 60)
    print("ALL DETECTION ENGINE TESTS PASSED")
    print("=" * 60)