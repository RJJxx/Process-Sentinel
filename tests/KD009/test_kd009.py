from detector.process_analyzer import analyze_process


def test_kd009_detects_process_network_correlation():
    fake_process = {
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
                "remote_ip": "192.168.1.100",
                "remote_port": 4444,
                "status": "ESTABLISHED",
            }
        ],
    }

    analysis = analyze_process(fake_process)

    assert any(
        finding["id"] == "KD-009"
        for finding in analysis["findings"]
    )