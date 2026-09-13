from detector.process_analyzer import analyze_process


def test_kd010_detects_suspicious_startup_persistence():
    fake_process = {
        "pid": 9999,
        "ppid": 1000,
        "parent_name": "explorer.exe",
        "name": "suspicious_startup.exe",
        "exe": r"C:\Users\ASUS\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\suspicious_startup.exe",
        "cmdline": [
            r"C:\Users\ASUS\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\suspicious_startup.exe"
        ],
        "username": "ASUS",
        "status": "running",
        "network_connections": [],
    }

    analysis = analyze_process(fake_process)

    assert any(
        finding["id"] == "KD-010"
        for finding in analysis["findings"]
    )