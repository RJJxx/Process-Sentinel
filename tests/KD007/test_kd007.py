from detector.process_analyzer import analyze_process


def test_kd007_detects_suspicious_commandline_activity():

    fake_process = {
        "pid": 9999,
        "ppid": 1000,
        "parent_name": "explorer.exe",
        "name": "cmd.exe",
        "exe": r"C:\Windows\System32\cmd.exe",
        "cmdline": [
            "cmd.exe",
            "/c",
            "net",
            "user",
        ],
        "username": "ASUS",
        "status": "running",
    }

    analysis = analyze_process(fake_process)

    assert any(
        finding["id"] == "KD-007"
        for finding in analysis["findings"]
    )