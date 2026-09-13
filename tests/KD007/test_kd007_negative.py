from detector.process_analyzer import analyze_process


def test_kd007_does_not_detect_legitimate_commandline():

    fake_process = {
        "pid": 10000,
        "ppid": 1000,
        "parent_name": "explorer.exe",
        "name": "cmd.exe",
        "exe": r"C:\Windows\System32\cmd.exe",
        "cmdline": [
            "cmd.exe",
            "/c",
            "ipconfig",
        ],
        "username": "ASUS",
        "status": "running",
    }

    analysis = analyze_process(fake_process)

    assert not any(
        finding["id"] == "KD-007"
        for finding in analysis["findings"]
    )