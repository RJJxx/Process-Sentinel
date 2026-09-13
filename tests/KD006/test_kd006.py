from detector.process_analyzer import analyze_process


def test_kd006_detects_suspicious_lolbin_usage():

    fake_process = {
        "pid": 9999,
        "ppid": 1000,
        "parent_name": "explorer.exe",
        "name": "certutil.exe",
        "exe": r"C:\Windows\System32\certutil.exe",
        "cmdline": [
            "certutil.exe",
            "-decode",
            "input.txt",
            "output.exe",
        ],
        "username": "ASUS",
        "status": "running",
    }

    analysis = analyze_process(fake_process)

    assert any(
        finding["id"] == "KD-006"
        for finding in analysis["findings"]
    )