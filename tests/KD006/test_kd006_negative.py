from detector.process_analyzer import analyze_process


def test_kd006_does_not_detect_legitimate_lolbin_usage():

    fake_process = {
        "pid": 10000,
        "ppid": 1000,
        "parent_name": "explorer.exe",
        "name": "certutil.exe",
        "exe": r"C:\Windows\System32\certutil.exe",
        "cmdline": [
            "certutil.exe",
            "-dump",
            "certificate.cer",
        ],
        "username": "ASUS",
        "status": "running",
    }

    analysis = analyze_process(fake_process)

    assert not any(
        finding["id"] == "KD-006"
        for finding in analysis["findings"]
    )