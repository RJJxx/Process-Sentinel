from detector.process_analyzer import analyze_process


def test_kd001_detects_suspicious_executable_location():

    fake_process = {
        "pid": 9999,
        "name": "python.exe",
        "exe": r"C:\Users\ASUS\Downloads\evil.exe",
        "cmdline": [],
        "username": "ASUS",
        "status": "running",
    }

    analysis = analyze_process(fake_process)

    assert any(
        finding["id"] == "KD-001"
        for finding in analysis["findings"]
    )