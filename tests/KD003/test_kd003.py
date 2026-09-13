from detector.process_analyzer import analyze_process


def test_kd003_detects_missing_executable_path():

    fake_process = {
        "pid": 7777,
        "name": "mystery.exe",
        "exe": "",
        "cmdline": [],
        "username": "ASUS",
        "status": "running",
    }

    analysis = analyze_process(fake_process)

    assert any(
        finding["id"] == "KD-003"
        for finding in analysis["findings"]
    )