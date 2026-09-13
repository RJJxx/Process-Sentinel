from detector.process_analyzer import analyze_process


def test_kd002_detects_process_name_masquerading():

    fake_process = {
        "pid": 8888,
        "name": "svch0st.exe",
        "exe": r"C:\Windows\System32\svch0st.exe",
        "cmdline": [],
        "username": "SYSTEM",
        "status": "running",
    }

    analysis = analyze_process(fake_process)

    assert any(
        finding["id"] == "KD-002"
        for finding in analysis["findings"]
    )