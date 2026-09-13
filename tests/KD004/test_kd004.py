from detector.process_analyzer import analyze_process


def test_kd004_detects_suspicious_parent_process():

    fake_process = {
        "pid": 5000,
        "ppid": 1000,
        "parent_name": "winword.exe",
        "name": "powershell.exe",
        "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "cmdline": [],
        "username": "ASUS",
        "status": "running",
    }

    analysis = analyze_process(fake_process)

    assert any(
        finding["id"] == "KD-004"
        for finding in analysis["findings"]
    )