from detector.process_analyzer import analyze_process


def test_kd005_detects_suspicious_powershell_execution():

    fake_process = {
        "pid": 9999,
        "ppid": 1000,
        "parent_name": "explorer.exe",
        "name": "powershell.exe",
        "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "cmdline": [
            "powershell.exe",
            "-EncodedCommand",
            "SQBFAFgA",
        ],
        "username": "ASUS",
        "status": "running",
    }

    analysis = analyze_process(fake_process)

    assert any(
        finding["id"] == "KD-005"
        for finding in analysis["findings"]
    )