from detector.process_analyzer import analyze_process


def test_kd009_does_not_match_partial_folder_name():
    fake_process = {
        "pid": 10001,
        "ppid": 1000,
        "parent_name": "explorer.exe",
        "name": "legitimate_test.exe",
        "exe": r"C:\Users\ASUS\SomeDownloadsBackup\legitimate_test.exe",
        "cmdline": [],
        "username": "ASUS",
        "status": "running",
        "network_connections": [
            {
                "remote_ip": "192.168.1.100",
                "remote_port": 4444,
                "status": "ESTABLISHED",
            }
        ],
    }

    analysis = analyze_process(fake_process)

    assert not any(
        finding["id"] == "KD-009"
        for finding in analysis["findings"]
    )