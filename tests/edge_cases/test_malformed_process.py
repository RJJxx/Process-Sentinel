from detector.process_analyzer import analyze_process


def test_empty_process_data_does_not_crash():
    fake_process = {}

    analysis = analyze_process(fake_process)

    assert isinstance(analysis, dict)
    assert "findings" in analysis



def test_missing_executable_path_does_not_crash():
    fake_process = {
        "pid": 1234,
        "name": "unknown.exe",
        "exe": "",
        "cmdline": [],
        "username": "ASUS",
        "status": "running",
    }

    analysis = analyze_process(fake_process)

    assert isinstance(analysis, dict)
    assert "findings" in analysis


def test_missing_commandline_does_not_crash():
    fake_process = {
        "pid": 1235,
        "name": "unknown.exe",
        "exe": r"C:\Windows\System32\unknown.exe",
        "username": "ASUS",
        "status": "running",
    }

    analysis = analyze_process(fake_process)

    assert isinstance(analysis, dict)
    assert "findings" in analysis


def test_missing_network_connections_does_not_crash():
    fake_process = {
        "pid": 1236,
        "name": "unknown.exe",
        "exe": r"C:\Windows\System32\unknown.exe",
        "cmdline": [],
        "username": "ASUS",
        "status": "running",
    }

    analysis = analyze_process(fake_process)

    assert isinstance(analysis, dict)
    assert "findings" in analysis   


def test_malformed_network_connection_does_not_crash():
    fake_process = {
        "pid": 1237,
        "name": "unknown.exe",
        "exe": r"C:\Windows\System32\unknown.exe",
        "cmdline": [],
        "username": "ASUS",
        "status": "running",
        "network_connections": [
            {}
        ],
    }

    analysis = analyze_process(fake_process)

    assert isinstance(analysis, dict)
    assert "findings" in analysis



def test_none_process_values_do_not_crash():
    fake_process = {
        "pid": 1238,
        "name": None,
        "exe": None,
        "cmdline": None,
        "username": None,
        "status": None,
        "network_connections": None,
    }

    analysis = analyze_process(fake_process)

    assert isinstance(analysis, dict)
    assert "findings" in analysis
        
