from detector.process_analyzer import analyze_process


fake_process = {
    "pid": 9999,
    "ppid": 1000,
    "parent_name": "explorer.exe",
    "name": "suspicious_test.exe",

    "exe": (
        r"C:\Users\ASUS\Downloads\suspicious_test.exe"
    ),

    "cmdline": [],

    "username": "ASUS",

    "status": "running",

    "network_connections": [
        {
            "local_address": "192.168.1.10:50000",
            "remote_ip": "192.168.1.20",
            "remote_port": 4444,
            "status": "ESTABLISHED"
        }
    ]
}


analysis = analyze_process(fake_process)


print("=" * 60)
print("KD-009 TEST")
print("=" * 60)

print(analysis)


if any(
    finding["id"] == "KD-009"
    for finding in analysis["findings"]
):
    print(
        "\nPASS: KD-009 detected "
        "correlated suspicious behavior."
    )
else:
    print(
        "\nFAIL: KD-009 was not detected."
    )