from detector.process_analyzer import analyze_process


fake_process = {
    "pid": 9999,
    "ppid": 1000,
    "parent_name": "explorer.exe",
    "name": "test_network_process.exe",
    "exe": r"C:\Users\ASUS\Downloads\test_network_process.exe",
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
print("KD-008 TEST")
print("=" * 60)

print(analysis)


if any(
    finding["id"] == "KD-008"
    for finding in analysis["findings"]
):
    print("\nPASS: KD-008 detected suspicious network activity.")
else:
    print("\nFAIL: KD-008 was not detected.")