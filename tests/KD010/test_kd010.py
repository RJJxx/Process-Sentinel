from detector.process_analyzer import analyze_process


# Fake process designed to trigger KD-010
fake_process = {
    "pid": 9999,
    "ppid": 1000,
    "parent_name": "explorer.exe",
    "name": "suspicious_startup.exe",
    "exe": r"C:\Users\ASUS\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\suspicious_startup.exe",
    "cmdline": [
        r"C:\Users\ASUS\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\suspicious_startup.exe"
    ],
    "username": "ASUS",
    "status": "running",
    "network_connections": []
}


analysis = analyze_process(fake_process)


print("=" * 60)
print("KD-010 TEST")
print("=" * 60)

print(analysis)


# Verify KD-010 was detected
if any(
    finding["id"] == "KD-010"
    for finding in analysis["findings"]
):
    print("\nPASS: KD-010 detected suspicious persistence.")
else:
    print("\nFAIL: KD-010 was not detected.")