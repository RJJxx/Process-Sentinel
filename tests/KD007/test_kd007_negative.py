from detector.process_analyzer import analyze_process


fake_process = {
    "pid": 10000,
    "ppid": 1000,
    "parent_name": "explorer.exe",
    "name": "cmd.exe",
    "exe": r"C:\Windows\System32\cmd.exe",
    "cmdline": [
        "cmd.exe",
        "/c",
        "ipconfig"
    ],
    "username": "ASUS",
    "status": "running"
}


analysis = analyze_process(fake_process)

print("=" * 60)
print("KD-007 NEGATIVE TEST")
print("=" * 60)

print(analysis)

if not any(
    finding["id"] == "KD-007"
    for finding in analysis["findings"]
):
    print("\nPASS: No KD-007 finding generated.")
else:
    print("\nFAIL: KD-007 incorrectly triggered.")