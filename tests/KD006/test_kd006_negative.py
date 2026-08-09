from detector.process_analyzer import analyze_process


fake_process = {
    "pid": 10000,
    "ppid": 1000,
    "parent_name": "explorer.exe",
    "name": "certutil.exe",
    "exe": r"C:\Windows\System32\certutil.exe",
    "cmdline": [
        "certutil.exe",
        "-dump",
        "certificate.cer"
    ],
    "username": "ASUS",
    "status": "running"
}


analysis = analyze_process(fake_process)

print("=" * 60)
print("KD-006 NEGATIVE TEST")
print("=" * 60)

print(analysis)

if not any(
    finding["id"] == "KD-006"
    for finding in analysis["findings"]
):
    print("\nPASS: No KD-006 finding generated.")
else:
    print("\nFAIL: KD-006 incorrectly triggered.")