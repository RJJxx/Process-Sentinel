from detector.process_analyzer import analyze_process


fake_process = {
    "pid": 9999,
    "ppid": 1000,
    "parent_name": "explorer.exe",
    "name": "certutil.exe",
    "exe": r"C:\Windows\System32\certutil.exe",
    "cmdline": [
        "certutil.exe",
        "-decode",
        "input.txt",
        "output.exe"
    ],
    "username": "ASUS",
    "status": "running"
}


analysis = analyze_process(fake_process)

print("=" * 60)
print("KD-006 TEST")
print("=" * 60)

print(analysis)