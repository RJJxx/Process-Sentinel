from detector.process_analyzer import analyze_process


fake_process = {
    "pid": 9999,
    "ppid": 1000,
    "parent_name": "explorer.exe",
    "name": "cmd.exe",
    "exe": r"C:\Windows\System32\cmd.exe",
    "cmdline": [
        "cmd.exe",
        "/c",
        "net",
        "user"
    ],
    "username": "ASUS",
    "status": "running"
}


analysis = analyze_process(fake_process)

print("=" * 60)
print("KD-007 TEST")
print("=" * 60)

print(analysis)