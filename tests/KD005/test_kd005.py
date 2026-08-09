from detector.process_analyzer import analyze_process

fake_process = {
    "pid": 9999,
    "ppid": 1000,
    "parent_name": "explorer.exe",
    "name": "powershell.exe",
    "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "cmdline": [
        "powershell.exe",
        "-EncodedCommand",
        "SQBFAFgA"
    ],
    "username": "ASUS",
    "status": "running"
}

analysis = analyze_process(fake_process)

print("=" * 60)
print("KD-005 TEST")
print("=" * 60)

print(analysis)