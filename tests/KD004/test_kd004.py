from detector.process_analyzer import analyze_process

fake_process = {
    "pid": 5000,
    "ppid": 1000,
    "parent_name": "winword.exe",
    "name": "powershell.exe",
    "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "cmdline": [],
    "username": "ASUS",
    "status": "running"
}

analysis = analyze_process(fake_process)

print("=" * 50)
print("KD-004 TEST")
print("=" * 50)

print(analysis)