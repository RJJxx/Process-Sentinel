from detector.process_analyzer import analyze_process

fake_process = {
    "pid": 7777,
    "name": "mystery.exe",
    "exe": "",
    "cmdline": [],
    "username": "ASUS",
    "status": "running"
}

analysis = analyze_process(fake_process)

print("=" * 50)
print("KD-003 TEST")
print("=" * 50)

print(analysis)