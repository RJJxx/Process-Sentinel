from detector.process_analyzer import analyze_process

# Fake process that should trigger KD-001
fake_process = {
    "pid": 9999,
    "name": "python.exe",
    "exe": r"C:\Users\ASUS\Downloads\evil.exe",
    "cmdline": [],
    "username": "ASUS",
    "status": "running"
}

analysis = analyze_process(fake_process)

print("=" * 50)
print("KD-001 TEST")
print("=" * 50)

print(analysis)