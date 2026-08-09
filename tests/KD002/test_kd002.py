from detector.process_analyzer import analyze_process

fake_process = {
    "pid": 8888,
    "name": "svch0st.exe",          # Notice the zero
    "exe": r"C:\Windows\System32\svch0st.exe",
    "cmdline": [],
    "username": "SYSTEM",
    "status": "running"
}

analysis = analyze_process(fake_process)

print("=" * 50)
print("KD-002 TEST")
print("=" * 50)

print(analysis)