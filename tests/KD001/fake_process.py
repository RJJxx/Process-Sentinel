import os
import time

print("=" * 50)
print("KD-001 TEST PROCESS")
print("=" * 50)

print(f"PID : {os.getpid()}")
print("Waiting...")

while True:
    time.sleep(1)