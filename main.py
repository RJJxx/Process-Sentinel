from detector.process_monitor import get_running_processes
from detector.process_analyzer import analyze_process


def main():
    print("=" * 50)
    print("Keylogger Detector")
    print("=" * 50)

    print("\nScanning running processes...\n")

    # Get all running processes
    processes = get_running_processes()

    print(f"Total Processes Found: {len(processes)}\n")

    # For now, analyze ONLY the first process
    first_process = processes[0]

    analysis = analyze_process(first_process)

    print("Analysis Result:\n")
    print(analysis)


if __name__ == "__main__":
    main()