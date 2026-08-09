from detector.process_monitor import get_running_processes
from detector.process_analyzer import analyze_process


def main():

    print("=" * 60)
    print("          KEYLOGGER DETECTOR")
    print("=" * 60)

    print("\nScanning running processes...\n")

    # Get all running processes
    processes = get_running_processes()

    print("=" * 60)
    print("FIRST 5 PROCESSES")
    print("=" * 60)

    for process in processes[:5]:
        print(process)
        print()

    print(f"Total Processes Found: {len(processes)}\n")

    suspicious_count = 0

    # Analyze every process
    for process in processes:

        analysis = analyze_process(process)

        # Print only if findings exist
        if analysis["findings"]:

            suspicious_count += 1

            print("=" * 60)
            print("⚠ Suspicious Process Found")
            print("=" * 60)

            print(f"Name : {process['name']}")
            print(f"PID  : {process['pid']}")
            print(f"User : {process['username']}")
            print(f"Path : {process['exe']}")
            print(f"Command Line : {process['cmdline']}")
           
            print()

            print("Findings:")

            for finding in analysis["findings"]:
                print(f"• Rule      : {finding['rule']}")
                print(f"  Severity : {finding['severity']}")
                print(f"  Details  : {finding['description']}")
                print()

    print("=" * 60)
    print("Scan Complete")
    print("=" * 60)
    print(f"Processes Scanned : {len(processes)}")
    print(f"Suspicious Found  : {suspicious_count}")


if __name__ == "__main__":
    main()