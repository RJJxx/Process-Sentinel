import psutil

from detector.detection_engine import run_detection_batch


def get_running_processes():
    """
    Collect information about all running processes,
    including network connections.
    """

    processes = []

    for process in psutil.process_iter():

        try:
            # Get parent process name
            parent_name = "Unknown"

            try:
                parent = process.parent()

                if parent:
                    parent_name = parent.name()

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied
            ):
                pass

            # Get network connections
            network_connections = []

            try:
                connections = process.net_connections(
                    kind="inet"
                )

                for connection in connections:

                    remote_ip = ""
                    remote_port = None

                    if connection.raddr:
                        remote_ip = connection.raddr.ip
                        remote_port = connection.raddr.port

                    network_connections.append({
                        "local_address": (
                            f"{connection.laddr.ip}:{connection.laddr.port}"
                            if connection.laddr
                            else ""
                        ),
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "status": connection.status
                    })

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess
            ):
                pass

            process_info = {
                "pid": process.pid,
                "ppid": process.ppid(),
                "parent_name": parent_name,
                "name": process.name(),
                "exe": process.exe(),
                "cmdline": process.cmdline(),
                "username": process.username(),
                "status": process.status(),
                "network_connections": network_connections
            }

            processes.append(process_info)

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    return processes


def analyze_running_processes():
    """
    Collect all currently running processes and
    send them through the detection engine.
    """

    processes = get_running_processes()

    results = run_detection_batch(processes)

    return results


def get_current_alerts():
    """
    Collect and analyze running processes, returning
    only processes that generated an alert.
    """

    results = analyze_running_processes()

    alerts = [
        result
        for result in results
        if result.get("alert", False)
    ]

    return alerts


if __name__ == "__main__":

    print("=" * 70)
    print("KEYLOGGER DETECTOR - PROCESS ANALYSIS")
    print("=" * 70)

    print("\nCollecting running processes...\n")

    results = analyze_running_processes()

    print(f"Processes analyzed: {len(results)}")

    alerts = get_current_alerts()

    print(f"Alerts generated: {len(alerts)}")

    print("\n" + "=" * 70)
    print("ALERTS")
    print("=" * 70)

    if not alerts:

        print("\nNo suspicious processes detected.")

    else:

        for alert in alerts:

            process = alert.get(
                "process",
                {}
            )

            print("\n" + "-" * 70)

            print(
                f"Process : "
                f"{process.get('name', 'Unknown')}"
            )

            print(
                f"PID     : "
                f"{process.get('pid', 'Unknown')}"
            )

            print(
                f"Risk    : "
                f"{alert.get('risk_score', 0)}"
            )

            print(
                f"Level   : "
                f"{alert.get('risk_level', 'Unknown')}"
            )

            print(
                f"Confidence: "
                f"{alert.get('confidence', 'Unknown')}"
            )

            print(
                f"Reason  : "
                f"{alert.get('alert_reason')}"
            )

            print("\nEvidence:")

            for evidence in alert.get(
                "evidence",
                []
            ):

                print(
                    f"  [{evidence.get('id')}] "
                    f"{evidence.get('description')}"
                )