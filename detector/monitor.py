import time

from detector.process_monitor import get_current_alerts
from detector.event_logger import log_detection


# ============================================================
# MONITOR CONFIGURATION
# ============================================================

SCAN_INTERVAL = 10


# ============================================================
# MONITOR
# ============================================================

def monitor_processes(interval=SCAN_INTERVAL):
    """
    Continuously monitor running processes.

    Suspicious detections are displayed in the terminal
    and persisted to logs/detections.json.

    Duplicate consecutive detections are not logged again.
    """

    print("=" * 70)
    print("KEYLOGGER DETECTOR - CONTINUOUS MONITOR")
    print("=" * 70)

    print(
        f"\nScan interval: {interval} seconds"
    )

    print(
        "Monitoring started."
    )

    print(
        "Press Ctrl+C to stop.\n"
    )

    scan_number = 0

    try:

        while True:

            scan_number += 1

            print("-" * 70)
            print(
                f"SCAN #{scan_number}"
            )
            print("-" * 70)

            start_time = time.time()

            alerts = get_current_alerts()

            elapsed_time = (
                time.time()
                - start_time
            )

            print(
                f"Scan completed in "
                f"{elapsed_time:.2f} seconds."
            )

            print(
                f"Alerts detected: "
                f"{len(alerts)}"
            )

            # ------------------------------------------------
            # Process alerts
            # ------------------------------------------------

            if alerts:

                for alert in alerts:

                    process = alert.get(
                        "process",
                        {}
                    )

                    print(
                        "\n"
                        + "!"
                        * 70
                    )

                    print(
                        f"ALERT: "
                        f"{process.get('name', 'Unknown')}"
                    )

                    print(
                        f"PID: "
                        f"{process.get('pid', 'Unknown')}"
                    )

                    print(
                        f"Risk Score: "
                        f"{alert.get('risk_score', 0)}"
                    )

                    print(
                        f"Risk Level: "
                        f"{alert.get('risk_level', 'Unknown')}"
                    )

                    print(
                        f"Confidence: "
                        f"{alert.get('confidence', 'Unknown')}"
                    )

                    print(
                        f"Reason: "
                        f"{alert.get('alert_reason')}"
                    )

                    print(
                        "\nEvidence:"
                    )

                    for evidence in alert.get(
                        "evidence",
                        []
                    ):

                        print(
                            f"  [{evidence.get('id')}] "
                            f"{evidence.get('description')}"
                        )

                    print(
                        "!"
                        * 70
                    )

                    # ----------------------------------------
                    # Persist alert
                    # ----------------------------------------

                    try:

                        event = log_detection(
                            alert
                        )

                        if event:

                            print(
                                "\n[LOGGED] "
                                "New detection event saved."
                            )

                            print(
                                f"[LOGGED] "
                                f"Event ID: "
                                f"{event.get('event_id')}"
                            )

                        else:

                            print(
                                "\n[SKIPPED] "
                                "Duplicate detection."
                            )

                    except Exception as error:

                        print(
                            "\n[LOGGER ERROR] "
                            f"{error}"
                        )

            else:

                print(
                    "Status: No suspicious "
                    "processes detected."
                )

            # ------------------------------------------------
            # Wait
            # ------------------------------------------------

            print(
                f"\nWaiting {interval} seconds "
                f"before next scan..."
            )

            time.sleep(
                interval
            )

    except KeyboardInterrupt:

        print("\n")

        print(
            "=" * 70
        )

        print(
            "MONITORING STOPPED"
        )

        print(
            "=" * 70
        )

        print(
            "Detector stopped by user."
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    monitor_processes()