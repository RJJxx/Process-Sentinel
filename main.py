import threading

from detector.api import app
from detector.monitor import monitor_processes


# ============================================================
# CONFIGURATION
# ============================================================

MONITOR_INTERVAL = 10

API_HOST = "127.0.0.1"
API_PORT = 5000


# ============================================================
# PROCESS MONITOR
# ============================================================

def start_process_monitor():
    """
    Start the continuous process monitoring system.
    """

    monitor_processes(
        interval=MONITOR_INTERVAL
    )


# ============================================================
# MAIN APPLICATION
# ============================================================

def main():
    """
    Start the complete Keylogger Detector application.

    The process monitor runs in a background thread while
    Flask serves the API and web dashboard.
    """

    print("=" * 70)
    print("KEYLOGGER DETECTOR")
    print("=" * 70)

    print("\nStarting application...\n")

    # --------------------------------------------------------
    # Start continuous process monitor
    # --------------------------------------------------------

    monitor_thread = threading.Thread(
        target=start_process_monitor,
        daemon=True
    )

    monitor_thread.start()

    print(
        "✓ Continuous process monitor started"
    )

    # --------------------------------------------------------
    # Start Flask API + Dashboard
    # --------------------------------------------------------

    print(
        f"✓ Web server starting at "
        f"http://{API_HOST}:{API_PORT}"
    )

    print(
        "\nOpen the dashboard:"
    )

    print(
        f"http://{API_HOST}:{API_PORT}/"
    )

    print(
        "\nPress Ctrl+C to stop the application."
    )

    print("=" * 70)

    try:

        app.run(
            host=API_HOST,
            port=API_PORT,
            debug=False,
            use_reloader=False
        )

    except KeyboardInterrupt:

        print("\nStopping Keylogger Detector...")

    finally:

        print("Application stopped.")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()