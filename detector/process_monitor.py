import psutil


def get_running_processes():
    """
    Collect information about all running processes.
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

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            process_info = {
                "pid": process.pid,
                "ppid": process.ppid(),
                "parent_name": parent_name,
                "name": process.name(),
                "exe": process.exe(),
                "cmdline": process.cmdline(),
                "username": process.username(),
                "status": process.status()
            }

            processes.append(process_info)

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    return processes