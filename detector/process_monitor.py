import psutil


def get_running_processes():

    processes = []

    for process in psutil.process_iter():

        try:
            process_info = {
                "pid": process.pid,
                "name": process.name(),
                "exe": process.exe(),
                "username": process.username(),
                "status": process.status(),
                "cmdline": process.cmdline()
            }

            processes.append(process_info)

        except (psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess):
            continue

    return processes