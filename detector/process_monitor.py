import psutil


def get_running_processes():

    processes = []

    for process in psutil.process_iter():

        try:
            process_info = {
                "pid": process.pid,
                "name": process.name(),
                "username": process.username(),
                "status": process.status()
            }

            processes.append(process_info)

        except (psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess):
            continue

    return processes