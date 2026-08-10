import psutil


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