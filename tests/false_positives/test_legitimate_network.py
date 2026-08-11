from detector.process_analyzer import analyze_process


LEGITIMATE_NETWORK_PROCESSES = [
    {
        "name": "svchost.exe",
        "exe": r"C:\Windows\System32\svchost.exe",
        "parent_name": "services.exe",
        "username": r"NT AUTHORITY\SYSTEM",
        "cmdline": [
            r"C:\Windows\System32\svchost.exe",
            "-k",
            "netsvcs",
        ],
        "network_connections": [
            {
                "local_address": "192.168.1.10:50000",
                "remote_ip": "8.8.8.8",
                "remote_port": 443,
                "status": "ESTABLISHED",
            }
        ],
    },
    {
        "name": "explorer.exe",
        "exe": r"C:\Windows\explorer.exe",
        "parent_name": "userinit.exe",
        "username": "ASUS",
        "cmdline": [
            r"C:\Windows\explorer.exe",
        ],
        "network_connections": [
            {
                "local_address": "192.168.1.10:50001",
                "remote_ip": "142.250.72.14",
                "remote_port": 443,
                "status": "ESTABLISHED",
            }
        ],
    },
]


def test_legitimate_processes_with_network():
    """
    Verify that legitimate Windows processes with
    normal HTTPS network connections are not incorrectly
    classified as high-risk.
    """

    for index, process_data in enumerate(
        LEGITIMATE_NETWORK_PROCESSES,
        start=1
    ):

        process = {
            "pid": 11000 + index,
            "ppid": 500,
            "parent_name": process_data["parent_name"],
            "name": process_data["name"],
            "exe": process_data["exe"],
            "cmdline": process_data["cmdline"],
            "username": process_data["username"],
            "status": "running",
            "network_connections": process_data["network_connections"],
        }

        analysis = analyze_process(process)

        print("=" * 60)
        print(f"FALSE POSITIVE NETWORK TEST {index}")
        print(f"PROCESS: {process_data['name']}")
        print("=" * 60)
        print(analysis)

        findings = analysis.get("findings", [])

        high_risk_findings = [
            finding
            for finding in findings
            if finding.get("severity") == "High"
        ]

        if high_risk_findings:
            print(
                f"FAIL: {process_data['name']} generated "
                "high-risk findings."
            )
            print(high_risk_findings)

            raise AssertionError(
                f"Legitimate process {process_data['name']} "
                "generated high-risk findings."
            )

        print(
            f"PASS: {process_data['name']} with normal "
            "network activity handled correctly."
        )


if __name__ == "__main__":
    test_legitimate_processes_with_network()