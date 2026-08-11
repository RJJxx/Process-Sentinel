from detector.process_analyzer import analyze_process


LEGITIMATE_PROCESSES = [
    {
        "name": "svchost.exe",
        "exe": r"C:\Windows\System32\svchost.exe",
        "parent_name": "services.exe",
        "username": r"NT AUTHORITY\SYSTEM",
        "cmdline": [
            r"C:\Windows\System32\svchost.exe",
            "-k",
            "LocalService",
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
    },
    {
        "name": "services.exe",
        "exe": r"C:\Windows\System32\services.exe",
        "parent_name": "wininit.exe",
        "username": r"NT AUTHORITY\SYSTEM",
        "cmdline": [
            r"C:\Windows\System32\services.exe",
        ],
    },
    {
        "name": "lsass.exe",
        "exe": r"C:\Windows\System32\lsass.exe",
        "parent_name": "wininit.exe",
        "username": r"NT AUTHORITY\SYSTEM",
        "cmdline": [
            r"C:\Windows\System32\lsass.exe",
        ],
    },
    {
        "name": "winlogon.exe",
        "exe": r"C:\Windows\System32\winlogon.exe",
        "parent_name": "smss.exe",
        "username": r"NT AUTHORITY\SYSTEM",
        "cmdline": [
            r"C:\Windows\System32\winlogon.exe",
        ],
    },
]


def test_legitimate_windows_processes():
    """
    Verify that common legitimate Windows processes
    do not generate high-risk findings under normal conditions.
    """

    for index, process_data in enumerate(LEGITIMATE_PROCESSES, start=1):

        process = {
            "pid": 10000 + index,
            "ppid": 500,
            "parent_name": process_data["parent_name"],
            "name": process_data["name"],
            "exe": process_data["exe"],
            "cmdline": process_data["cmdline"],
            "username": process_data["username"],
            "status": "running",
            "network_connections": [],
        }

        analysis = analyze_process(process)

        print("=" * 60)
        print(f"FALSE POSITIVE TEST {index}")
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
            f"PASS: {process_data['name']} "
            "handled correctly."
        )


if __name__ == "__main__":
    test_legitimate_windows_processes()