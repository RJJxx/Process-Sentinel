from detector.process_analyzer import analyze_process


LEGITIMATE_COMMAND_PROCESSES = [
    {
        "name": "cmd.exe",
        "exe": r"C:\Windows\System32\cmd.exe",
        "parent_name": "explorer.exe",
        "username": "ASUS",
        "cmdline": [
            r"C:\Windows\System32\cmd.exe",
            "/c",
            "ipconfig",
        ],
    },
    {
        "name": "cmd.exe",
        "exe": r"C:\Windows\System32\cmd.exe",
        "parent_name": "explorer.exe",
        "username": "ASUS",
        "cmdline": [
            r"C:\Windows\System32\cmd.exe",
            "/c",
            "ping",
            "127.0.0.1",
        ],
    },
    {
        "name": "powershell.exe",
        "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "parent_name": "explorer.exe",
        "username": "ASUS",
        "cmdline": [
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-Command",
            "Get-Process",
        ],
    },
    {
        "name": "certutil.exe",
        "exe": r"C:\Windows\System32\certutil.exe",
        "parent_name": "explorer.exe",
        "username": "ASUS",
        "cmdline": [
            r"C:\Windows\System32\certutil.exe",
            "-dump",
            "certificate.cer",
        ],
    },
]


def test_legitimate_commandline_activity():
    """
    Verify that legitimate command-line activity does not
    incorrectly generate high-risk findings.

    These commands represent normal administrative or
    diagnostic activity.
    """

    for index, process_data in enumerate(
        LEGITIMATE_COMMAND_PROCESSES,
        start=1
    ):

        process = {
            "pid": 12000 + index,
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
        print(f"FALSE POSITIVE COMMAND-LINE TEST {index}")
        print(f"PROCESS: {process_data['name']}")
        print(f"COMMAND: {' '.join(process_data['cmdline'])}")
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
                f"Legitimate command-line activity for "
                f"{process_data['name']} generated "
                "high-risk findings."
            )

        print(
            f"PASS: {process_data['name']} legitimate "
            "command-line activity handled correctly."
        )


if __name__ == "__main__":
    test_legitimate_commandline_activity()