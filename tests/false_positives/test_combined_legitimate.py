from detector.process_analyzer import analyze_process


LEGITIMATE_COMBINED_PROCESSES = [
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
                "local_address": "192.168.1.10:50010",
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
                "local_address": "192.168.1.10:50011",
                "remote_ip": "142.250.72.14",
                "remote_port": 443,
                "status": "ESTABLISHED",
            }
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
        "network_connections": [],
    },
]


def test_legitimate_process_with_multiple_normal_characteristics():
    """
    Verify that a legitimate process with multiple normal
    characteristics is not incorrectly classified as suspicious.
    """

    for index, process_data in enumerate(
        LEGITIMATE_COMBINED_PROCESSES,
        start=1
    ):

        process = {
            "pid": 13000 + index,
            "ppid": 500,
            "parent_name": process_data["parent_name"],
            "name": process_data["name"],
            "exe": process_data["exe"],
            "cmdline": process_data["cmdline"],
            "username": process_data["username"],
            "status": "running",
            "network_connections": process_data[
                "network_connections"
            ],
        }

        analysis = analyze_process(process)

        print("=" * 60)
        print(f"COMBINED FALSE POSITIVE TEST {index}")
        print(f"PROCESS: {process_data['name']}")
        print("=" * 60)
        print(analysis)

        findings = analysis.get("findings", [])
        risk_score = analysis.get("risk_score", 0)
        risk_level = analysis.get("risk_level", "Unknown")

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

        if risk_level == "High":
            raise AssertionError(
                f"Legitimate process {process_data['name']} "
                "was classified as High risk."
            )

        print(
            f"PASS: {process_data['name']} remained "
            f"{risk_level} risk with score {risk_score}."
        )


if __name__ == "__main__":
    test_legitimate_process_with_multiple_normal_characteristics()