SUSPICIOUS_FOLDERS = [
    "Temp",
    "Downloads"
]

TRUSTED_PROCESS_NAMES = [
    "explorer.exe",
    "svchost.exe",
    "services.exe",
    "winlogon.exe",
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "notepad.exe",
    "cmd.exe",
    "powershell.exe"
]

SYSTEM_PROCESSES = [
    "system",
    "system idle process"
]


RULES = {
    "KD-001": {
        "name": "Suspicious Executable Location",
        "severity": "Medium",
        "description": "Executable is running from a suspicious location."
    },

    "KD-002": {
        "name": "Possible Masquerading",
        "severity": "High",
        "description": "Process name closely resembles a trusted application."
    },

    "KD-003": {
        "name": "Missing Executable Path",
        "severity": "Medium",
        "description": "Process does not expose an executable path."
    },

    "KD-004": {
    "name": "Suspicious Parent Process",
    "severity": "High",
    "description": "Process was launched by an unusual parent process."
    },

    "KD-005": {
    "name": "Suspicious PowerShell Execution",
    "severity": "High",
    "description": "Detected suspicious PowerShell command-line arguments."
    },

    "KD-006": {
    "name": "Suspicious LOLBin Usage",
    "severity": "High",
    "description": (
        "A legitimate Windows utility was executed "
        "with a suspicious usage pattern."
    )
},

    "KD-007": {
    "name": "Suspicious Command-Line Activity",
    "severity": "Medium",
    "description": (
        "Detected a command-line pattern associated "
        "with potentially suspicious process activity."
    )
},

    "KD-008": {
    "name": "Suspicious Network Connection",
    "severity": "Medium",
    "description": (
        "Detects processes making network connections "
        "to suspicious or unusual remote endpoints."
    )
},

    "KD-008": {
    "name": "Suspicious Network Connection",
    "severity": "Medium",
    "description": "Detects potentially suspicious outbound network activity."
},

"KD-009": {
    "name": "Suspicious Process and Network Correlation",
    "severity": "High",
    "description": (
        "Detects processes exhibiting both suspicious "
        "execution location and suspicious network activity."
    )
},

"KD-010": {
    "name": "Suspicious Persistence Location",
    "severity": "High"
},
    
}


SUSPICIOUS_PARENT_CHILD = {
    "powershell.exe": [
        "winword.exe",
        "excel.exe",
        "outlook.exe"
    ],

    "cmd.exe": [
        "winword.exe",
        "excel.exe"
    ],

    "wscript.exe": [
        "winword.exe",
        "excel.exe"
    ],

    "cscript.exe": [
        "winword.exe",
        "excel.exe"
    ]
}


SUSPICIOUS_POWERSHELL_FLAGS = [
    "-enc",
    "-encodedcommand",
    "-executionpolicy bypass",
    "frombase64string",
    "-nop",
    "-windowstyle hidden",
    "-w hidden",
    "-noprofile"
]



SUSPICIOUS_LOLBINS = [
    "certutil.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "bitsadmin.exe"
]


SUSPICIOUS_LOLBIN_PATTERNS = {
    "certutil.exe": [
        "-urlcache",
        "-decode",
        "-decodehex",
    ],

    "mshta.exe": [
        "http://",
        "https://",
        "javascript:",
        "vbscript:",
    ],

    "regsvr32.exe": [
        "http://",
        "https://",
        "/i:",
    ],

    "rundll32.exe": [
        "javascript:",
        "http://",
        "https://",
    ],

    "bitsadmin.exe": [
        "/transfer",
        "/create",
        "/addfile",
    ],
}

SUSPICIOUS_COMMAND_PATTERNS = [
    "schtasks /create",
    "reg add",
    "net user",
    "net localgroup",
]

SUSPICIOUS_NETWORK_PORTS = [
    4444,
    1337,
    31337,
    6667,
]

SUSPICIOUS_NETWORK_PORTS = [
    4444,
    5555,
    1337,
    31337,
    9001,
]

SUSPICIOUS_PERSISTENCE_LOCATIONS = [
    "\\startup\\",
    "\\start menu\\programs\\startup\\",
    "\\run\\",
    "\\runonce\\",
]

# ============================================================
# RISK SCORING
# ============================================================

SEVERITY_SCORES = {
    "Low": 10,
    "Medium": 20,
    "High": 30,
    "Critical": 40,
}


def calculate_risk_score(findings):
    """
    Calculate an overall risk score from detection findings.

    Each detection rule contributes according to its severity.
    Duplicate rule IDs are counted only once.
    """

    if not findings:
        return 0

    score = 0
    processed_rules = set()

    for finding in findings:
        rule_id = finding.get("id")

        # Prevent duplicate findings from inflating the score
        if rule_id in processed_rules:
            continue

        processed_rules.add(rule_id)

        severity = finding.get("severity", "Low")
        score += SEVERITY_SCORES.get(severity, 0)

    # Maximum score is 100
    return min(score, 100)


def get_risk_level(score):
    """
    Convert a numerical risk score into a risk level.
    """

    if score >= 80:
        return "Critical"

    if score >= 60:
        return "High"

    if score >= 30:
        return "Medium"

    return "Low"