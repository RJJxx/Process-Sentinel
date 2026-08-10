from detector.process_analyzer import (
    check_suspicious_path,
    check_process_name,
    check_missing_executable,
    check_suspicious_parent,
    check_suspicious_lolbin,
    check_suspicious_command_line,
    check_suspicious_network,
    check_process_network_correlation,
)

DETECTION_MODULES = [
    check_suspicious_path,
    check_process_name,
    check_missing_executable,
    check_suspicious_parent,
    check_suspicious_lolbin,
    check_suspicious_command_line,
    check_suspicious_network,
    check_process_network_correlation,
]