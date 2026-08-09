from detector.process_analyzer import (
    check_suspicious_path,
    check_process_name,
    check_missing_executable,
    check_suspicious_parent
)

DETECTION_MODULES = [
    check_suspicious_path,
    check_process_name,
    check_missing_executable,
    check_suspicious_parent
]