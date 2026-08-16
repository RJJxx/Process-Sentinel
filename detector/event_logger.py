import json
import os
import hashlib
import uuid
from datetime import datetime, timezone


# ============================================================
# LOG CONFIGURATION
# ============================================================

LOG_DIRECTORY = "logs"

LOG_FILE = os.path.join(
    LOG_DIRECTORY,
    "detections.json"
)


# ============================================================
# INVESTIGATION CONFIGURATION
# ============================================================

DEFAULT_INVESTIGATION_STATUS = "New"

VALID_INVESTIGATION_STATUSES = {
    "New",
    "Investigated",
    "Dismissed",
}


# ============================================================
# DIRECTORY INITIALIZATION
# ============================================================

def ensure_log_directory():
    """
    Create the log directory if it does not already exist.
    """

    os.makedirs(
        LOG_DIRECTORY,
        exist_ok=True
    )


# ============================================================
# LOAD EVENTS
# ============================================================

def load_events():
    """
    Load previously stored detection events.

    Older events that do not contain investigation information
    are automatically given the default 'New' status.
    """

    ensure_log_directory()

    if not os.path.exists(LOG_FILE):
        return []

    try:

        with open(
            LOG_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        if not isinstance(data, list):
            return []

        changed = False

        # ----------------------------------------------------
        # Add investigation information to older events
        # ----------------------------------------------------

        for event in data:

            if not isinstance(event, dict):
                continue

            if "investigation" not in event:

                event["investigation"] = {
                    "status": DEFAULT_INVESTIGATION_STATUS,
                    "updated_at": None,
                    "updated_by": "system",
                }

                changed = True

                continue

            investigation = event.get(
                "investigation"
            )

            if not isinstance(
                investigation,
                dict
            ):

                event["investigation"] = {
                    "status": DEFAULT_INVESTIGATION_STATUS,
                    "updated_at": None,
                    "updated_by": "system",
                }

                changed = True

                continue

            if not investigation.get("status"):

                investigation["status"] = (
                    DEFAULT_INVESTIGATION_STATUS
                )

                changed = True

        # ----------------------------------------------------
        # Save migrated events if necessary
        # ----------------------------------------------------

        if changed:
            save_events(data)

        return data

    except (
        json.JSONDecodeError,
        OSError
    ):

        return []


# ============================================================
# SAVE EVENTS
# ============================================================

def save_events(events):
    """
    Save detection events to the JSON log.
    """

    ensure_log_directory()

    with open(
        LOG_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            events,
            file,
            indent=4
        )


# ============================================================
# EVENT FINGERPRINT
# ============================================================

def create_event_fingerprint(alert):
    """
    Create a stable fingerprint for a detection.

    The fingerprint is based on the process executable,
    PID, risk score and triggered detection rules.
    """

    process = alert.get(
        "process",
        {}
    )

    pid = process.get(
        "pid",
        ""
    )

    name = process.get(
        "name",
        ""
    )

    exe = process.get(
        "exe",
        ""
    )

    risk_score = alert.get(
        "risk_score",
        0
    )

    findings = alert.get(
        "findings",
        []
    )

    rule_ids = sorted(
        str(
            finding.get(
                "id",
                ""
            )
        )
        for finding in findings
    )

    fingerprint_data = "|".join([
        str(pid),
        str(name),
        str(exe),
        str(risk_score),
        ",".join(rule_ids),
    ])

    return hashlib.sha256(
        fingerprint_data.encode(
            "utf-8"
        )
    ).hexdigest()


# ============================================================
# CREATE DETECTION EVENT
# ============================================================

def create_detection_event(alert):
    """
    Convert a detection-engine alert into a persistent
    security event.
    """

    process = alert.get(
        "process",
        {}
    )

    event = {

        "event_id": str(
            uuid.uuid4()
        ),

        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "fingerprint": create_event_fingerprint(
            alert
        ),

        "process": {

            "pid": process.get(
                "pid"
            ),

            "name": process.get(
                "name",
                "Unknown"
            ),

            "parent_name": process.get(
                "parent_name",
                "Unknown"
            ),

            "exe": process.get(
                "exe",
                ""
            ),

            "username": process.get(
                "username",
                "Unknown"
            ),

        },

        "risk": {

            "score": alert.get(
                "risk_score",
                0
            ),

            "level": alert.get(
                "risk_level",
                "Unknown"
            ),

            "confidence": alert.get(
                "confidence",
                "Unknown"
            ),

        },

        "alert_reason": alert.get(
            "alert_reason"
        ),

        "findings": alert.get(
            "findings",
            []
        ),

        "evidence": alert.get(
            "evidence",
            []
        ),

        # ----------------------------------------------------
        # Investigation information
        # ----------------------------------------------------

        "investigation": {

            "status":
                DEFAULT_INVESTIGATION_STATUS,

            "updated_at":
                None,

            "updated_by":
                "system",

        },

    }

    return event


# ============================================================
# CHECK FOR DUPLICATE
# ============================================================

def is_duplicate_detection(
    alert,
    events=None
):
    """
    Check whether the same detection was already logged.

    Only the most recent event is checked.
    """

    if events is None:
        events = load_events()

    if not events:
        return False

    fingerprint = create_event_fingerprint(
        alert
    )

    latest_event = events[-1]

    return (
        latest_event.get(
            "fingerprint"
        ) == fingerprint
    )


# ============================================================
# LOG DETECTION
# ============================================================

def log_detection(alert):
    """
    Log a detection event unless it is an identical
    consecutive detection.

    Returns:
        event -> newly logged event
        None  -> duplicate detection
    """

    events = load_events()

    # --------------------------------------------------------
    # Duplicate protection
    # --------------------------------------------------------

    if is_duplicate_detection(
        alert,
        events
    ):

        return None

    # --------------------------------------------------------
    # Create event
    # --------------------------------------------------------

    event = create_detection_event(
        alert
    )

    # --------------------------------------------------------
    # Save event
    # --------------------------------------------------------

    events.append(
        event
    )

    save_events(
        events
    )

    return event


# ============================================================
# GET DETECTION HISTORY
# ============================================================

def get_detection_history():
    """
    Return all stored detection events.
    """

    return load_events()


# ============================================================
# GET EVENT BY ID
# ============================================================

def get_event_by_id(event_id):
    """
    Return one detection event using its event ID.

    Returns:
        dict -> matching event
        None -> event not found
    """

    if not event_id:
        return None

    events = load_events()

    for event in events:

        if event.get(
            "event_id"
        ) == event_id:

            return event

    return None


# ============================================================
# UPDATE INVESTIGATION STATUS
# ============================================================

def update_event_status(
    event_id,
    status,
    updated_by="analyst"
):
    """
    Update the investigation status of a detection event.

    Valid statuses:
        New
        Investigated
        Dismissed

    Returns:
        dict -> updated event
        None -> event not found

    Raises:
        ValueError -> invalid status
    """

    if status not in VALID_INVESTIGATION_STATUSES:

        raise ValueError(
            "Invalid investigation status. "
            "Valid statuses: "
            + ", ".join(
                sorted(
                    VALID_INVESTIGATION_STATUSES
                )
            )
        )

    events = load_events()

    for event in events:

        if event.get(
            "event_id"
        ) != event_id:

            continue

        # ----------------------------------------------------
        # Make sure investigation object exists
        # ----------------------------------------------------

        if not isinstance(
            event.get("investigation"),
            dict
        ):

            event["investigation"] = {}

        # ----------------------------------------------------
        # Update investigation status
        # ----------------------------------------------------

        event["investigation"]["status"] = (
            status
        )

        event["investigation"]["updated_at"] = (
            datetime.now(
                timezone.utc
            ).isoformat()
        )

        event["investigation"]["updated_by"] = (
            updated_by or "analyst"
        )

        # ----------------------------------------------------
        # Save changes
        # ----------------------------------------------------

        save_events(
            events
        )

        return event

    return None


# ============================================================
# MARK EVENT AS INVESTIGATED
# ============================================================

def mark_event_investigated(
    event_id,
    updated_by="analyst"
):
    """
    Mark a detection event as Investigated.
    """

    return update_event_status(
        event_id,
        "Investigated",
        updated_by
    )


# ============================================================
# MARK EVENT AS DISMISSED
# ============================================================

def mark_event_dismissed(
    event_id,
    updated_by="analyst"
):
    """
    Mark a detection event as Dismissed.
    """

    return update_event_status(
        event_id,
        "Dismissed",
        updated_by
    )


# ============================================================
# RESET EVENT STATUS
# ============================================================

def reset_event_status(
    event_id,
    updated_by="analyst"
):
    """
    Reset a detection event back to New.
    """

    return update_event_status(
        event_id,
        "New",
        updated_by
    )


# ============================================================
# CLEAR DETECTION HISTORY
# ============================================================

def clear_detection_history():
    """
    Remove all stored detection events.
    """

    ensure_log_directory()

    save_events([])


# ============================================================
# TEST / DEMO
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("EVENT LOGGER TEST")
    print("=" * 70)

    print(
        "\nNOTE:"
    )

    print(
        "This test clears the detection history."
    )

    print(
        "Do not run this file during normal operation."
    )

    # --------------------------------------------------------
    # Start with a clean test log
    # --------------------------------------------------------

    clear_detection_history()

    test_alert = {

        "process": {

            "pid": 9999,

            "name":
                "test_suspicious.exe",

            "parent_name":
                "explorer.exe",

            "exe": (
                r"C:\Users\ASUS\Downloads"
                r"\test_suspicious.exe"
            ),

            "username":
                "ASUS",

        },

        "risk_score":
            70,

        "risk_level":
            "High",

        "confidence":
            "Very High",

        "alert_reason":
            "Risk level is High.",

        "findings": [

            {

                "id":
                    "KD-001",

                "rule":
                    "Suspicious Executable Location",

                "severity":
                    "Medium",

                "description": (
                    "Executable is running "
                    "from a suspicious location."
                ),

            }

        ],

        "evidence": [

            {

                "id":
                    "KD-001",

                "rule":
                    "Suspicious Executable Location",

                "severity":
                    "Medium",

                "description": (
                    "Executable is running "
                    "from a suspicious location."
                ),

            }

        ],

    }

    # --------------------------------------------------------
    # First detection
    # --------------------------------------------------------

    first_event = log_detection(
        test_alert
    )

    if first_event:

        print(
            "\nPASS: First detection was logged."
        )

        print(
            "Event ID: "
            f"{first_event['event_id']}"
        )

    else:

        print(
            "\nFAIL: First detection was not logged."
        )

    # --------------------------------------------------------
    # Duplicate detection
    # --------------------------------------------------------

    second_event = log_detection(
        test_alert
    )

    if second_event is None:

        print(
            "PASS: Duplicate detection was ignored."
        )

    else:

        print(
            "FAIL: Duplicate detection was logged."
        )

    # --------------------------------------------------------
    # Retrieve event
    # --------------------------------------------------------

    if first_event:

        event_id = first_event[
            "event_id"
        ]

        found_event = get_event_by_id(
            event_id
        )

        if found_event:

            print(
                "PASS: Event retrieved successfully."
            )

            print(
                "Investigation status: "
                f"{found_event['investigation']['status']}"
            )

        else:

            print(
                "FAIL: Event could not be retrieved."
            )

        # ----------------------------------------------------
        # Mark investigated
        # ----------------------------------------------------

        investigated_event = (
            mark_event_investigated(
                event_id
            )
        )

        if investigated_event:

            print(
                "PASS: Event marked as Investigated."
            )

            print(
                "Status: "
                f"{investigated_event['investigation']['status']}"
            )

        else:

            print(
                "FAIL: Could not mark event as Investigated."
            )

        # ----------------------------------------------------
        # Mark dismissed
        # ----------------------------------------------------

        dismissed_event = (
            mark_event_dismissed(
                event_id
            )
        )

        if dismissed_event:

            print(
                "PASS: Event marked as Dismissed."
            )

            print(
                "Status: "
                f"{dismissed_event['investigation']['status']}"
            )

        else:

            print(
                "FAIL: Could not mark event as Dismissed."
            )

    # --------------------------------------------------------
    # Final history
    # --------------------------------------------------------

    history = get_detection_history()

    print(
        f"\nStored events: "
        f"{len(history)}"
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "EVENT LOGGER TEST COMPLETE"
    )

    print(
        "=" * 70
    )