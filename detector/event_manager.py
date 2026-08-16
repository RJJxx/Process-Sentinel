from detector.event_logger import (
    get_detection_history,
    get_event_by_id,
    mark_event_investigated,
    mark_event_dismissed,
    reset_event_status,
)


# ============================================================
# EVENT RETRIEVAL
# ============================================================

def get_all_events():
    """
    Return all stored detection events.
    """

    return get_detection_history()


def get_recent_events(limit=10):
    """
    Return the most recent detection events.
    """

    events = get_detection_history()

    if limit <= 0:
        return []

    return events[-limit:]


def get_event(event_id):
    """
    Return one detection event by event ID.

    Returns:
        dict -> event
        None -> event not found
    """

    return get_event_by_id(
        event_id
    )


# ============================================================
# EVENT COUNTS
# ============================================================

def get_event_count():
    """
    Return the total number of stored detection events.
    """

    events = get_detection_history()

    return len(events)


# ============================================================
# RISK STATISTICS
# ============================================================

def get_risk_statistics():
    """
    Return the number of events grouped by risk level.
    """

    events = get_detection_history()

    statistics = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Unknown": 0,
    }

    for event in events:

        risk = event.get(
            "risk",
            {}
        )

        level = risk.get(
            "level",
            "Unknown"
        )

        if level in statistics:

            statistics[level] += 1

        else:

            statistics["Unknown"] += 1

    return statistics


# ============================================================
# INVESTIGATION STATISTICS
# ============================================================

def get_investigation_statistics():
    """
    Return the number of events grouped by investigation status.
    """

    events = get_detection_history()

    statistics = {
        "New": 0,
        "Investigated": 0,
        "Dismissed": 0,
        "Unknown": 0,
    }

    for event in events:

        investigation = event.get(
            "investigation",
            {}
        )

        status = investigation.get(
            "status",
            "New"
        )

        if status in statistics:

            statistics[status] += 1

        else:

            statistics["Unknown"] += 1

    return statistics


# ============================================================
# UPDATE INVESTIGATION STATUS
# ============================================================

def investigate_event(
    event_id,
    updated_by="analyst"
):
    """
    Mark a detection event as Investigated.

    Returns:
        dict -> updated event
        None -> event not found
    """

    return mark_event_investigated(
        event_id,
        updated_by
    )


def dismiss_event(
    event_id,
    updated_by="analyst"
):
    """
    Mark a detection event as Dismissed.

    Returns:
        dict -> updated event
        None -> event not found
    """

    return mark_event_dismissed(
        event_id,
        updated_by
    )


def reopen_event(
    event_id,
    updated_by="analyst"
):
    """
    Reset a detection event back to New.
    """

    return reset_event_status(
        event_id,
        updated_by
    )


# ============================================================
# PROCESS EVENTS
# ============================================================

def get_process_events(process_name):
    """
    Return all events associated with a process name.
    """

    events = get_detection_history()

    return [
        event
        for event in events
        if event.get(
            "process",
            {}
        ).get(
            "name"
        ) == process_name
    ]


# ============================================================
# LATEST EVENT
# ============================================================

def get_latest_event():
    """
    Return the most recent detection event.

    Returns None if no events exist.
    """

    events = get_detection_history()

    if not events:
        return None

    return events[-1]


# ============================================================
# COMPLETE DETECTION STATISTICS
# ============================================================

def get_detection_statistics():
    """
    Return a complete summary of the detection history.
    """

    events = get_detection_history()

    risk_statistics = get_risk_statistics()

    investigation_statistics = get_investigation_statistics()

    return {
        "total_events": len(events),

        "critical":
            risk_statistics["Critical"],

        "high":
            risk_statistics["High"],

        "medium":
            risk_statistics["Medium"],

        "low":
            risk_statistics["Low"],

        "investigation": {
            "new":
                investigation_statistics["New"],

            "investigated":
                investigation_statistics["Investigated"],

            "dismissed":
                investigation_statistics["Dismissed"],
        },
    }


# ============================================================
# TEST / DEMO
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("DETECTION EVENT MANAGER")
    print("=" * 70)

    events = get_all_events()

    print(
        f"\nTotal events: {len(events)}"
    )

    # --------------------------------------------------------
    # Risk statistics
    # --------------------------------------------------------

    print(
        "\nRisk statistics:"
    )

    risk_statistics = get_risk_statistics()

    for level, count in risk_statistics.items():

        print(
            f"  {level}: {count}"
        )

    # --------------------------------------------------------
    # Investigation statistics
    # --------------------------------------------------------

    print(
        "\nInvestigation statistics:"
    )

    investigation_statistics = get_investigation_statistics()

    for status, count in (
        investigation_statistics.items()
    ):

        print(
            f"  {status}: {count}"
        )

    # --------------------------------------------------------
    # Latest event
    # --------------------------------------------------------

    latest = get_latest_event()

    print(
        "\nLatest event:"
    )

    if latest:

        print(
            f"  Event ID: "
            f"{latest.get('event_id')}"
        )

        print(
            f"  Process: "
            f"{latest.get('process', {}).get('name')}"
        )

        print(
            f"  Risk: "
            f"{latest.get('risk', {}).get('level')}"
        )

        print(
            f"  Investigation: "
            f"{latest.get('investigation', {}).get('status', 'New')}"
        )

    else:

        print(
            "  No events recorded."
        )

    # --------------------------------------------------------
    # Recent events
    # --------------------------------------------------------

    print(
        "\nRecent events:"
    )

    for event in get_recent_events(5):

        print(
            f"  {event.get('timestamp')} | "
            f"{event.get('process', {}).get('name')} | "
            f"{event.get('risk', {}).get('level')} | "
            f"{event.get('investigation', {}).get('status', 'New')}"
        )

    print(
        "\n" + "=" * 70
    )

    print(
        "EVENT MANAGER TEST COMPLETE"
    )

    print(
        "=" * 70
    )