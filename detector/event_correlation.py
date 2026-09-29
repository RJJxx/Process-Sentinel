from datetime import datetime, timezone
import uuid


DEFAULT_CORRELATION_WINDOW = 60


def parse_timestamp(timestamp):
    """
    Convert an ISO 8601 timestamp into a timezone-aware datetime.

    Returns:
        datetime -> parsed timestamp
        None     -> invalid or missing timestamp
    """

    if not timestamp:
        return None

    try:
        parsed = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed

    except (TypeError, ValueError):
        return None


def events_same_process(event_a, event_b):
    """
    Determine whether two events belong to the same process.

    PID must be present and equal.
    """

    process_a = event_a.get("process") or {}
    process_b = event_b.get("process") or {}

    pid_a = process_a.get("pid")
    pid_b = process_b.get("pid")

    if pid_a is None or pid_b is None:
        return False

    return pid_a == pid_b


def events_within_window(
    event_a,
    event_b,
    window_seconds=DEFAULT_CORRELATION_WINDOW
):
    """
    Determine whether two events occurred within
    the configured correlation window.
    """

    timestamp_a = parse_timestamp(
        event_a.get("timestamp")
    )

    timestamp_b = parse_timestamp(
        event_b.get("timestamp")
    )

    if timestamp_a is None or timestamp_b is None:
        return False

    difference = abs(
        (timestamp_a - timestamp_b).total_seconds()
    )

    return difference <= window_seconds


def events_parent_child(event_a, event_b):
    """
    Determine whether two events represent a parent-child
    process relationship.

    Event A is considered the parent when event_b's PPID
    matches event_a's PID.
    """

    process_a = event_a.get("process") or {}
    process_b = event_b.get("process") or {}

    parent_pid = process_a.get("pid")
    child_ppid = process_b.get("ppid")

    if parent_pid is None or child_ppid is None:
        return False

    return parent_pid == child_ppid


def events_are_related(
    event_a,
    event_b,
    window_seconds=DEFAULT_CORRELATION_WINDOW
):
    """
    Determine whether two detection events should
    currently be considered related.

    Events are related when:

    1. They belong to the same process and occur
       within the correlation window.

    OR

    2. One event represents a parent process and the
       other represents its child process, and both
       events occur within the correlation window.
    """

    if not isinstance(event_a, dict):
        return False

    if not isinstance(event_b, dict):
        return False

    if event_a.get("event_id") == event_b.get("event_id"):
        return False

    # All correlation types must occur within
    # the configured time window.
    if not events_within_window(
        event_a,
        event_b,
        window_seconds
    ):
        return False

    # Same-process correlation.
    if events_same_process(event_a, event_b):
        return True

    # Parent -> child correlation.
    if events_parent_child(event_a, event_b):
        return True

    # Child -> parent correlation.
    if events_parent_child(event_b, event_a):
        return True

    return False


def create_incident(events):
    """
    Create a correlated incident from related detection events.

    Events are preserved in their original form.
    """

    if not events:
        return None

    valid_events = [
        event
        for event in events
        if isinstance(event, dict)
    ]

    if not valid_events:
        return None

    timestamps = [
        event.get("timestamp")
        for event in valid_events
        if event.get("timestamp")
    ]

    rule_ids = []

    for event in valid_events:
        findings = event.get("findings") or []

        for finding in findings:
            rule_id = finding.get("id")

            if rule_id and rule_id not in rule_ids:
                rule_ids.append(rule_id)

    process_ids = []

    for event in valid_events:
        process = event.get("process") or {}
        pid = process.get("pid")

        if pid is not None and pid not in process_ids:
            process_ids.append(pid)

    return {
        "incident_id": str(uuid.uuid4()),
        "created_at": timestamps[0] if timestamps else None,
        "updated_at": timestamps[-1] if timestamps else None,
        "event_ids": [
            event.get("event_id")
            for event in valid_events
            if event.get("event_id")
        ],
        "process_ids": process_ids,
        "rule_ids": rule_ids,
        "events": valid_events,
        "status": "New",
    }


def correlate_events(
    events,
    window_seconds=DEFAULT_CORRELATION_WINDOW
):
    """
    Group related detection events into incidents.

    Events are compared against existing incident groups.
    A new incident group is created when an event does not
    relate to any existing group.
    """

    if not events:
        return []

    valid_events = [
        event
        for event in events
        if isinstance(event, dict)
    ]

    if not valid_events:
        return []

    incident_groups = []

    for event in valid_events:
        added_to_group = False

        for group in incident_groups:
            if any(
                events_are_related(
                    event,
                    existing_event,
                    window_seconds
                )
                for existing_event in group
            ):
                group.append(event)
                added_to_group = True
                break

        if not added_to_group:
            incident_groups.append([event])

    return [
        create_incident(group)
        for group in incident_groups
    ]
