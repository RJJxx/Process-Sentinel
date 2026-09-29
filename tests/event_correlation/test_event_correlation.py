from detector.event_correlation import (
    events_same_process,
    events_within_window,
    events_are_related,
    create_incident,
    events_parent_child,
    correlate_events,
)


def make_event(event_id, timestamp, pid):
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "process": {
            "pid": pid,
            "name": "powershell.exe",
        },
    }


def test_same_process():
    event_a = make_event(
        "event-1",
        "2026-09-20T10:00:00+00:00",
        1234,
    )

    event_b = make_event(
        "event-2",
        "2026-09-20T10:00:05+00:00",
        1234,
    )

    assert events_same_process(event_a, event_b)


def test_different_process():
    event_a = make_event(
        "event-1",
        "2026-09-20T10:00:00+00:00",
        1234,
    )

    event_b = make_event(
        "event-2",
        "2026-09-20T10:00:05+00:00",
        5678,
    )

    assert not events_same_process(event_a, event_b)


def test_events_within_window():
    event_a = make_event(
        "event-1",
        "2026-09-20T10:00:00+00:00",
        1234,
    )

    event_b = make_event(
        "event-2",
        "2026-09-20T10:00:30+00:00",
        1234,
    )

    assert events_within_window(event_a, event_b)


def test_events_outside_window():
    event_a = make_event(
        "event-1",
        "2026-09-20T10:00:00+00:00",
        1234,
    )

    event_b = make_event(
        "event-2",
        "2026-09-20T10:02:00+00:00",
        1234,
    )

    assert not events_within_window(event_a, event_b)


def test_related_events():
    event_a = make_event(
        "event-1",
        "2026-09-20T10:00:00+00:00",
        1234,
    )

    event_b = make_event(
        "event-2",
        "2026-09-20T10:00:10+00:00",
        1234,
    )

    assert events_are_related(event_a, event_b)


def test_different_processes_are_not_related():
    event_a = make_event(
        "event-1",
        "2026-09-20T10:00:00+00:00",
        1234,
    )

    event_b = make_event(
        "event-2",
        "2026-09-20T10:00:10+00:00",
        5678,
    )

    assert not events_are_related(event_a, event_b)


def test_same_event_is_not_related_to_itself():
    event = make_event(
        "event-1",
        "2026-09-20T10:00:00+00:00",
        1234,
    )

    assert not events_are_related(event, event)


def test_missing_pid_does_not_crash():
    event_a = make_event(
        "event-1",
        "2026-09-20T10:00:00+00:00",
        None,
    )

    event_b = make_event(
        "event-2",
        "2026-09-20T10:00:05+00:00",
        1234,
    )

    assert not events_are_related(event_a, event_b)


def test_invalid_timestamp_does_not_crash():
    event_a = make_event(
        "event-1",
        "not-a-timestamp",
        1234,
    )

    event_b = make_event(
        "event-2",
        "2026-09-20T10:00:05+00:00",
        1234,
    )

    assert not events_are_related(event_a, event_b)



def test_create_incident():
    events = [
        {
            "event_id": "event-1",
            "timestamp": "2026-09-20T10:00:00+00:00",
            "process": {
                "pid": 1234,
                "name": "powershell.exe",
            },
            "findings": [
                {"id": "KD-005"}
            ],
        },
        {
            "event_id": "event-2",
            "timestamp": "2026-09-20T10:00:05+00:00",
            "process": {
                "pid": 1234,
                "name": "powershell.exe",
            },
            "findings": [
                {"id": "KD-007"}
            ],
        },
    ]

    incident = create_incident(events)

    assert incident is not None
    assert incident["incident_id"]
    assert incident["event_ids"] == [
        "event-1",
        "event-2",
    ]
    assert incident["process_ids"] == [1234]
    assert incident["rule_ids"] == [
        "KD-005",
        "KD-007",
    ]
    assert incident["status"] == "New"


def test_create_incident_deduplicates_rules_and_processes():
    events = [
        {
            "event_id": "event-1",
            "timestamp": "2026-09-20T10:00:00+00:00",
            "process": {
                "pid": 1234,
            },
            "findings": [
                {"id": "KD-005"},
                {"id": "KD-005"},
            ],
        },
        {
            "event_id": "event-2",
            "timestamp": "2026-09-20T10:00:05+00:00",
            "process": {
                "pid": 1234,
            },
            "findings": [
                {"id": "KD-007"},
            ],
        },
    ]

    incident = create_incident(events)

    assert incident["process_ids"] == [1234]
    assert incident["rule_ids"] == [
        "KD-005",
        "KD-007",
    ]


def test_create_incident_with_empty_events():
    assert create_incident([]) is None


def test_create_incident_ignores_invalid_events():
    events = [
        None,
        "invalid",
        {
            "event_id": "event-1",
            "timestamp": "2026-09-20T10:00:00+00:00",
            "process": {
                "pid": 1234,
            },
            "findings": [],
        },
    ]

    incident = create_incident(events)

    assert incident is not None
    assert incident["event_ids"] == ["event-1"]    


def test_parent_child_processes():
    parent = make_event(
        "event-parent",
        "2026-09-20T10:00:00+00:00",
        1000,
    )

    child = make_event(
        "event-child",
        "2026-09-20T10:00:05+00:00",
        2000,
    )

    child["process"]["ppid"] = 1000

    assert events_parent_child(parent, child)


def test_unrelated_processes_are_not_parent_child():
    parent = make_event(
        "event-parent",
        "2026-09-20T10:00:00+00:00",
        1000,
    )

    child = make_event(
        "event-child",
        "2026-09-20T10:00:05+00:00",
        2000,
    )

    child["process"]["ppid"] = 9999

    assert not events_parent_child(parent, child)


def test_missing_parent_or_child_pid_does_not_crash():
    parent = make_event(
        "event-parent",
        "2026-09-20T10:00:00+00:00",
        None,
    )

    child = make_event(
        "event-child",
        "2026-09-20T10:00:05+00:00",
        2000,
    )

    child["process"]["ppid"] = None

    assert not events_parent_child(parent, child)


def test_parent_child_events_are_related():
    parent = make_event(
        "event-parent",
        "2026-09-20T10:00:00+00:00",
        1000,
    )

    child = make_event(
        "event-child",
        "2026-09-20T10:00:05+00:00",
        2000,
    )

    child["process"]["ppid"] = 1000

    assert events_are_related(parent, child)


def test_child_parent_order_is_supported():
    parent = make_event(
        "event-parent",
        "2026-09-20T10:00:00+00:00",
        1000,
    )

    child = make_event(
        "event-child",
        "2026-09-20T10:00:05+00:00",
        2000,
    )

    child["process"]["ppid"] = 1000

    assert events_are_related(child, parent)


def test_parent_child_events_outside_window_are_not_related():
    parent = make_event(
        "event-parent",
        "2026-09-20T10:00:00+00:00",
        1000,
    )

    child = make_event(
        "event-child",
        "2026-09-20T10:02:00+00:00",
        2000,
    )

    child["process"]["ppid"] = 1000

    assert not events_are_related(parent, child)  


def test_correlate_events_groups_related_events():
    event_a = make_event(
        "event-a",
        "2026-09-20T10:00:00+00:00",
        1000,
    )

    event_b = make_event(
        "event-b",
        "2026-09-20T10:00:10+00:00",
        1000,
    )

    incidents = correlate_events(
        [event_a, event_b]
    )

    assert len(incidents) == 1
    assert incidents[0]["event_ids"] == [
        "event-a",
        "event-b",
    ]


def test_correlate_events_separates_unrelated_events():
    event_a = make_event(
        "event-a",
        "2026-09-20T10:00:00+00:00",
        1000,
    )

    event_b = make_event(
        "event-b",
        "2026-09-20T10:00:10+00:00",
        2000,
    )

    incidents = correlate_events(
        [event_a, event_b]
    )

    assert len(incidents) == 2
    assert incidents[0]["event_ids"] == ["event-a"]
    assert incidents[1]["event_ids"] == ["event-b"]     


def test_correlate_events_groups_multiple_related_events():
    event_a = make_event(
        "event-a",
        "2026-09-20T10:00:00+00:00",
        1000,
    )

    event_b = make_event(
        "event-b",
        "2026-09-20T10:00:10+00:00",
        1000,
    )

    event_c = make_event(
        "event-c",
        "2026-09-20T10:00:20+00:00",
        1000,
    )

    incidents = correlate_events(
        [event_a, event_b, event_c]
    )

    assert len(incidents) == 1
    assert incidents[0]["event_ids"] == [
        "event-a",
        "event-b",
        "event-c",
    ]     


def test_correlate_events_groups_parent_child_events():
    parent = make_event(
        "event-parent",
        "2026-09-20T10:00:00+00:00",
        1000,
    )

    child = make_event(
        "event-child",
        "2026-09-20T10:00:05+00:00",
        2000,
    )

    child["process"]["ppid"] = 1000

    incidents = correlate_events(
        [parent, child]
    )

    assert len(incidents) == 1
    assert incidents[0]["event_ids"] == [
        "event-parent",
        "event-child",
    ]


def test_correlate_events_separates_parent_child_outside_window():
    parent = make_event(
        "event-parent",
        "2026-09-20T10:00:00+00:00",
        1000,
    )

    child = make_event(
        "event-child",
        "2026-09-20T10:02:00+00:00",
        2000,
    )

    child["process"]["ppid"] = 1000

    incidents = correlate_events(
        [parent, child]
    )

    assert len(incidents) == 2
    assert incidents[0]["event_ids"] == [
        "event-parent"
    ]
    assert incidents[1]["event_ids"] == [
        "event-child"
    ]


    
