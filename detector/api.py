from flask import Flask, jsonify, render_template, request

from detector.event_manager import (
    get_all_events,
    get_recent_events,
    get_detection_statistics,
    get_event,
    investigate_event,
    dismiss_event,
    reopen_event,
)

from detector.process_monitor import get_running_processes


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(
    __name__,
    template_folder="../web/templates",
    static_folder="../web/static",
)


# ============================================================
# WEB DASHBOARD
# ============================================================

@app.route("/", methods=["GET"])
def dashboard():
    """
    Serve the main security monitoring dashboard.
    """

    return render_template(
        "dashboard.html"
    )


# ============================================================
# API: STATUS
# ============================================================

@app.route(
    "/api/status",
    methods=["GET"]
)
def api_status():

    return jsonify({
        "status": "online",
        "service": "Keylogger Detector API"
    })


# ============================================================
# API: HEALTH
# ============================================================

@app.route(
    "/api/health",
    methods=["GET"]
)
def api_health():

    return jsonify({
        "status": "healthy"
    })


# ============================================================
# API: ALL EVENTS
# ============================================================

@app.route(
    "/api/events",
    methods=["GET"]
)
def api_events():

    events = get_all_events()

    return jsonify({
        "count": len(events),
        "events": events
    })


# ============================================================
# API: RECENT EVENTS
# ============================================================

@app.route(
    "/api/events/recent",
    methods=["GET"]
)
def api_recent_events():

    try:

        limit = int(
            request.args.get(
                "limit",
                10
            )
        )

    except (ValueError, TypeError):

        limit = 10


    # --------------------------------------------------------
    # Protect API from invalid values
    # --------------------------------------------------------

    if limit < 1:

        limit = 1


    if limit > 100:

        limit = 100


    events = get_recent_events(
        limit
    )


    return jsonify({
        "count": len(events),
        "events": events
    })


# ============================================================
# API: SINGLE EVENT
# ============================================================

@app.route(
    "/api/events/<event_id>",
    methods=["GET"]
)
def api_event_details(event_id):
    """
    Return one detection event using its event ID.
    """

    event = get_event(
        event_id
    )


    if event is None:

        return jsonify({
            "found": False,
            "error": (
                f"Event '{event_id}' "
                "was not found."
            )
        }), 404


    return jsonify({
        "found": True,
        "event": event
    })


# ============================================================
# API: MARK EVENT AS INVESTIGATED
# ============================================================

@app.route(
    "/api/events/<event_id>/investigate",
    methods=["POST"]
)
def api_investigate_event(event_id):
    """
    Mark a detection event as Investigated.

    Optional JSON body:

        {
            "updated_by": "analyst"
        }
    """

    data = request.get_json(
        silent=True
    ) or {}


    updated_by = data.get(
        "updated_by",
        "analyst"
    )


    try:

        event = investigate_event(
            event_id,
            updated_by
        )

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


    if event is None:

        return jsonify({
            "success": False,
            "error": (
                f"Event '{event_id}' "
                "was not found."
            )
        }), 404


    return jsonify({
        "success": True,
        "message": (
            "Event marked as Investigated."
        ),
        "event": event
    })


# ============================================================
# API: DISMISS EVENT
# ============================================================

@app.route(
    "/api/events/<event_id>/dismiss",
    methods=["POST"]
)
def api_dismiss_event(event_id):
    """
    Mark a detection event as Dismissed.

    Optional JSON body:

        {
            "updated_by": "analyst"
        }
    """

    data = request.get_json(
        silent=True
    ) or {}


    updated_by = data.get(
        "updated_by",
        "analyst"
    )


    try:

        event = dismiss_event(
            event_id,
            updated_by
        )

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


    if event is None:

        return jsonify({
            "success": False,
            "error": (
                f"Event '{event_id}' "
                "was not found."
            )
        }), 404


    return jsonify({
        "success": True,
        "message": (
            "Event marked as Dismissed."
        ),
        "event": event
    })


# ============================================================
# API: REOPEN EVENT
# ============================================================

@app.route(
    "/api/events/<event_id>/reopen",
    methods=["POST"]
)
def api_reopen_event(event_id):
    """
    Reset an event back to New.

    Optional JSON body:

        {
            "updated_by": "analyst"
        }
    """

    data = request.get_json(
        silent=True
    ) or {}


    updated_by = data.get(
        "updated_by",
        "analyst"
    )


    try:

        event = reopen_event(
            event_id,
            updated_by
        )

    except Exception as error:

        return jsonify({
            "success": False,
            "error": str(error)
        }), 500


    if event is None:

        return jsonify({
            "success": False,
            "error": (
                f"Event '{event_id}' "
                "was not found."
            )
        }), 404


    return jsonify({
        "success": True,
        "message": (
            "Event reopened."
        ),
        "event": event
    })


# ============================================================
# API: STATISTICS
# ============================================================

@app.route(
    "/api/statistics",
    methods=["GET"]
)
def api_statistics():

    statistics = (
        get_detection_statistics()
    )


    return jsonify(
        statistics
    )


# ============================================================
# API: CURRENT PROCESSES
# ============================================================

@app.route(
    "/api/processes",
    methods=["GET"]
)
def api_processes():

    processes = (
        get_running_processes()
    )


    return jsonify({
        "count": len(processes),
        "processes": processes
    })


# ============================================================
# API: PROCESS DETAILS
# ============================================================

@app.route(
    "/api/processes/<int:pid>",
    methods=["GET"]
)
def api_process_details(pid):
    """
    Return detailed information
    for a specific running process.
    """

    processes = (
        get_running_processes()
    )


    for process in processes:

        if process.get(
            "pid"
        ) == pid:

            return jsonify({
                "found": True,
                "process": process
            })


    return jsonify({
        "found": False,
        "error": (
            f"Process with PID {pid} "
            "was not found."
        )
    }), 404


# ============================================================
# START FLASK SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )