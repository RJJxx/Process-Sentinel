// ============================================================
// KEYLOGGER DETECTOR - DASHBOARD
// ============================================================


// ============================================================
// GLOBAL DATA
// ============================================================

let allProcesses = [];

let currentDetectionEvents = [];

let lastDetectionEventId = null;

let liveAlertDetectionEventId = null;

let currentDetectionEventId = null;


// ============================================================
// API HELPER
// ============================================================

async function fetchJSON(url, options = {}) {

    const response = await fetch(
        url,
        options
    );

    if (!response.ok) {

        let errorMessage =
            `API request failed: ${response.status}`;

        try {

            const errorData =
                await response.json();

            if (errorData.error) {

                errorMessage =
                    errorData.error;

            }

        } catch {

            // Ignore JSON parsing errors
        }

        throw new Error(
            errorMessage
        );
    }

    return await response.json();
}


// ============================================================
// HTML ESCAPING
// ============================================================

function escapeHTML(value) {

    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


// ============================================================
// SYSTEM STATUS
// ============================================================

async function updateSystemStatus() {

    const statusElement =
        document.getElementById(
            "system-status"
        );

    const sidebarStatus =
        document.getElementById(
            "sidebar-status"
        );

    try {

        const data =
            await fetchJSON(
                "/api/status"
            );

        if (
            data.status === "online"
        ) {

            if (statusElement) {

                statusElement.textContent =
                    "API Online";

            }

            if (sidebarStatus) {

                sidebarStatus.textContent =
                    "Detector API Online";

            }

        } else {

            if (statusElement) {

                statusElement.textContent =
                    "API Offline";

            }

            if (sidebarStatus) {

                sidebarStatus.textContent =
                    "Detector API Offline";

            }
        }

    } catch (error) {

        console.error(
            "Status error:",
            error
        );

        if (statusElement) {

            statusElement.textContent =
                "API Offline";

        }

        if (sidebarStatus) {

            sidebarStatus.textContent =
                "Detector API Offline";

        }
    }
}


// ============================================================
// STATISTICS
// ============================================================

async function updateStatistics() {

    try {

        const data =
            await fetchJSON(
                "/api/statistics"
            );

        const totalEvents =
            document.getElementById(
                "total-events"
            );

        const highEvents =
            document.getElementById(
                "high-events"
            );

        const mediumEvents =
            document.getElementById(
                "medium-events"
            );

        const criticalEvents =
            document.getElementById(
                "critical-events"
            );

        const riskCritical =
            document.getElementById(
                "risk-critical"
            );

        const riskHigh =
            document.getElementById(
                "risk-high"
            );

        const riskMedium =
            document.getElementById(
                "risk-medium"
            );

        const riskLow =
            document.getElementById(
                "risk-low"
            );

        if (totalEvents) {

            totalEvents.textContent =
                data.total_events ?? 0;

        }

        if (highEvents) {

            highEvents.textContent =
                data.high ?? 0;

        }

        if (mediumEvents) {

            mediumEvents.textContent =
                data.medium ?? 0;

        }

        if (criticalEvents) {

            criticalEvents.textContent =
                data.critical ?? 0;

        }

        if (riskCritical) {

            riskCritical.textContent =
                data.critical ?? 0;

        }

        if (riskHigh) {

            riskHigh.textContent =
                data.high ?? 0;

        }

        if (riskMedium) {

            riskMedium.textContent =
                data.medium ?? 0;

        }

        if (riskLow) {

            riskLow.textContent =
                data.low ?? 0;

        }

    } catch (error) {

        console.error(
            "Statistics error:",
            error
        );

    }
}


// ============================================================
// RISK BADGE
// ============================================================

function createRiskBadge(level) {

    const normalized =
        String(
            level || "Unknown"
        ).toLowerCase();

    return `
        <span class="risk-badge ${normalized}">
            ${escapeHTML(
                level || "Unknown"
            )}
        </span>
    `;
}


// ============================================================
// INVESTIGATION STATUS
// ============================================================

function getInvestigationStatus(event) {

    const investigation =
        event?.investigation || {};

    return (
        investigation.status ||
        "New"
    );
}


// ============================================================
// INVESTIGATION STATUS BADGE
// ============================================================

function createInvestigationBadge(event) {

    const status =
        getInvestigationStatus(
            event
        );

    const normalized =
        status
            .toLowerCase()
            .replace(
                /[^a-z]/g,
                "-"
            );

    return `
        <span
            class="investigation-badge investigation-${escapeHTML(
                normalized
            )}"
        >
            ${escapeHTML(status)}
        </span>
    `;
}


// ============================================================
// FORMAT TIMESTAMP
// ============================================================

function formatTimestamp(timestamp) {

    if (!timestamp) {

        return "Unknown";

    }

    try {

        return new Date(
            timestamp
        ).toLocaleString();

    } catch {

        return timestamp;

    }
}


// ============================================================
// LIVE DETECTION ALERT
// ============================================================

function checkForNewDetection(events) {

    if (
        !Array.isArray(events) ||
        events.length === 0
    ) {

        return;

    }

    const eventsWithTime =
        events
            .map(
                event => ({

                    event: event,

                    time:
                        new Date(
                            event?.timestamp || 0
                        ).getTime() || 0

                })
            )
            .sort(
                (a, b) =>
                    b.time - a.time
            );

    const newest =
        eventsWithTime[0];

    if (
        !newest ||
        !newest.event
    ) {

        return;

    }

    const newestEvent =
        newest.event;

    const newestEventId =
        newestEvent.event_id;

    if (!newestEventId) {

        return;

    }

    if (
        lastDetectionEventId === null
    ) {

        lastDetectionEventId =
            newestEventId;

        return;

    }

    if (
        newestEventId ===
        lastDetectionEventId
    ) {

        return;

    }

    console.log(
        "🚨 NEW SECURITY DETECTION:",
        newestEvent
    );

    lastDetectionEventId =
        newestEventId;

    liveAlertDetectionEventId =
        newestEventId;

    showLiveDetectionAlert(
        newestEvent
    );
}


// ============================================================
// SHOW LIVE DETECTION ALERT
// ============================================================

function showLiveDetectionAlert(event) {

    const alertElement =
        document.getElementById(
            "live-alert"
        );

    const processElement =
        document.getElementById(
            "live-alert-process"
        );

    const detailsElement =
        document.getElementById(
            "live-alert-details"
        );

    if (!alertElement) {

        console.warn(
            "Live alert element not found."
        );

        return;

    }

    const process =
        event.process || {};

    const risk =
        event.risk || {};

    if (processElement) {

        processElement.textContent =
            process.name ||
            "Suspicious process detected";

    }

    if (detailsElement) {

        detailsElement.textContent =
            `Risk: ${
                risk.level || "Unknown"
            }  •  Score: ${
                risk.score ?? 0
            }  •  Confidence: ${
                risk.confidence || "Unknown"
            }`;

    }

    alertElement.classList.remove(
        "hidden"
    );
}


// ============================================================
// CLOSE LIVE DETECTION ALERT
// ============================================================

function closeLiveDetectionAlert() {

    const alertElement =
        document.getElementById(
            "live-alert"
        );

    if (!alertElement) {

        return;

    }

    alertElement.classList.add(
        "hidden"
    );
}


// ============================================================
// OPEN LIVE DETECTION DETAILS
// ============================================================

function openLiveDetectionDetails() {

    if (
        !liveAlertDetectionEventId
    ) {

        return;

    }

    closeLiveDetectionAlert();

    const index =
        currentDetectionEvents.findIndex(
            event =>
                event &&
                event.event_id ===
                liveAlertDetectionEventId
        );

    if (index === -1) {

        console.warn(
            "Live detection event is no longer in the recent event list."
        );

        return;

    }

    viewDetectionDetails(
        index
    );
}


// ============================================================
// LIVE ALERT CONTROLS
// ============================================================

function setupLiveAlert() {

    const closeButton =
        document.getElementById(
            "live-alert-close"
        );

    const viewButton =
        document.getElementById(
            "live-alert-view"
        );

    if (closeButton) {

        closeButton.addEventListener(
            "click",
            closeLiveDetectionAlert
        );

    }

    if (viewButton) {

        viewButton.addEventListener(
            "click",
            openLiveDetectionDetails
        );

    }
}


// ============================================================
// RECENT DETECTIONS
// ============================================================

async function updateRecentDetections() {

    const table =
        document.getElementById(
            "detections-table"
        );

    if (!table) {

        return;

    }

    try {

        const data =
            await fetchJSON(
                "/api/events/recent?limit=10"
            );

        const events =
            data.events || [];

        currentDetectionEvents =
            events;

        checkForNewDetection(
            events
        );

        if (
            events.length === 0
        ) {

            table.innerHTML = `
                <tr>

                    <td
                        colspan="7"
                        class="empty-state"
                    >
                        No detections recorded.
                    </td>

                </tr>
            `;

            return;

        }

        table.innerHTML =
            events
                .map(
                    (event, index) => {

                        const process =
                            event.process || {};

                        const risk =
                            event.risk || {};

                        return `
                            <tr
                                class="detection-row"
                            >

                                <td>

                                    <strong>
                                        ${escapeHTML(
                                            process.name ||
                                            "Unknown"
                                        )}
                                    </strong>

                                </td>

                                <td>

                                    ${createRiskBadge(
                                        risk.level
                                    )}

                                </td>

                                <td>

                                    ${escapeHTML(
                                        risk.score ?? 0
                                    )}

                                </td>

                                <td>

                                    ${escapeHTML(
                                        risk.confidence ||
                                        "Unknown"
                                    )}

                                </td>

                                <td>

                                    ${escapeHTML(
                                        formatTimestamp(
                                            event.timestamp
                                        )
                                    )}

                                </td>

                                <td>

                                    ${createInvestigationBadge(
                                        event
                                    )}

                                </td>

                                <td>

                                    <button
                                        type="button"
                                        class="view-detection-button"
                                        onclick="viewDetectionDetails(${index})"
                                    >
                                        View
                                    </button>

                                </td>

                            </tr>
                        `;

                    }
                )
                .join("");

    } catch (error) {

        console.error(
            "Detection loading error:",
            error
        );

        table.innerHTML = `
            <tr>

                <td
                    colspan="7"
                    class="empty-state"
                >
                    Unable to load detection data.
                </td>

            </tr>
        `;

    }
}


// ============================================================
// CURRENT PROCESSES
// ============================================================

async function updateProcesses() {

    const table =
        document.getElementById(
            "processes-table"
        );

    const countElement =
        document.getElementById(
            "process-count"
        );

    if (!table) {

        return;

    }

    try {

        const data =
            await fetchJSON(
                "/api/processes"
            );

        allProcesses =
            data.processes || [];

        if (countElement) {

            countElement.textContent =
                `${allProcesses.length} processes`;

        }

        renderProcesses(
            allProcesses
        );

    } catch (error) {

        console.error(
            "Process loading error:",
            error
        );

        if (countElement) {

            countElement.textContent =
                "Unable to load";

        }

        table.innerHTML = `
            <tr>

                <td
                    colspan="7"
                    class="empty-state"
                >
                    Unable to load process data.
                </td>

            </tr>
        `;

    }
}


// ============================================================
// RENDER PROCESSES
// ============================================================

function renderProcesses(processes) {

    const table =
        document.getElementById(
            "processes-table"
        );

    if (!table) {

        return;

    }

    if (
        !Array.isArray(processes) ||
        processes.length === 0
    ) {

        table.innerHTML = `
            <tr>

                <td
                    colspan="7"
                    class="empty-state"
                >
                    No processes found.
                </td>

            </tr>
        `;

        return;

    }

    table.innerHTML =
        processes
            .map(
                process => {

                    const networkConnections =
                        process.network_connections ||
                        [];

                    return `
                        <tr>

                            <td>

                                <span
                                    class="process-name"
                                >
                                    ${escapeHTML(
                                        process.name ||
                                        "Unknown"
                                    )}
                                </span>

                            </td>

                            <td>

                                ${escapeHTML(
                                    process.pid ??
                                    "Unknown"
                                )}

                            </td>

                            <td>

                                ${escapeHTML(
                                    process.username ||
                                    "Unknown"
                                )}

                            </td>

                            <td>

                                <span
                                    class="process-status"
                                >

                                    <span
                                        class="process-status-dot"
                                    ></span>

                                    ${escapeHTML(
                                        process.status ||
                                        "Unknown"
                                    )}

                                </span>

                            </td>

                            <td>

                                <span
                                    class="network-count"
                                >
                                    ${
                                        networkConnections.length
                                    }
                                </span>

                            </td>

                            <td>

                                <span
                                    class="process-path"
                                    title="${escapeHTML(
                                        process.exe ||
                                        ""
                                    )}"
                                >
                                    ${escapeHTML(
                                        process.exe ||
                                        "Unknown"
                                    )}
                                </span>

                            </td>

                            <td>

                                <button
                                    type="button"
                                    class="view-process-button"
                                    onclick="viewProcessDetails(${process.pid})"
                                >
                                    View
                                </button>

                            </td>

                        </tr>
                    `;

                }
            )
            .join("");

}


// ============================================================
// PROCESS SEARCH
// ============================================================

function setupProcessSearch() {

    const searchInput =
        document.getElementById(
            "process-search-input"
        );

    if (!searchInput) {

        return;

    }

    searchInput.addEventListener(
        "input",
        () => {

            const search =
                searchInput.value
                    .trim()
                    .toLowerCase();

            if (!search) {

                renderProcesses(
                    allProcesses
                );

                return;

            }

            const filtered =
                allProcesses.filter(
                    process => {

                        const name =
                            String(
                                process.name ||
                                ""
                            ).toLowerCase();

                        const pid =
                            String(
                                process.pid ||
                                ""
                            ).toLowerCase();

                        const username =
                            String(
                                process.username ||
                                ""
                            ).toLowerCase();

                        const exe =
                            String(
                                process.exe ||
                                ""
                            ).toLowerCase();

                        return (
                            name.includes(search) ||
                            pid.includes(search) ||
                            username.includes(search) ||
                            exe.includes(search)
                        );

                    }
                );

            renderProcesses(
                filtered
            );

        }
    );

}


// ============================================================
// PROCESS DETAILS
// ============================================================

async function viewProcessDetails(pid) {

    const modal =
        document.getElementById(
            "process-modal"
        );

    if (!modal) {

        return;

    }

    try {

        const data =
            await fetchJSON(
                `/api/processes/${pid}`
            );

        if (!data.found) {

            alert(
                data.error ||
                "Process could not be found."
            );

            return;

        }

        const process =
            data.process;

        const networkConnections =
            process.network_connections ||
            [];

        const modalProcessName =
            document.getElementById(
                "modal-process-name"
            );

        const modalPid =
            document.getElementById(
                "modal-pid"
            );

        const modalStatus =
            document.getElementById(
                "modal-status"
            );

        const modalUser =
            document.getElementById(
                "modal-user"
            );

        const modalParent =
            document.getElementById(
                "modal-parent"
            );

        const modalNetworkCount =
            document.getElementById(
                "modal-network-count"
            );

        const modalExe =
            document.getElementById(
                "modal-exe"
            );

        const modalCmdline =
            document.getElementById(
                "modal-cmdline"
            );

        if (modalProcessName) {

            modalProcessName.textContent =
                process.name ||
                "Unknown Process";

        }

        if (modalPid) {

            modalPid.textContent =
                process.pid ??
                "Unknown";

        }

        if (modalStatus) {

            modalStatus.textContent =
                process.status ||
                "Unknown";

        }

        if (modalUser) {

            modalUser.textContent =
                process.username ||
                "Unknown";

        }

        if (modalParent) {

            modalParent.textContent =
                process.parent_name ||
                "Unknown";

        }

        if (modalNetworkCount) {

            modalNetworkCount.textContent =
                networkConnections.length;

        }

        if (modalExe) {

            modalExe.textContent =
                process.exe ||
                "Not available";

        }

        const commandLine =
            process.cmdline ||
            [];

        if (modalCmdline) {

            modalCmdline.textContent =
                Array.isArray(commandLine)
                    ? commandLine.join(" ")
                    : String(commandLine);

        }

        renderProcessNetworkConnections(
            networkConnections
        );

        modal.classList.remove(
            "hidden"
        );

    } catch (error) {

        console.error(
            "Process details error:",
            error
        );

        alert(
            "Unable to load process details."
        );

    }
}


// ============================================================
// PROCESS NETWORK CONNECTIONS
// ============================================================

function renderProcessNetworkConnections(
    connections
) {

    const container =
        document.getElementById(
            "modal-network"
        );

    if (!container) {

        return;

    }

    if (
        !connections ||
        connections.length === 0
    ) {

        container.innerHTML = `
            <div class="network-empty">
                No network connections
            </div>
        `;

        return;

    }

    container.innerHTML =
        connections
            .map(
                connection => {

                    const localAddress =
                        connection.local_address ||
                        "Unknown";

                    const remoteIp =
                        connection.remote_ip ||
                        "Unknown";

                    const remotePort =
                        connection.remote_port ??
                        "Unknown";

                    const status =
                        connection.status ||
                        "Unknown";

                    return `
                        <div
                            class="network-item"
                        >

                            <span
                                class="network-local"
                            >
                                ${escapeHTML(
                                    localAddress
                                )}
                            </span>

                            <span
                                class="network-arrow"
                            >
                                →
                            </span>

                            <span
                                class="network-remote"
                            >
                                ${escapeHTML(
                                    remoteIp
                                )}:${escapeHTML(
                                    remotePort
                                )}
                            </span>

                            <span
                                class="network-state"
                            >
                                ${escapeHTML(
                                    status
                                )}
                            </span>

                        </div>
                    `;

                }
            )
            .join("");

}


// ============================================================
// INVESTIGATION UI
// ============================================================

function ensureInvestigationUI() {

    const modal =
        document.getElementById(
            "detection-modal"
        );

    if (!modal) {

        return;

    }

    if (
        document.getElementById(
            "detection-investigation-panel"
        )
    ) {

        return;

    }

    const panel =
        document.createElement(
            "div"
        );

    panel.id =
        "detection-investigation-panel";

    panel.className =
        "detection-investigation-panel";

    panel.innerHTML = `
        <div class="investigation-header">

            <div>

                <div class="investigation-label">
                    INVESTIGATION
                </div>

                <div
                    id="detection-investigation-status"
                    class="investigation-status"
                >
                    New
                </div>

            </div>

            <div
                id="detection-investigation-updated"
                class="investigation-updated"
            >
            </div>

        </div>


        <div
            id="detection-investigation-actions"
            class="investigation-actions"
        >
        </div>

    `;

    const existingContent =
        modal.querySelector(
            ".process-modal-content"
        );

    if (existingContent) {

        existingContent.appendChild(
            panel
        );

        return;

    }

    const closeButton =
        modal.querySelector(
            "#close-detection-modal"
        );

    if (
        closeButton &&
        closeButton.parentElement
    ) {

        closeButton.parentElement.after(
            panel
        );

        return;

    }

    modal.appendChild(
        panel
    );
}


// ============================================================
// RENDER INVESTIGATION STATUS
// ============================================================

function renderInvestigationStatus(
    event
) {

    ensureInvestigationUI();

    const statusElement =
        document.getElementById(
            "detection-investigation-status"
        );

    const updatedElement =
        document.getElementById(
            "detection-investigation-updated"
        );

    const actionsElement =
        document.getElementById(
            "detection-investigation-actions"
        );

    if (!statusElement) {

        return;

    }

    const investigation =
        event?.investigation || {};

    const status =
        investigation.status ||
        "New";

    statusElement.textContent =
        status;

    statusElement.className =
        `investigation-status investigation-status-${status
            .toLowerCase()
            .replace(
                /[^a-z]/g,
                "-"
            )}`;

    if (updatedElement) {

        if (
            investigation.updated_at
        ) {

            updatedElement.textContent =
                `Updated ${formatTimestamp(
                    investigation.updated_at
                )}`;

        } else {

            updatedElement.textContent =
                "";

        }

    }

    if (!actionsElement) {

        return;

    }

    if (
        status === "Investigated"
    ) {

        actionsElement.innerHTML = `
            <button
                type="button"
                class="investigation-button investigation-dismiss"
                onclick="dismissCurrentDetection()"
            >
                Dismiss
            </button>

            <button
                type="button"
                class="investigation-button investigation-reopen"
                onclick="reopenCurrentDetection()"
            >
                Reopen
            </button>
        `;

    } else if (
        status === "Dismissed"
    ) {

        actionsElement.innerHTML = `
            <button
                type="button"
                class="investigation-button investigation-investigate"
                onclick="investigateCurrentDetection()"
            >
                Mark as Investigated
            </button>

            <button
                type="button"
                class="investigation-button investigation-reopen"
                onclick="reopenCurrentDetection()"
            >
                Reopen
            </button>
        `;

    } else {

        actionsElement.innerHTML = `
            <button
                type="button"
                class="investigation-button investigation-investigate"
                onclick="investigateCurrentDetection()"
            >
                Mark as Investigated
            </button>

            <button
                type="button"
                class="investigation-button investigation-dismiss"
                onclick="dismissCurrentDetection()"
            >
                Dismiss
            </button>
        `;

    }
}


// ============================================================
// UPDATE EVENT INVESTIGATION STATUS
// ============================================================

async function updateEventInvestigation(
    action
) {

    if (
        !currentDetectionEventId
    ) {

        alert(
            "No detection event is currently selected."
        );

        return;

    }

    const eventId =
        currentDetectionEventId;

    const actions =
        {
            investigate:
                "investigate",

            dismiss:
                "dismiss",

            reopen:
                "reopen"
        };

    const endpoint =
        actions[action];

    if (!endpoint) {

        console.error(
            "Unknown investigation action:",
            action
        );

        return;

    }

    const actionButtons =
        document.querySelectorAll(
            ".investigation-button"
        );

    actionButtons.forEach(
        button => {

            button.disabled =
                true;

            button.classList.add(
                "loading"
            );

        }
    );

    try {

        const data =
            await fetchJSON(
                `/api/events/${encodeURIComponent(
                    eventId
                )}/${endpoint}`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        updated_by:
                            "analyst"
                    })
                }
            );

        if (
            !data.success
        ) {

            throw new Error(
                data.error ||
                "Unable to update event."
            );

        }

        const updatedEvent =
            data.event;

        // Update local event list.

        const localIndex =
            currentDetectionEvents.findIndex(
                event =>
                    event &&
                    event.event_id ===
                    eventId
            );

        if (
            localIndex !== -1
        ) {

            currentDetectionEvents[
                localIndex
            ] =
                updatedEvent;

        }

        renderInvestigationStatus(
            updatedEvent
        );

        // Refresh the table so the badge changes.

        await updateRecentDetections();

        // Restore the selected event ID.

        currentDetectionEventId =
            eventId;

        // Refresh modal status from the
        // updated event.

        renderInvestigationStatus(
            updatedEvent
        );

        console.log(
            "Investigation status updated:",
            updatedEvent
        );

    } catch (error) {

        console.error(
            "Investigation update error:",
            error
        );

        alert(
            error.message ||
            "Unable to update investigation status."
        );

        renderInvestigationStatus(
            currentDetectionEvents.find(
                event =>
                    event &&
                    event.event_id ===
                    eventId
            ) || {}
        );

    }
}


// ============================================================
// INVESTIGATION ACTIONS
// ============================================================

async function investigateCurrentDetection() {

    await updateEventInvestigation(
        "investigate"
    );
}


async function dismissCurrentDetection() {

    await updateEventInvestigation(
        "dismiss"
    );
}


async function reopenCurrentDetection() {

    await updateEventInvestigation(
        "reopen"
    );
}


// ============================================================
// DETECTION DETAILS
// ============================================================

async function viewDetectionDetails(index) {

    let event =
        currentDetectionEvents[index];

    if (!event) {

        console.error(
            "Detection event not found:",
            index
        );

        return;

    }

    const eventId =
        event.event_id;

    if (!eventId) {

        alert(
            "This detection does not have a valid event ID."
        );

        return;

    }

    currentDetectionEventId =
        eventId;

    // --------------------------------------------------------
    // Fetch the latest version from the API.
    // This ensures we get the current investigation status.
    // --------------------------------------------------------

    try {

        const data =
            await fetchJSON(
                `/api/events/${encodeURIComponent(
                    eventId
                )}`
            );

        if (
            data.found &&
            data.event
        ) {

            event =
                data.event;

            const localIndex =
                currentDetectionEvents.findIndex(
                    item =>
                        item &&
                        item.event_id ===
                        eventId
                );

            if (
                localIndex !== -1
            ) {

                currentDetectionEvents[
                    localIndex
                ] =
                    event;

            }

        }

    } catch (error) {

        console.warn(
            "Unable to refresh detection details:",
            error
        );

        // Continue using the event already
        // loaded in the dashboard.
    }

    const process =
        event.process || {};

    const risk =
        event.risk || {};

    const findings =
        event.findings || [];

    const evidence =
        event.evidence || [];

    const processName =
        document.getElementById(
            "detection-process-name"
        );

    const detectionRisk =
        document.getElementById(
            "detection-risk"
        );

    const detectionScore =
        document.getElementById(
            "detection-score"
        );

    const detectionConfidence =
        document.getElementById(
            "detection-confidence"
        );

    const detectionEventId =
        document.getElementById(
            "detection-event-id"
        );

    const detectionTimestamp =
        document.getElementById(
            "detection-timestamp"
        );

    const detectionPid =
        document.getElementById(
            "detection-pid"
        );

    const detectionUser =
        document.getElementById(
            "detection-user"
        );

    const detectionAlertReason =
        document.getElementById(
            "detection-alert-reason"
        );

    const detectionExe =
        document.getElementById(
            "detection-exe"
        );

    if (processName) {

        processName.textContent =
            process.name ||
            "Unknown Process";

    }

    if (detectionRisk) {

        detectionRisk.textContent =
            risk.level ||
            "Unknown";

    }

    if (detectionScore) {

        detectionScore.textContent =
            risk.score ??
            "—";

    }

    if (detectionConfidence) {

        detectionConfidence.textContent =
            risk.confidence ||
            "Unknown";

    }

    if (detectionEventId) {

        detectionEventId.textContent =
            event.event_id ||
            "—";

    }

    if (detectionTimestamp) {

        detectionTimestamp.textContent =
            formatTimestamp(
                event.timestamp
            );

    }

    if (detectionPid) {

        detectionPid.textContent =
            process.pid ??
            "—";

    }

    if (detectionUser) {

        detectionUser.textContent =
            process.username ||
            "—";

    }

    if (detectionAlertReason) {

        detectionAlertReason.textContent =
            event.alert_reason ||
            "No alert reason available.";

    }

    if (detectionExe) {

        detectionExe.textContent =
            process.exe ||
            "Not available";

    }

    renderDetectionFindings(
        "detection-findings",
        findings
    );

    renderDetectionFindings(
        "detection-evidence",
        evidence
    );

    // --------------------------------------------------------
    // Risk styling
    // --------------------------------------------------------

    if (detectionRisk) {

        detectionRisk.classList.remove(
            "detection-risk-high",
            "detection-risk-medium",
            "detection-risk-critical",
            "detection-risk-low"
        );

        const riskLevel =
            String(
                risk.level || ""
            ).toLowerCase();

        if (
            riskLevel === "high"
        ) {

            detectionRisk.classList.add(
                "detection-risk-high"
            );

        } else if (
            riskLevel === "medium"
        ) {

            detectionRisk.classList.add(
                "detection-risk-medium"
            );

        } else if (
            riskLevel === "critical"
        ) {

            detectionRisk.classList.add(
                "detection-risk-critical"
            );

        } else if (
            riskLevel === "low"
        ) {

            detectionRisk.classList.add(
                "detection-risk-low"
            );

        }

    }

    // --------------------------------------------------------
    // Investigation section
    // --------------------------------------------------------

    ensureInvestigationUI();

    renderInvestigationStatus(
        event
    );

    const modal =
        document.getElementById(
            "detection-modal"
        );

    if (modal) {

        modal.classList.remove(
            "hidden"
        );

    }

}


// ============================================================
// RENDER DETECTION FINDINGS
// ============================================================

function renderDetectionFindings(
    containerId,
    findings
) {

    const container =
        document.getElementById(
            containerId
        );

    if (!container) {

        return;

    }

    if (
        !findings ||
        findings.length === 0
    ) {

        container.innerHTML = `
            <div class="network-empty">
                No findings available
            </div>
        `;

        return;

    }

    container.innerHTML =
        findings
            .map(
                finding => {

                    const severity =
                        String(
                            finding.severity ||
                            "Unknown"
                        );

                    const severityClass =
                        severity
                            .toLowerCase()
                            .replace(
                                /[^a-z]/g,
                                ""
                            );

                    return `
                        <div
                            class="detection-finding detection-${severityClass}"
                        >

                            <div
                                class="detection-finding-header"
                            >

                                <div>

                                    <div
                                        class="detection-rule-id"
                                    >
                                        ${escapeHTML(
                                            finding.id ||
                                            "UNKNOWN"
                                        )}
                                    </div>

                                    <div
                                        class="detection-rule-name"
                                    >
                                        ${escapeHTML(
                                            finding.rule ||
                                            "Unknown Rule"
                                        )}
                                    </div>

                                </div>

                                <span
                                    class="detection-severity"
                                >
                                    ${escapeHTML(
                                        severity
                                    )}
                                </span>

                            </div>

                            <div
                                class="detection-finding-description"
                            >
                                ${escapeHTML(
                                    finding.description ||
                                    "No description available."
                                )}
                            </div>

                        </div>
                    `;

                }
            )
            .join("");

}


// ============================================================
// PROCESS MODAL CONTROLS
// ============================================================

function setupProcessModal() {

    const modal =
        document.getElementById(
            "process-modal"
        );

    const closeButton =
        document.getElementById(
            "close-process-modal"
        );

    if (
        !modal ||
        !closeButton
    ) {

        return () => {};

    }

    const overlay =
        modal.querySelector(
            ".process-modal-overlay"
        );

    function closeModal() {

        modal.classList.add(
            "hidden"
        );

    }

    closeButton.addEventListener(
        "click",
        closeModal
    );

    if (overlay) {

        overlay.addEventListener(
            "click",
            closeModal
        );

    }

    return closeModal;
}


// ============================================================
// DETECTION MODAL CONTROLS
// ============================================================

function setupDetectionModal() {

    const modal =
        document.getElementById(
            "detection-modal"
        );

    const closeButton =
        document.getElementById(
            "close-detection-modal"
        );

    if (
        !modal ||
        !closeButton
    ) {

        return () => {};

    }

    const overlay =
        modal.querySelector(
            ".process-modal-overlay"
        );

    function closeModal() {

        modal.classList.add(
            "hidden"
        );

        currentDetectionEventId =
            null;

    }

    closeButton.addEventListener(
        "click",
        closeModal
    );

    if (overlay) {

        overlay.addEventListener(
            "click",
            closeModal
        );

    }

    return closeModal;
}


// ============================================================
// REFRESH BUTTONS
// ============================================================

function setupRefreshButtons() {

    const refreshButton =
        document.getElementById(
            "refresh-button"
        );

    if (refreshButton) {

        refreshButton.addEventListener(
            "click",
            async () => {

                refreshButton.disabled =
                    true;

                refreshButton.textContent =
                    "Refreshing...";

                try {

                    await updateDashboard();

                } finally {

                    refreshButton.disabled =
                        false;

                    refreshButton.textContent =
                        "Refresh";

                }

            }
        );

    }

    const processRefreshButton =
        document.getElementById(
            "process-refresh-button"
        );

    if (processRefreshButton) {

        processRefreshButton.addEventListener(
            "click",
            async () => {

                processRefreshButton.disabled =
                    true;

                processRefreshButton.textContent =
                    "Refreshing...";

                try {

                    await updateProcesses();

                } finally {

                    processRefreshButton.disabled =
                        false;

                    processRefreshButton.textContent =
                        "Refresh";

                }

            }
        );

    }

}


// ============================================================
// DASHBOARD UPDATE
// ============================================================

async function updateDashboard() {

    await Promise.all([

        updateSystemStatus(),

        updateStatistics(),

        updateRecentDetections(),

        updateProcesses()

    ]);

}


// ============================================================
// KEYBOARD CONTROLS
// ============================================================

function setupKeyboardControls(
    closeProcessModal,
    closeDetectionModal
) {

    document.addEventListener(
        "keydown",
        event => {

            if (
                event.key !== "Escape"
            ) {

                return;

            }

            if (closeProcessModal) {

                closeProcessModal();

            }

            if (closeDetectionModal) {

                closeDetectionModal();

            }

            closeLiveDetectionAlert();

        }
    );

}


// ============================================================
// INITIALIZE DASHBOARD
// ============================================================

document.addEventListener(
    "DOMContentLoaded",
    () => {

        // ----------------------------------------------------
        // Initial dashboard load
        // ----------------------------------------------------

        updateDashboard();


        // ----------------------------------------------------
        // Search
        // ----------------------------------------------------

        setupProcessSearch();


        // ----------------------------------------------------
        // Refresh buttons
        // ----------------------------------------------------

        setupRefreshButtons();


        // ----------------------------------------------------
        // Live detection alert
        // ----------------------------------------------------

        setupLiveAlert();


        // ----------------------------------------------------
        // Investigation UI
        // ----------------------------------------------------

        ensureInvestigationUI();


        // ----------------------------------------------------
        // Process details modal
        // ----------------------------------------------------

        const closeProcessModal =
            setupProcessModal();


        // ----------------------------------------------------
        // Detection details modal
        // ----------------------------------------------------

        const closeDetectionModal =
            setupDetectionModal();


        // ----------------------------------------------------
        // Keyboard controls
        // ----------------------------------------------------

        setupKeyboardControls(
            closeProcessModal,
            closeDetectionModal
        );


        // ----------------------------------------------------
        // Auto-refresh every 5 seconds
        // ----------------------------------------------------

        setInterval(
            updateDashboard,
            5000
        );

    }
);