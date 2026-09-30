"""
Data playbook (UC16 PB1) run by an analyst on any container. Reads a host&#39;s security posture from Tehtris EDR -- inventory, isolation state, system info, processes, live connections, installed software and recent events -- and writes it as a Tehtris Posture note. Changes nothing on the host.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


################################################################################
## Global Custom Code Start
################################################################################
################################################################################

# Design notes (kept here because a VPE save replaces the module docstring):
# UC16 PB1 -- see docs/usecases/uc16_tehtris_edr_implementation_plan.md.
# Read-only: every action here is an investigate action, so the playbook is
# safe to run and re-run on any container (label "*"). The hostname input is
# the check that it belongs; get host detail is the existence check and, since
# connector v1.2.1, reports an unknown host as a success with total_hosts 0.
# Live calls (isolation status, system info, netstat, software) need the agent
# connected -- 504 otherwise -- and system info is Windows-only (501); a failed
# call becomes "not available" in the note and never fails the playbook.

from datetime import timezone

# The target SOAR shows at most about 22,000 characters of a note, so no note
# is posted longer than this; a longer one is split by _note_parts().
_NOTE_MAX_CHARS = 20000
_DEFAULT_LOOKBACK_MINUTES = 60
# Tehtris refuses an events query that starts more than 43 days back.
_MAX_LOOKBACK_MINUTES = 42 * 24 * 60
# Characters each table may use, so a table never has to be split across
# note parts; rows past the budget stay in the action result.
_TABLE_BUDGETS = {"processes": 9000, "connections": 4000, "software": 4000, "events": 4000}
_CELL_MAX_CHARS = 200
_SUMMARY_MAX_CHARS = 2000
_ACTIONS = [
    "get_host_detail",
    "get_isolation_status",
    "get_system_info",
    "get_processes",
    "get_network_info",
    "list_software",
    "get_recent_events",
]


def _note_parts(title, content, limit=_NOTE_MAX_CHARS):
    """[(title, content)] for one note, or numbered parts "title (k/N)" cut at
    line boundaries when content is longer than limit. A line longer than the
    limit is cut inside itself. Parts after the first open with a heading."""
    if len(content) <= limit:
        return [(title, content)]
    budget = limit - 300  # room for the heading added to later parts
    chunks, current, size = [], [], 0
    for line in content.split("\n"):
        for piece in [line[i:i + budget] for i in range(0, len(line), budget)] or [""]:
            if current and size + len(piece) + 1 > budget:
                chunks.append("\n".join(current))
                current, size = [], 0
            current.append(piece)
            size += len(piece) + 1
    if current:
        chunks.append("\n".join(current))
    total = len(chunks)
    return [("{} ({}/{})".format(title, n, total),
             chunk if n == 1 else "# {} ({}/{}, continued)\n\n{}".format(title, n, total, chunk))
            for n, chunk in enumerate(chunks, 1)]


def _code(value, limit=_CELL_MAX_CHARS):
    """A value from Tehtris as an inline code span, safe inside a markdown table:
    one line, no backticks, pipes escaped, cut at limit. Code spans keep links
    and markup in endpoint data (command lines, paths) inert."""
    if value is None or value == "":
        return "—"
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True, default=str)
    text = " ".join(str(value).split()).replace("`", "'")
    if len(text) > limit:
        text = text[:limit - 1] + "…"
    return "`{}`".format(text.replace("|", "\\|"))


def _table(headers, rows, what, budget):
    """A markdown table of as many rows as fit in `budget` characters, with a
    line saying how many were left out."""
    if not rows:
        return ["No {} returned.".format(what)]
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    size = sum(len(line) + 1 for line in lines)
    shown = 0
    for row in rows:
        line = "| " + " | ".join(row) + " |"
        if shown and size + len(line) + 1 > budget:
            break
        lines.append(line)
        size += len(line) + 1
        shown += 1
    if shown < len(rows):
        lines.append("")
        lines.append("{} more {} are in the action result.".format(len(rows) - shown, what))
    return lines


def _pack(title, sections, limit=_NOTE_MAX_CHARS):
    """[(title, content)] with whole sections packed into as few notes as fit
    under limit, titled "title (k/N)" when there are several; a section is only
    ever cut (by _note_parts) if it alone is longer than a note."""
    budget = limit - 300  # room for the heading added to later parts
    chunks, current = [], ""
    for section in sections:
        if len(section) > budget:
            if current:
                chunks.append(current)
                current = ""
            chunks += [content for _, content in _note_parts(title, section, budget)]
            continue
        if current and len(current) + len(section) + 2 > budget:
            chunks.append(current)
            current = ""
        current = section if not current else current + "\n\n" + section
    if current:
        chunks.append(current)
    if len(chunks) == 1:
        return [(title, chunks[0])]
    total = len(chunks)
    return [("{} ({}/{})".format(title, n, total),
             chunk if n == 1 else "# {} ({}/{}, continued)\n\n{}".format(title, n, total, chunk))
            for n, chunk in enumerate(chunks, 1)]


def _plain_rows(data):
    """Action-result data items without the connector's raw_json copy."""
    return [{k: v for k, v in item.items() if k != "raw_json"} for item in data if isinstance(item, dict)]


def _generic_rows(data, max_columns=8):
    """Headers and rows for replies whose columns the vendor does not list
    (netstat, software): the keys of the rows themselves, in first-seen order."""
    rows = _plain_rows(data)
    headers = []
    for row in rows:
        for key in row:
            if key not in headers:
                headers.append(key)
    headers = headers[:max_columns]
    return headers, [[_code(row.get(h)) for h in headers] for row in rows]


def _nested(item, dotted):
    for part in dotted.split("."):
        item = item.get(part) if isinstance(item, dict) else None
    return item


def _unavailable(result):
    return "Not available: {}".format(_code(result.get("message") or "no result", limit=300))


def _posture(hostname, window, outcome):
    """(note sections, playbook output) from every action's outcome, a dict
    {action name: {status, message, summary, data}}."""
    ok = {name: (outcome.get(name) or {}).get("status") == "success" for name in _ACTIONS}
    detail = outcome["get_host_detail"]
    hosts = _plain_rows(detail.get("data") or [])
    host = hosts[0] if hosts else {}

    isolation = outcome["get_isolation_status"]
    isolated = (isolation.get("summary") or {}).get("isolated") if ok["get_isolation_status"] else None
    isolation_state = "isolated" if isolated is True else "not isolated" if isolated is False else "unknown"
    if ok["get_isolation_status"]:
        isolation_text = {"isolated": "**isolated**", "not isolated": "not isolated"}.get(
            isolation_state, "unknown (Tehtris answered without a state)")
    else:
        isolation_text = "unknown — " + _unavailable(isolation)

    system = _plain_rows(outcome["get_system_info"].get("data") or [])
    system = system[0] if system else {}
    os_text = " ".join(str(system.get(k)) for k in ("name", "release", "version") if system.get(k))
    if not os_text:
        host_os = host.get("os") if isinstance(host.get("os"), dict) else {}
        os_text = " ".join(str(host_os.get(k)) for k in ("name", "version") if host_os.get(k))

    def count(name, key):
        return (outcome[name].get("summary") or {}).get(key) if ok[name] else None

    process_count = count("get_processes", "num_processes")
    connection_count = count("get_network_info", "num_connections")
    software_count = count("list_software", "num_software")
    event_count = count("get_recent_events", "num_events")

    lines = [
        "# Tehtris posture: {}".format(_code(hostname)),
        "",
        "- **Isolation:** {}".format(isolation_text),
        "- **OS:** {}".format(_code(os_text) if os_text else "unknown"),
        "- **Agent last seen:** {}".format(_code(host.get("lastSeen"))),
        "- **First seen:** {}".format(_code(host.get("firstSeen"))),
        "- **Domain:** {}".format(_code(host.get("domain"))),
        "- **Local / remote IP:** {} / {}".format(_code(host.get("localIp")), _code(host.get("remoteIp"))),
        "- **Tags:** {}".format(_code(host.get("tags"))),
        "- **Endpoint:** uuid {}, appliance {}".format(_code(host.get("uuid")), _code(host.get("applianceId"))),
        "- **Window:** {} to {} ({} minutes)".format(_code(window["time_from"]), _code(window["time_to"]), window["minutes"]),
    ]
    if len(hosts) > 1:
        lines.append("- **{} endpoints are named {}** (a re-installed agent keeps its hostname under a new uuid). "
                     "This note shows the most recently seen one; write actions refuse such a hostname.".format(
                         len(hosts), _code(hostname)))

    sections = []
    lines += ["", "## System info", ""]
    if ok["get_system_info"] and system:
        lines += _table(["Name", "Type", "Architecture", "Release", "Version"],
                        [[_code(system.get(k)) for k in ("name", "type", "architecture", "release", "version")]],
                        "system info", _NOTE_MAX_CHARS)
    else:
        lines.append(_unavailable(outcome["get_system_info"]) if not ok["get_system_info"] else "No system info returned.")

    sections.append("\n".join(lines))
    lines = ["## Processes alive in the window ({})".format(process_count if process_count is not None else "?"), ""]
    if ok["get_processes"]:
        rows = []
        for proc in _plain_rows(outcome["get_processes"].get("data") or []):
            binaries = proc.get("binaries") if isinstance(proc.get("binaries"), list) else []
            first = binaries[0] if binaries and isinstance(binaries[0], dict) else {}
            rows.append([_code(proc.get("pid")), _code(proc.get("ppid")), _code(proc.get("username")),
                         _code(proc.get("created")), _code(proc.get("cmdline")), _code(first.get("sha256"))])
        lines += _table(["PID", "PPID", "User", "Created", "Command line", "SHA-256"], rows, "processes", _TABLE_BUDGETS["processes"])
    else:
        lines.append(_unavailable(outcome["get_processes"]))

    sections.append("\n".join(lines))
    lines = ["## Network connections, live ({})".format(connection_count if connection_count is not None else "?"), ""]
    if ok["get_network_info"]:
        headers, rows = _generic_rows(outcome["get_network_info"].get("data") or [])
        lines += _table(headers, rows, "connections", _TABLE_BUDGETS["connections"])
    else:
        lines.append(_unavailable(outcome["get_network_info"]))

    sections.append("\n".join(lines))
    lines = ["## Installed software ({})".format(software_count if software_count is not None else "?"), ""]
    if ok["list_software"]:
        headers, rows = _generic_rows(outcome["list_software"].get("data") or [])
        lines += _table(headers, rows, "software entries", _TABLE_BUDGETS["software"])
    else:
        lines.append(_unavailable(outcome["list_software"]))

    sections.append("\n".join(lines))
    lines = ["## Tehtris events since {} ({})".format(_code(window["time_from"]),
                                                    event_count if event_count is not None else "?"), ""]
    if ok["get_recent_events"]:
        rows = []
        for event in _plain_rows(outcome["get_recent_events"].get("data") or []):
            rows.append([_code(event.get("time")), _code(event.get("lvl")), _code(event.get("module")),
                         _code(_nested(event, "threat.name")), _code(event.get("path") or event.get("cmdline"))])
        lines += _table(["Time", "Level", "Module", "Threat", "Path / command line"], rows, "events", _TABLE_BUDGETS["events"])
    else:
        lines.append(_unavailable(outcome["get_recent_events"]))
    sections.append("\n".join(lines))

    missing = [name for name in _ACTIONS if not ok[name]]
    status = "success" if not missing else "partial"
    summary = "\n".join([
        "Tehtris posture of {}: isolation {}; OS {}; agent last seen {}.".format(
            hostname, isolation_state, os_text or "unknown", host.get("lastSeen") or "unknown"),
        "Processes {}, connections {}, software {}, events {} (window {} min).".format(
            *["n/a" if c is None else c for c in (process_count, connection_count, software_count, event_count)],
            window["minutes"]),
        "Not available: {}.".format(", ".join(missing)) if missing else "All sections available.",
    ])[:_SUMMARY_MAX_CHARS]
    output = {
        "status": status,
        "host_found": True,
        "os": os_text or None,
        "agent_last_seen": host.get("lastSeen"),
        "isolation_state": isolation_state,
        "process_count": process_count,
        "connection_count": connection_count,
        "software_count": software_count,
        "event_count": event_count,
        "summary": summary,
    }
    return sections, output
################################################################################
################################################################################
## Global Custom Code End
################################################################################

@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'check_inputs' block
    check_inputs(container=container)

    return

@phantom.playbook_block()
def check_inputs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("check_inputs() called")

    ################################################################################
    # Check the hostname input and build the lookback window in both time formats.
    ################################################################################

    playbook_input_hostname = phantom.collect2(container=container, datapath=["playbook_input:hostname"])
    playbook_input_lookback_minutes = phantom.collect2(container=container, datapath=["playbook_input:lookback_minutes"])

    playbook_input_hostname_values = [item[0] for item in playbook_input_hostname]
    playbook_input_lookback_minutes_values = [item[0] for item in playbook_input_lookback_minutes]

    check_inputs__hostname = None
    check_inputs__time_from = None
    check_inputs__time_to = None
    check_inputs__from_date = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################

    # Read again here so this block does not depend on the generated variable names.
    hostname_rows = phantom.collect2(container=container, datapath=["playbook_input:hostname"])
    lookback_rows = phantom.collect2(container=container, datapath=["playbook_input:lookback_minutes"])
    hostname = str((hostname_rows[0][0] if hostname_rows else None) or "").strip()
    lookback_raw = str((lookback_rows[0][0] if lookback_rows else None) or "").strip()

    problem = None
    lookback = _DEFAULT_LOOKBACK_MINUTES
    if lookback_raw:
        try:
            lookback = int(float(lookback_raw))
        except (ValueError, OverflowError):
            lookback = None
        if lookback is None or not 1 <= lookback <= _MAX_LOOKBACK_MINUTES:
            problem = ("lookback_minutes must be a whole number of minutes from 1 to {} (42 days); got {}."
                       .format(_MAX_LOOKBACK_MINUTES, _code(lookback_raw)))
    if not hostname:
        problem = "No hostname was given. Run the playbook again with the endpoint's hostname as Tehtris shows it."

    if problem:
        phantom.error(problem)
        phantom.add_note(
            container=container,
            note_type="general",
            title="Tehtris Posture - Error",
            content=problem,
            note_format="markdown",  # the content is markdown; add_note() defaults to html
        )
        phantom.save_run_data(key="playbook_output", value=json.dumps({
            "status": "error", "host_found": False, "summary": problem}))
        return

    # get processes takes ISO 8601 date-times, get events epoch seconds.
    now = datetime.now(timezone.utc).replace(microsecond=0)
    start = now - timedelta(minutes=lookback)
    check_inputs__hostname = hostname
    check_inputs__time_from = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    check_inputs__time_to = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    check_inputs__from_date = int(start.timestamp())

    # Also saved as run data: later blocks read these keys in their own Custom Code.
    for key, value in (("hostname", check_inputs__hostname), ("time_from", check_inputs__time_from),
                       ("time_to", check_inputs__time_to), ("from_date", check_inputs__from_date),
                       ("lookback_minutes", lookback)):
        phantom.save_run_data(key="check_inputs:" + key, value=json.dumps(value))

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="check_inputs__inputs:0:playbook_input:hostname", value=json.dumps(playbook_input_hostname_values))
    phantom.save_block_result(key="check_inputs__inputs:1:playbook_input:lookback_minutes", value=json.dumps(playbook_input_lookback_minutes_values))

    phantom.save_block_result(key="check_inputs:hostname", value=json.dumps(check_inputs__hostname))
    phantom.save_block_result(key="check_inputs:time_from", value=json.dumps(check_inputs__time_from))
    phantom.save_block_result(key="check_inputs:time_to", value=json.dumps(check_inputs__time_to))
    phantom.save_block_result(key="check_inputs:from_date", value=json.dumps(check_inputs__from_date))

    phantom.save_block_result(key="check_inputs_called", value="True")

    get_host_detail(container=container)

    return


@phantom.playbook_block()
def get_host_detail(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_host_detail() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Find the endpoint in the Tehtris EDR inventory (exact hostname match).
    ################################################################################

    check_inputs__hostname = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:hostname")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if check_inputs__hostname is not None:
        parameters.append({
            "hostname": check_inputs__hostname,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get host detail", parameters=parameters, name="get_host_detail", assets=["tehtris_mock_8446"], callback=check_host)

    return


@phantom.playbook_block()
def check_host(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("check_host() called")

    ################################################################################
    # Classify the inventory lookup: found, not found, or the call failed.
    ################################################################################

    get_host_detail_result_data = phantom.collect2(container=container, datapath=["get_host_detail:action_result.status","get_host_detail:action_result.message","get_host_detail:action_result.summary.total_hosts"], action_results=results)

    get_host_detail_result_item_0 = [item[0] for item in get_host_detail_result_data]
    get_host_detail_result_message = [item[1] for item in get_host_detail_result_data]
    get_host_detail_summary_total_hosts = [item[2] for item in get_host_detail_result_data]

    check_host__host_state = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################

    # Since connector v1.2.1 an unknown hostname is a success with total_hosts 0;
    # a failed status means the lookup itself failed.
    rows = phantom.collect2(container=container, datapath=[
        "get_host_detail:action_result.status",
        "get_host_detail:action_result.message",
        "get_host_detail:action_result.summary.total_hosts",
    ])
    status, message, total = (list(rows[0]) + [None, None, None])[:3] if rows else (None, "The inventory lookup returned no result.", None)
    if status != "success":
        check_host__host_state = "failed"
    elif not total:
        check_host__host_state = "not_found"
    else:
        check_host__host_state = "found"

    phantom.save_run_data(key="check_host:host_state", value=json.dumps(check_host__host_state))
    phantom.save_run_data(key="check_host:message", value=json.dumps(message or ""))

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="check_host__inputs:0:get_host_detail:action_result.status", value=json.dumps(get_host_detail_result_item_0))
    phantom.save_block_result(key="check_host__inputs:1:get_host_detail:action_result.message", value=json.dumps(get_host_detail_result_message))
    phantom.save_block_result(key="check_host__inputs:2:get_host_detail:action_result.summary.total_hosts", value=json.dumps(get_host_detail_summary_total_hosts))

    phantom.save_block_result(key="check_host:host_state", value=json.dumps(check_host__host_state))

    phantom.save_block_result(key="check_host_called", value="True")

    host_found(container=container)

    return


@phantom.playbook_block()
def host_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("host_found() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["check_host:custom_function:host_state", "==", "found"]
        ],
        conditions_dps=[
            ["check_host:custom_function:host_state", "==", "found"]
        ],
        name="host_found:condition_1",
        delimiter=",")

    # call connected blocks if condition 1 matched
    if found_match_1:
        get_isolation_status(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    note_no_host(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def get_isolation_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_isolation_status() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Read whether the endpoint is network-isolated (live: needs the agent connected).
    ################################################################################

    check_inputs__hostname = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:hostname")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if check_inputs__hostname is not None:
        parameters.append({
            "hostname": check_inputs__hostname,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get isolation status", parameters=parameters, name="get_isolation_status", assets=["tehtris_mock_8446"], callback=get_system_info)

    return


@phantom.playbook_block()
def get_system_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_system_info() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Read OS details (live; Windows only, other systems may answer 501).
    ################################################################################

    check_inputs__hostname = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:hostname")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if check_inputs__hostname is not None:
        parameters.append({
            "hostname": check_inputs__hostname,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get system info", parameters=parameters, name="get_system_info", assets=["tehtris_mock_8446"], callback=get_processes)

    return


@phantom.playbook_block()
def get_processes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_processes() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # List the processes alive during the lookback window (works with the agent offline).
    ################################################################################

    check_inputs__time_to = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:time_to")) != "" else "null")  # pylint: disable=used-before-assignment
    check_inputs__hostname = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:hostname")) != "" else "null")  # pylint: disable=used-before-assignment
    check_inputs__time_from = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:time_from")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if check_inputs__hostname is not None:
        parameters.append({
            "time_to": check_inputs__time_to,
            "hostname": check_inputs__hostname,
            "time_from": check_inputs__time_from,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get processes", parameters=parameters, name="get_processes", assets=["tehtris_mock_8446"], callback=get_network_info)

    return


@phantom.playbook_block()
def get_network_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_network_info() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Read the endpoint's live network connections (netstat).
    ################################################################################

    check_inputs__hostname = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:hostname")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if check_inputs__hostname is not None:
        parameters.append({
            "hostname": check_inputs__hostname,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get network info", parameters=parameters, name="get_network_info", assets=["tehtris_mock_8446"], callback=list_software)

    return


@phantom.playbook_block()
def list_software(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_software() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # List the software installed on the endpoint (live).
    ################################################################################

    check_inputs__hostname = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:hostname")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if check_inputs__hostname is not None:
        parameters.append({
            "hostname": check_inputs__hostname,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("list software", parameters=parameters, name="list_software", assets=["tehtris_mock_8446"], callback=get_recent_events)

    return


@phantom.playbook_block()
def get_recent_events(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_recent_events() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Fetch the host's Tehtris events since the window start (alert context).
    ################################################################################

    check_inputs__hostname = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:hostname")) != "" else "null")  # pylint: disable=used-before-assignment
    check_inputs__from_date = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:from_date")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if check_inputs__hostname is not None and check_inputs__from_date is not None:
        parameters.append({
            "hostname": check_inputs__hostname,
            "from_date": check_inputs__from_date,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get events", parameters=parameters, name="get_recent_events", assets=["tehtris_mock_8446"], callback=note_posture)

    return


@phantom.playbook_block()
def note_posture(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("note_posture() called")

    ################################################################################
    # Write the Tehtris Posture note, one section per action; a failed call shows 
    # as not available.
    ################################################################################

    get_recent_events_result_data = phantom.collect2(container=container, datapath=["get_recent_events:action_result.status"], action_results=results)
    check_inputs__hostname = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:hostname")) != "" else "null")  # pylint: disable=used-before-assignment

    get_recent_events_result_item_0 = [item[0] for item in get_recent_events_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################

    hostname = json.loads(phantom.get_run_data(key="check_inputs:hostname") or '""')
    window = {
        "time_from": json.loads(phantom.get_run_data(key="check_inputs:time_from") or '""'),
        "time_to": json.loads(phantom.get_run_data(key="check_inputs:time_to") or '""'),
        "minutes": json.loads(phantom.get_run_data(key="check_inputs:lookback_minutes") or "null"),
    }

    # Every action ran on this path; read each one's result by its block name.
    outcome = {}
    for name in _ACTIONS:
        rows = phantom.collect2(container=container, datapath=[
            name + ":action_result.status",
            name + ":action_result.message",
            name + ":action_result.summary",
            name + ":action_result.data",
        ])
        status, message, summary, data = (list(rows[0]) + [None] * 4)[:4] if rows else (None, "no result", None, None)
        outcome[name] = {"status": status, "message": message or "", "summary": summary or {}, "data": data or []}

    sections, playbook_output = _posture(hostname, window, outcome)
    for part_title, part_content in _pack("Tehtris Posture: {}".format(hostname), sections):
        phantom.add_note(
            container=container,
            note_type="general",
            title=part_title,
            content=part_content,
            note_format="markdown",  # the content is markdown; add_note() defaults to html
        )

    phantom.save_run_data(key="playbook_output", value=json.dumps(playbook_output))
    phantom.debug("Tehtris posture note written: status={}".format(playbook_output["status"]))

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="note_posture__inputs:0:check_inputs:custom_function:hostname", value=json.dumps(check_inputs__hostname))
    phantom.save_block_result(key="note_posture__inputs:1:get_recent_events:action_result.status", value=json.dumps(get_recent_events_result_item_0))

    phantom.save_block_result(key="note_posture_called", value="True")

    return


@phantom.playbook_block()
def note_no_host(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("note_no_host() called")

    ################################################################################
    # Note why no posture was read: the host is unknown to Tehtris, or the lookup 
    # failed.
    ################################################################################

    check_inputs__hostname = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:hostname")) != "" else "null")  # pylint: disable=used-before-assignment
    check_host__host_state = json.loads(_ if (_ := phantom.get_run_data(key="check_host:host_state")) != "" else "null")  # pylint: disable=used-before-assignment

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################

    hostname = json.loads(phantom.get_run_data(key="check_inputs:hostname") or '""')
    state = json.loads(phantom.get_run_data(key="check_host:host_state") or '"failed"')
    message = " ".join((json.loads(phantom.get_run_data(key="check_host:message") or '""') or "").split())

    if state == "not_found":
        headline = "Tehtris EDR has no endpoint named {}.".format(_code(hostname))
        status = "not_found"
    else:
        headline = "The Tehtris EDR inventory lookup for {} failed, so no posture was read.".format(_code(hostname))
        status = "error"
    content = "# Tehtris posture: {}\n\n{}\n\n**Tehtris said:** {}".format(
        _code(hostname), headline, _code(message, limit=1000))

    phantom.add_note(
        container=container,
        note_type="general",
        title="Tehtris Posture: {}".format(hostname),
        content=content,
        note_format="markdown",  # the content is markdown; add_note() defaults to html
    )
    phantom.save_run_data(key="playbook_output", value=json.dumps({
        "status": status, "host_found": False, "summary": "{} {}".format(headline.replace("`", ""), message)[:_SUMMARY_MAX_CHARS]}))

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="note_no_host__inputs:0:check_inputs:custom_function:hostname", value=json.dumps(check_inputs__hostname))
    phantom.save_block_result(key="note_no_host__inputs:1:check_host:custom_function:host_state", value=json.dumps(check_host__host_state))

    phantom.save_block_result(key="note_no_host_called", value="True")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    output = {
        "status": [],
        "host_found": [],
        "os": [],
        "agent_last_seen": [],
        "isolation_state": [],
        "process_count": [],
        "connection_count": [],
        "software_count": [],
        "event_count": [],
        "summary": [],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################

    # Populate the generated `output` dict; the save after Custom Code End emits it.
    # No block recorded an outcome (the run stopped early): report error.
    raw_output = phantom.get_run_data(key="playbook_output")
    if raw_output:
        output.update(json.loads(raw_output))
    # The 8.6 VPE initialises every output above to [] (8.5 wrote None), so an
    # output no block set is normalised to null here, whichever form a save wrote.
    for key, value in output.items():
        if value == []:
            output[key] = None
    if output["status"] is None:
        output["status"] = "error"

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return
