"""
Data playbook (UC16 PB5) run by an analyst on any container. Quarantines one file on a host through Tehtris EDR after an analyst approves it in a prompt: reads the file&#39;s details, quarantines it, lists the host&#39;s quarantine, and records the outcome and the quarantine paths in a Tehtris Quarantine note.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


################################################################################
## Global Custom Code Start
################################################################################
################################################################################

# Design notes (kept here because a VPE save replaces the module docstring):
# UC16 PB5 -- see docs/usecases/uc16_tehtris_edr_implementation_plan.md
# (decision 9, proposal P4). Quarantine only: a restore is done from the
# Tehtris console with the quarantine path this playbook's note records
# ("restore file" takes the path IN quarantine, not the original path).
# Always an analyst prompt, raised from a code block so the approver can fall
# back from the container owner to soar_local_admin (UC2 PB4/PB5 precedent).
# Nothing is sent when the file details cannot be read -- agent offline (504),
# unknown host -- (decision 8): no persist, so nothing runs unseen later.

import re

_PROMPT_MINUTES = 30
_QUARANTINE = "Quarantine file"
_DO_NOT_QUARANTINE = "Do not quarantine"
_CELL_MAX_CHARS = 300
_NOTE_MAX_CHARS = 20000


def _code(value, limit=_CELL_MAX_CHARS):
    """A value from Tehtris or an input as an inline code span: one line, no
    backticks, cut at limit, so markup and links in it stay inert."""
    if value is None or value == "":
        return "—"
    text = " ".join(str(value).split()).replace("`", "'")
    if len(text) > limit:
        text = text[:limit - 1] + "…"
    return "`{}`".format(text)


def _first(rows, index=0):
    """Value `index` of the first collect2 row, or None."""
    if rows and len(rows[0]) > index:
        return rows[0][index]
    return None


def _file_record(data):
    """The FileInfoData dict from get file info's action-result data, without
    the connector's raw_json copy; {} when there is none."""
    for item in data or []:
        if isinstance(item, dict):
            return {k: v for k, v in item.items() if k != "raw_json"}
    return {}


def _signature_text(signatures):
    """'publisher (validity, type)' for each signature, or 'unsigned'."""
    parts = []
    for sig in signatures or []:
        if isinstance(sig, dict):
            parts.append("{} ({}, {})".format(sig.get("publisherName") or "unknown publisher",
                                              sig.get("validity") or "unknown", sig.get("type") or "unknown"))
    return "; ".join(parts) if parts else "unsigned"


def _run_value(key, default):
    raw = phantom.get_run_data(key=key)
    return json.loads(raw) if raw else default
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
    # Check the hostname and path inputs; read the optional reason and notification.
    ################################################################################

    playbook_input_hostname = phantom.collect2(container=container, datapath=["playbook_input:hostname"])
    playbook_input_path = phantom.collect2(container=container, datapath=["playbook_input:path"])
    playbook_input_reason = phantom.collect2(container=container, datapath=["playbook_input:reason"])
    playbook_input_notification = phantom.collect2(container=container, datapath=["playbook_input:notification"])

    playbook_input_hostname_values = [item[0] for item in playbook_input_hostname]
    playbook_input_path_values = [item[0] for item in playbook_input_path]
    playbook_input_reason_values = [item[0] for item in playbook_input_reason]
    playbook_input_notification_values = [item[0] for item in playbook_input_notification]

    check_inputs__hostname = None
    check_inputs__path = None
    check_inputs__reason = None
    check_inputs__notification = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################

    # Read again here so this block does not depend on the generated variable names.
    values = {}
    for name in ("hostname", "path", "reason", "notification"):
        rows = phantom.collect2(container=container, datapath=["playbook_input:" + name])
        values[name] = str(_first(rows) or "").strip()

    missing = [name for name in ("hostname", "path") if not values[name]]
    if missing:
        problem = ("No {} was given. Run the playbook again with the endpoint's hostname as Tehtris shows it "
                   "and the file's full path on that endpoint.".format(" and no ".join(missing)))
        phantom.error(problem)
        phantom.add_note(
            container=container,
            note_type="general",
            title="Tehtris Quarantine - Error",
            content=problem,
            note_format="markdown",  # the content is markdown; add_note() defaults to html
        )
        phantom.save_run_data(key="playbook_output", value=json.dumps({
            "status": "error", "file_found": False, "quarantined": False, "message": problem}))
        return

    check_inputs__hostname = values["hostname"]
    check_inputs__path = values["path"]
    check_inputs__reason = values["reason"]
    # Blank = no message to the Windows user; the connector then omits the field.
    check_inputs__notification = values["notification"] or None

    # Also saved as run data: later blocks read these keys in their own Custom Code.
    values["notification"] = check_inputs__notification
    for name, value in values.items():
        phantom.save_run_data(key="check_inputs:" + name, value=json.dumps(value))

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="check_inputs__inputs:0:playbook_input:hostname", value=json.dumps(playbook_input_hostname_values))
    phantom.save_block_result(key="check_inputs__inputs:1:playbook_input:path", value=json.dumps(playbook_input_path_values))
    phantom.save_block_result(key="check_inputs__inputs:2:playbook_input:reason", value=json.dumps(playbook_input_reason_values))
    phantom.save_block_result(key="check_inputs__inputs:3:playbook_input:notification", value=json.dumps(playbook_input_notification_values))

    phantom.save_block_result(key="check_inputs:hostname", value=json.dumps(check_inputs__hostname))
    phantom.save_block_result(key="check_inputs:path", value=json.dumps(check_inputs__path))
    phantom.save_block_result(key="check_inputs:reason", value=json.dumps(check_inputs__reason))
    phantom.save_block_result(key="check_inputs:notification", value=json.dumps(check_inputs__notification))

    phantom.save_block_result(key="check_inputs_called", value="True")

    get_file_info(container=container)

    return


@phantom.playbook_block()
def get_file_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_file_info() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Read the file's hashes, version and signatures (live: needs the agent connected).
    ################################################################################

    check_inputs__path = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:path")) != "" else "null")  # pylint: disable=used-before-assignment
    check_inputs__hostname = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:hostname")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if check_inputs__path is not None and check_inputs__hostname is not None:
        parameters.append({
            "path": check_inputs__path,
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

    phantom.act("get file info", parameters=parameters, name="get_file_info", assets=["tehtris_mock_8446"], callback=route_file_info)

    return


@phantom.playbook_block()
def route_file_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("route_file_info() called")

    ################################################################################
    # Stop if the file is unreadable or absent; else ask the analyst.
    ################################################################################

    get_file_info_result_data = phantom.collect2(container=container, datapath=["get_file_info:action_result.status","get_file_info:action_result.message","get_file_info:action_result.summary.file_found","get_file_info:action_result.data"], action_results=results)
    check_inputs__hostname = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:hostname")) != "" else "null")  # pylint: disable=used-before-assignment

    get_file_info_result_item_0 = [item[0] for item in get_file_info_result_data]
    get_file_info_result_message = [item[1] for item in get_file_info_result_data]
    get_file_info_summary_file_found = [item[2] for item in get_file_info_result_data]
    get_file_info_result_data_1 = [item[3] for item in get_file_info_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################

    hostname = _run_value("check_inputs:hostname", "")
    path = _run_value("check_inputs:path", "")
    reason = _run_value("check_inputs:reason", "")
    notification = _run_value("check_inputs:notification", None)
    rows = phantom.collect2(container=container, datapath=[
        "get_file_info:action_result.status",
        "get_file_info:action_result.message",
        "get_file_info:action_result.summary.file_found",
        "get_file_info:action_result.data",
    ])
    status, message, found, data = _first(rows, 0), _first(rows, 1), _first(rows, 2), _first(rows, 3)
    record = _file_record(data)
    phantom.save_run_data(key="route_file_info:file", value=json.dumps(record))

    stop = None
    if status != "success":
        stop = ("not_sent", "Nothing was sent to Tehtris: the details of {} on {} could not be read, so the "
                            "playbook did not ask for approval. **Tehtris said:** {}".format(
                                _code(path), _code(hostname), _code(message, 2000)))
    elif found is not True:
        stop = ("not_found", "Tehtris found no file {} on {}; nothing was sent. Check the full path "
                             "(Windows paths with a drive letter and backslashes).".format(_code(path), _code(hostname)))
    if stop:
        outcome, text = stop
        phantom.add_note(
            container=container,
            note_type="general",
            title="Tehtris Quarantine: {}".format(hostname),
            content="# Tehtris quarantine: {}\n\n{}".format(_code(hostname), text),
            note_format="markdown",  # the content is markdown; add_note() defaults to html
        )
        phantom.save_run_data(key="playbook_output", value=json.dumps({
            "status": outcome, "file_found": found is True, "quarantined": False,
            "message": re.sub(r"[`*]", "", text)}))
        return

    # The prompt is raised from code, not from a native prompt block: a VPE save
    # regenerates prompt blocks whole (they have no Custom Code), which would drop
    # this approver fallback. The callback continues the flow; the return below
    # stops the generated call to quarantine_decision from also running right away.
    user = container.get("owner_name", None) or "soar_local_admin"
    lines = [
        "**Quarantine this file on {} through Tehtris EDR?**".format(_code(hostname)),
        "",
        "Path: {}".format(_code(record.get("path") or path, 1000)),
        "SHA-256: {}".format(_code(record.get("sha256"))),
        "Original file name: {}".format(_code(record.get("originalFilename"))),
        "Product: {} {}".format(_code(record.get("productName")), _code(record.get("fileVersion"))),
        "Signatures: {}".format(_code(_signature_text(record.get("signatures")), 1000)),
        "",
        "Container: {}".format(_code(container.get("name"))),
        "Reason given: {}".format(_code(reason) if reason else "none"),
        "Message to the endpoint's user: {}".format(_code(notification) if notification else "none"),
        "",
        "Tehtris moves the file into its quarantine. A restore is done from the Tehtris console, with "
        "the quarantine path this playbook's note records.",
    ]
    response_types = [
        {
            "prompt": "Decision",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    _QUARANTINE,
                    _DO_NOT_QUARANTINE,
                ],
            },
        },
    ]
    phantom.save_run_data(key="route_file_info:approver", value=json.dumps(user))
    phantom.prompt2(container=container, user=user, role=None, message="\n".join(lines), respond_in_mins=_PROMPT_MINUTES, name="quarantine_approval", parameters=[], response_types=response_types, callback=quarantine_decision)

    return

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="route_file_info__inputs:0:get_file_info:action_result.status", value=json.dumps(get_file_info_result_item_0))
    phantom.save_block_result(key="route_file_info__inputs:1:get_file_info:action_result.message", value=json.dumps(get_file_info_result_message))
    phantom.save_block_result(key="route_file_info__inputs:2:get_file_info:action_result.summary.file_found", value=json.dumps(get_file_info_summary_file_found))
    phantom.save_block_result(key="route_file_info__inputs:3:get_file_info:action_result.data", value=json.dumps(get_file_info_result_data_1))
    phantom.save_block_result(key="route_file_info__inputs:4:check_inputs:custom_function:hostname", value=json.dumps(check_inputs__hostname))

    phantom.save_block_result(key="route_file_info_called", value="True")

    quarantine_decision(container=container)

    return


@phantom.playbook_block()
def quarantine_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("quarantine_decision() called")

    ################################################################################
    # Read the analyst's answer; anything but Quarantine file stops with a note.
    ################################################################################

    quarantine_decision__analyst_response = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################

    hostname = _run_value("check_inputs:hostname", "")
    path = _run_value("check_inputs:path", "")
    approver = _run_value("route_file_info:approver", "")
    run_id = phantom.get_playbook_run_id_()

    answer, prompt_status = None, "expired"
    try:
        approval_url = phantom.build_phantom_rest_url("approval") + \
            "?_filter_playbook_run={}&_filter_name=\"quarantine_approval\"&sort=id&order=desc&page_size=1".format(run_id)
        approvals = phantom.requests.get(uri=approval_url, verify=False).json().get("data") or []
    except Exception as e:
        phantom.error("Could not fetch the approval record for playbook_run {}: {}".format(run_id, str(e)))
        approvals = []
    if approvals:
        approval = approvals[0]
        responses = approval.get("responses") or []
        if approval.get("status") == "approved" and responses and responses[0]:
            answer, prompt_status = responses[0], "answered"
        else:
            prompt_status = approval.get("status") or "expired"
    else:
        phantom.error("No approval record found for playbook_run {}".format(run_id))

    quarantine_decision__analyst_response = answer or prompt_status
    phantom.save_run_data(key="quarantine_decision:analyst_response", value=json.dumps(quarantine_decision__analyst_response))

    if answer != _QUARANTINE:
        if answer == _DO_NOT_QUARANTINE:
            outcome, text = "declined", "{} declined the quarantine of {} on {}; nothing was sent to Tehtris.".format(
                _code(approver), _code(path), _code(hostname))
        else:
            outcome, text = "expired", ("The quarantine prompt for {} on {} got no answer from {} within {} minutes "
                                        "(status {}); nothing was sent to Tehtris.").format(
                _code(path), _code(hostname), _code(approver), _PROMPT_MINUTES, _code(prompt_status))
        record = _run_value("route_file_info:file", {})
        phantom.add_note(
            container=container,
            note_type="general",
            title="Tehtris Quarantine: {}".format(hostname),
            content="# Tehtris quarantine: {}\n\n{}".format(_code(hostname), text),
            note_format="markdown",  # the content is markdown; add_note() defaults to html
        )
        phantom.save_run_data(key="playbook_output", value=json.dumps({
            "status": outcome, "file_found": True, "sha256": record.get("sha256"), "quarantined": False,
            "analyst_response": quarantine_decision__analyst_response,
            "message": text.replace("`", "")}))
        return

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="quarantine_decision:analyst_response", value=json.dumps(quarantine_decision__analyst_response))

    phantom.save_block_result(key="quarantine_decision_called", value="True")

    quarantine_file(container=container)

    return


@phantom.playbook_block()
def quarantine_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("quarantine_file() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Ask Tehtris to quarantine the file (refused for a shared hostname).
    ################################################################################

    check_inputs__path = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:path")) != "" else "null")  # pylint: disable=used-before-assignment
    check_inputs__hostname = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:hostname")) != "" else "null")  # pylint: disable=used-before-assignment
    check_inputs__notification = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:notification")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if check_inputs__path is not None and check_inputs__hostname is not None:
        parameters.append({
            "path": check_inputs__path,
            "hostname": check_inputs__hostname,
            "notification": check_inputs__notification,
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

    phantom.act("quarantine file", parameters=parameters, name="quarantine_file", assets=["tehtris_mock_8446"], callback=list_quarantined)

    return


@phantom.playbook_block()
def list_quarantined(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("list_quarantined() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # List the host's quarantine, so the note can record the path to restore from.
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

    phantom.act("list quarantined files", parameters=parameters, name="list_quarantined", assets=["tehtris_mock_8446"], callback=note_result)

    return


@phantom.playbook_block()
def note_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("note_result() called")

    ################################################################################
    # Write the Tehtris Quarantine note: request outcome and the host's quarantine paths.
    ################################################################################

    quarantine_file_result_data = phantom.collect2(container=container, datapath=["quarantine_file:action_result.status","quarantine_file:action_result.message","quarantine_file:action_result.summary.applied"], action_results=results)
    list_quarantined_result_data = phantom.collect2(container=container, datapath=["list_quarantined:action_result.status","list_quarantined:action_result.message","list_quarantined:action_result.data.*.quarantinePath"], action_results=results)
    quarantine_decision__analyst_response = json.loads(_ if (_ := phantom.get_run_data(key="quarantine_decision:analyst_response")) != "" else "null")  # pylint: disable=used-before-assignment

    quarantine_file_result_item_0 = [item[0] for item in quarantine_file_result_data]
    quarantine_file_result_message = [item[1] for item in quarantine_file_result_data]
    quarantine_file_summary_applied = [item[2] for item in quarantine_file_result_data]
    list_quarantined_result_item_0 = [item[0] for item in list_quarantined_result_data]
    list_quarantined_result_message = [item[1] for item in list_quarantined_result_data]
    list_quarantined_result_item_2 = [item[2] for item in list_quarantined_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################

    hostname = _run_value("check_inputs:hostname", "")
    path = _run_value("check_inputs:path", "")
    reason = _run_value("check_inputs:reason", "")
    notification = _run_value("check_inputs:notification", None)
    approver = _run_value("route_file_info:approver", "")
    answer = _run_value("quarantine_decision:analyst_response", None)
    record = _run_value("route_file_info:file", {})

    send = phantom.collect2(container=container, datapath=["quarantine_file:action_result.status",
                                                           "quarantine_file:action_result.message",
                                                           "quarantine_file:action_result.summary.applied"])
    send_status, send_message, applied = _first(send, 0), _first(send, 1), _first(send, 2)
    listing = phantom.collect2(container=container, datapath=["list_quarantined:action_result.status",
                                                              "list_quarantined:action_result.message",
                                                              "list_quarantined:action_result.data.*.quarantinePath"])
    list_status, list_message = _first(listing, 0), _first(listing, 1)
    quarantine_paths = [row[2] for row in listing if len(row) > 2 and row[2]]

    if send_status != "success":
        status, quarantined = "failed", False
        headline = "Tehtris refused or failed the quarantine of {} on {}.".format(_code(path), _code(hostname))
    elif applied is False:
        status, quarantined = "queued", False
        headline = "Tehtris queued the quarantine of {} on {}; it is not applied yet.".format(_code(path), _code(hostname))
    else:
        status, quarantined = "quarantined", True
        headline = "{} on {} is quarantined by Tehtris EDR.".format(_code(path), _code(hostname))

    lines = [
        "# Tehtris quarantine: {}".format(_code(hostname)),
        "",
        headline,
        "",
        "- **Approved by:** {} ({})".format(_code(approver), _code(answer)),
        "- **Reason:** {}".format(_code(reason) if reason else "none given"),
        "- **File:** {}".format(_code(record.get("path") or path, 1000)),
        "- **SHA-256:** {}".format(_code(record.get("sha256"))),
        "- **Original file name:** {}".format(_code(record.get("originalFilename"))),
        "- **Signatures:** {}".format(_code(_signature_text(record.get("signatures")), 1000)),
        "- **Message to the endpoint's user:** {}".format(_code(notification) if notification else "none"),
        # A refusal for a shared hostname lists every endpoint's uuid: keep it whole.
        "- **Quarantine request:** {} — {}".format(_code(send_status or "not run"), _code(send_message, 2000)),
        "",
        "## Quarantine of {} after the request".format(_code(hostname)),
        "",
    ]
    if list_status != "success":
        lines.append("Could not be listed: {}".format(_code(list_message or list_status or "not run", 2000)))
    elif not quarantine_paths:
        lines.append("Empty.")
    else:
        # Tehtris lists quarantine paths only, so the file cannot be matched to one
        # of them for certain: every path is listed, for a restore from the console.
        lines.append("To restore a file, use its path below (not the original path) in the Tehtris console "
                     "or with the connector's restore file action.")
        lines.append("")
        budget = _NOTE_MAX_CHARS - len("\n".join(lines)) - 200
        shown = 0
        for quarantine_path in quarantine_paths:
            line = "- {}".format(_code(quarantine_path, 1000))
            if budget - len(line) - 1 < 0:
                break
            lines.append(line)
            budget -= len(line) + 1
            shown += 1
        if shown < len(quarantine_paths):
            lines.append("- … {} more are in the list_quarantined action result.".format(len(quarantine_paths) - shown))

    phantom.add_note(
        container=container,
        note_type="general",
        title="Tehtris Quarantine: {}".format(hostname),
        content="\n".join(lines),
        note_format="markdown",  # the content is markdown; add_note() defaults to html
    )
    phantom.save_run_data(key="playbook_output", value=json.dumps({
        "status": status,
        "file_found": True,
        "sha256": record.get("sha256"),
        "quarantined": quarantined,
        "quarantine_paths": quarantine_paths,
        "analyst_response": answer,
        "message": re.sub(r"[`*]", "", headline),
    }))

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="note_result__inputs:0:quarantine_file:action_result.status", value=json.dumps(quarantine_file_result_item_0))
    phantom.save_block_result(key="note_result__inputs:1:quarantine_file:action_result.message", value=json.dumps(quarantine_file_result_message))
    phantom.save_block_result(key="note_result__inputs:2:quarantine_file:action_result.summary.applied", value=json.dumps(quarantine_file_summary_applied))
    phantom.save_block_result(key="note_result__inputs:3:list_quarantined:action_result.status", value=json.dumps(list_quarantined_result_item_0))
    phantom.save_block_result(key="note_result__inputs:4:list_quarantined:action_result.message", value=json.dumps(list_quarantined_result_message))
    phantom.save_block_result(key="note_result__inputs:5:list_quarantined:action_result.data.*.quarantinePath", value=json.dumps(list_quarantined_result_item_2))
    phantom.save_block_result(key="note_result__inputs:6:quarantine_decision:custom_function:analyst_response", value=json.dumps(quarantine_decision__analyst_response))

    phantom.save_block_result(key="note_result_called", value="True")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    output = {
        "status": [],
        "file_found": [],
        "sha256": [],
        "quarantined": [],
        "quarantine_paths": [],
        "analyst_response": [],
        "message": [],
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
    # quarantine_paths is a real list when set, so only the other fields are touched.
    for key, value in output.items():
        if value == [] and key != "quarantine_paths":
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

