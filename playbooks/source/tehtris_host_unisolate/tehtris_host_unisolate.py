"""
Releases a host from Tehtris EDR isolation after an analyst approves it in a prompt, verifies the release, swaps the host tag to soar-released and writes a Tehtris Release note.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


################################################################################
## Global Custom Code Start
################################################################################
################################################################################

# PB2 tehtris_host_isolate in the other direction. The release prompt is
# raised from a code block so the approver can fall back from the container
# owner to soar_local_admin.
# Nothing is sent when the pre-check cannot read the isolation state (agent
# offline, unknown host, no state): no persist, so nothing runs unseen later.
# The Tehtris tags are ONE string, at most 64 characters, "<trigram>_...", that
# update tag replaces whole: the marker is added by read, append, write back,
# in one slot (soar-isolated / soar-released).

import re

_MARKER = "soar-released"
_OTHER_MARKER = "soar-isolated"
_SETTINGS_LIST = "tehtris_edr_settings"
_DEFAULT_TAG_SEPARATOR = ","
_TAGS_MAX_CHARS = 64
_PROMPT_MINUTES = 30
_RELEASE = "Release host"
_DO_NOT_RELEASE = "Do not release"
_CELL_MAX_CHARS = 300


def _code(value, limit=_CELL_MAX_CHARS):
    """A value from Tehtris or an input as an inline code span: one line, no
    backticks, cut at limit, so markup and links in it stay inert."""
    if value is None or value == "":
        return "—"
    text = " ".join(str(value).split()).replace("`", "'")
    if len(text) > limit:
        text = text[:limit - 1] + "…"
    return "`{}`".format(text)


def _settings(rows):
    """{key: value} from the tehtris_edr_settings custom list rows."""
    settings = {}
    for row in rows or []:
        if row and row[0] not in (None, "") and len(row) > 1:
            settings[str(row[0]).strip()] = str(row[1] if row[1] is not None else "").strip()
    return settings


def _build_tag(current, add, remove, trigram, separator):
    """(action, new_tags, reason) to put `add` in the endpoint's tag string and
    take `remove` out. action is "write", "already" or "skip"; a skip never
    writes, so the endpoint's existing tags are never cut or reshaped."""
    current = (current or "").strip()
    separator = separator or _DEFAULT_TAG_SEPARATOR
    if current:
        match = re.match(r"^([A-Za-z0-9]{3}_)(.*)$", current, re.S)
        if not match:
            return "skip", None, "the endpoint's tags {} do not start with a trigram and '_'".format(_code(current))
        prefix, body = match.groups()
        items = [item for item in body.split(separator) if item != ""]
    else:
        trigram = (trigram or "").strip()
        if not re.match(r"^[A-Za-z0-9]{3}$", trigram):
            return "skip", None, ("the endpoint has no tags yet and custom list {} has no valid tag_trigram"
                                  .format(_SETTINGS_LIST))
        prefix, items = trigram + "_", []
    if add in items and remove not in items:
        return "already", current, "the endpoint's tags already carry {}".format(_code(add))
    items = [item for item in items if item != remove]
    if add not in items:
        items.append(add)
    new = prefix + separator.join(items)
    if len(new) > _TAGS_MAX_CHARS:
        return "skip", None, ("adding {} would make the tags {} characters long; Tehtris allows {}"
                              .format(_code(add), len(new), _TAGS_MAX_CHARS))
    if "%" in new or "*" in new:
        return "skip", None, "the tags would contain '%' or '*', which Tehtris refuses"
    return "write", new, ""


def _first(rows, index=0):
    """Value `index` of the first collect2 row, or None."""
    if rows and len(rows[0]) > index:
        return rows[0][index]
    return None
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
    # Check the hostname input; read the optional reason.
    ################################################################################

    playbook_input_hostname = phantom.collect2(container=container, datapath=["playbook_input:hostname"])
    playbook_input_reason = phantom.collect2(container=container, datapath=["playbook_input:reason"])

    playbook_input_hostname_values = [item[0] for item in playbook_input_hostname]
    playbook_input_reason_values = [item[0] for item in playbook_input_reason]

    check_inputs__hostname = None
    check_inputs__reason = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################

    # Read again here so this block does not depend on the generated variable names.
    values = {}
    for name in ("hostname", "reason"):
        rows = phantom.collect2(container=container, datapath=["playbook_input:" + name])
        values[name] = str(_first(rows) or "").strip()

    if not values["hostname"]:
        problem = "No hostname was given. Run the playbook again with the endpoint's hostname as Tehtris shows it."
        phantom.error(problem)
        phantom.add_note(
            container=container,
            note_type="general",
            title="Tehtris Release - Error",
            content=problem,
            note_format="markdown",  # the content is markdown; add_note() defaults to html
        )
        phantom.save_run_data(key="playbook_output", value=json.dumps({
            "status": "error", "release_requested": False, "release_verified": False, "message": problem}))
        return

    check_inputs__hostname = values["hostname"]
    check_inputs__reason = values["reason"]

    # Also saved as run data: later blocks read these keys in their own Custom Code.
    for name, value in values.items():
        phantom.save_run_data(key="check_inputs:" + name, value=json.dumps(value))

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="check_inputs__inputs:0:playbook_input:hostname", value=json.dumps(playbook_input_hostname_values))
    phantom.save_block_result(key="check_inputs__inputs:1:playbook_input:reason", value=json.dumps(playbook_input_reason_values))

    phantom.save_block_result(key="check_inputs:hostname", value=json.dumps(check_inputs__hostname))
    phantom.save_block_result(key="check_inputs:reason", value=json.dumps(check_inputs__reason))

    phantom.save_block_result(key="check_inputs_called", value="True")

    pre_check_isolation(container=container)

    return


@phantom.playbook_block()
def pre_check_isolation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pre_check_isolation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Read the current isolation state (live: needs the agent connected).
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

    phantom.act("get isolation status", parameters=parameters, name="pre_check_isolation", assets=["tehtris_mock"], callback=route_pre_check)

    return


@phantom.playbook_block()
def route_pre_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("route_pre_check() called")

    ################################################################################
    # Stop if the state is unreadable or not isolated; else ask the analyst.
    ################################################################################

    pre_check_isolation_result_data = phantom.collect2(container=container, datapath=["pre_check_isolation:action_result.status","pre_check_isolation:action_result.message","pre_check_isolation:action_result.summary.isolated"], action_results=results)
    check_inputs__hostname = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:hostname")) != "" else "null")  # pylint: disable=used-before-assignment

    pre_check_isolation_result_item_0 = [item[0] for item in pre_check_isolation_result_data]
    pre_check_isolation_result_message = [item[1] for item in pre_check_isolation_result_data]
    pre_check_isolation_summary_isolated = [item[2] for item in pre_check_isolation_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################

    hostname = json.loads(phantom.get_run_data(key="check_inputs:hostname") or '""')
    reason = json.loads(phantom.get_run_data(key="check_inputs:reason") or '""')
    rows = phantom.collect2(container=container, datapath=[
        "pre_check_isolation:action_result.status",
        "pre_check_isolation:action_result.message",
        "pre_check_isolation:action_result.summary.isolated",
    ])
    status, message, isolated = _first(rows, 0), _first(rows, 1), _first(rows, 2)

    stop = None
    if status != "success":
        stop = ("not_sent", "Nothing was sent to Tehtris: the isolation state of {} could not be read, so the "
                            "playbook did not ask for approval. **Tehtris said:** {}".format(_code(hostname), _code(message)))
    elif isolated is False:
        stop = ("not_isolated", "{} is not isolated in Tehtris EDR; nothing was sent.".format(_code(hostname)))
    elif isolated is not True:
        stop = ("not_sent", "Nothing was sent to Tehtris: its reply did not say whether {} is isolated."
                            .format(_code(hostname)))
    if stop:
        outcome, text = stop
        phantom.add_note(
            container=container,
            note_type="general",
            title="Tehtris Release: {}".format(hostname),
            content="# Tehtris release: {}\n\n{}".format(_code(hostname), text),
            note_format="markdown",  # the content is markdown; add_note() defaults to html
        )
        phantom.save_run_data(key="playbook_output", value=json.dumps({
            "status": outcome, "release_requested": False, "release_verified": isolated is False,
            "tag_applied": "not attempted", "message": re.sub(r"[`*]", "", text)}))
        return

    # The prompt is raised from code, not from a native prompt block: a VPE save
    # regenerates prompt blocks whole (they have no Custom Code), which would drop
    # this approver fallback. The callback continues the flow; the return below
    # stops the generated call to release_decision from also running right away.
    user = container.get("owner_name", None) or "soar_local_admin"
    lines = [
        "**Release {} from Tehtris EDR network isolation?**".format(_code(hostname)),
        "",
        "Container: {}".format(_code(container.get("name"))),
        "Reason given: {}".format(_code(reason) if reason else "none"),
        "",
        "The endpoint gets its normal network access back. Isolate it again with tehtris_host_isolate.",
    ]
    response_types = [
        {
            "prompt": "Decision",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    _RELEASE,
                    _DO_NOT_RELEASE,
                ],
            },
        },
    ]
    phantom.save_run_data(key="route_pre_check:approver", value=json.dumps(user))
    phantom.prompt2(container=container, user=user, role=None, message="\n".join(lines), respond_in_mins=_PROMPT_MINUTES, name="release_approval", parameters=[], response_types=response_types, callback=release_decision)

    return

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="route_pre_check__inputs:0:pre_check_isolation:action_result.status", value=json.dumps(pre_check_isolation_result_item_0))
    phantom.save_block_result(key="route_pre_check__inputs:1:pre_check_isolation:action_result.message", value=json.dumps(pre_check_isolation_result_message))
    phantom.save_block_result(key="route_pre_check__inputs:2:pre_check_isolation:action_result.summary.isolated", value=json.dumps(pre_check_isolation_summary_isolated))
    phantom.save_block_result(key="route_pre_check__inputs:3:check_inputs:custom_function:hostname", value=json.dumps(check_inputs__hostname))

    phantom.save_block_result(key="route_pre_check_called", value="True")

    release_decision(container=container)

    return


@phantom.playbook_block()
def release_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("release_decision() called")

    ################################################################################
    # Read the analyst's answer; anything but Release host stops with a note.
    ################################################################################

    release_decision__analyst_response = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################

    hostname = json.loads(phantom.get_run_data(key="check_inputs:hostname") or '""')
    approver = json.loads(phantom.get_run_data(key="route_pre_check:approver") or '""')
    run_id = phantom.get_playbook_run_id_()

    answer, prompt_status = None, "expired"
    try:
        approval_url = phantom.build_phantom_rest_url("approval") + \
            "?_filter_playbook_run={}&_filter_name=\"release_approval\"&sort=id&order=desc&page_size=1".format(run_id)
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

    release_decision__analyst_response = answer or prompt_status
    phantom.save_run_data(key="release_decision:analyst_response", value=json.dumps(release_decision__analyst_response))

    if answer != _RELEASE:
        if answer == _DO_NOT_RELEASE:
            outcome, text = "declined", "{} declined the release of {}; nothing was sent to Tehtris.".format(
                _code(approver), _code(hostname))
        else:
            outcome, text = "expired", ("The release prompt for {} got no answer from {} within {} minutes "
                                        "(status {}); nothing was sent to Tehtris.").format(
                _code(hostname), _code(approver), _PROMPT_MINUTES, _code(prompt_status))
        phantom.add_note(
            container=container,
            note_type="general",
            title="Tehtris Release: {}".format(hostname),
            content="# Tehtris release: {}\n\n{}".format(_code(hostname), text),
            note_format="markdown",  # the content is markdown; add_note() defaults to html
        )
        phantom.save_run_data(key="playbook_output", value=json.dumps({
            "status": outcome, "release_requested": False, "release_verified": False,
            "tag_applied": "not attempted", "analyst_response": release_decision__analyst_response,
            "message": text.replace("`", "")}))
        return

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="release_decision:analyst_response", value=json.dumps(release_decision__analyst_response))

    phantom.save_block_result(key="release_decision_called", value="True")

    remove_from_isolation(container=container)

    return


@phantom.playbook_block()
def remove_from_isolation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("remove_from_isolation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Ask Tehtris to release the endpoint (refused for a shared hostname).
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

    phantom.act("remove from isolation", parameters=parameters, name="remove_from_isolation", assets=["tehtris_mock"], callback=verify_isolation)

    return


@phantom.playbook_block()
def verify_isolation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("verify_isolation() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Read the isolation state again to confirm the release took effect.
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

    phantom.act("get isolation status", parameters=parameters, name="verify_isolation", assets=["tehtris_mock"], callback=read_host_tags)

    return


@phantom.playbook_block()
def read_host_tags(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("read_host_tags() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Read the endpoint's current tag string, to append the marker to it.
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

    phantom.act("get host detail", parameters=parameters, name="read_host_tags", assets=["tehtris_mock"], callback=build_tag)

    return


@phantom.playbook_block()
def build_tag(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("build_tag() called")

    ################################################################################
    # New tag string: current tags plus soar-released, minus soar-isolated.
    ################################################################################

    verify_isolation_result_data = phantom.collect2(container=container, datapath=["verify_isolation:action_result.summary.isolated"], action_results=results)
    read_host_tags_result_data = phantom.collect2(container=container, datapath=["read_host_tags:action_result.status","read_host_tags:action_result.data.*.tags"], action_results=results)

    verify_isolation_summary_isolated = [item[0] for item in verify_isolation_result_data]
    read_host_tags_result_item_0 = [item[0] for item in read_host_tags_result_data]
    read_host_tags_result_item_1 = [item[1] for item in read_host_tags_result_data]

    build_tag__tag = None
    build_tag__tag_action = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################

    verified = _first(phantom.collect2(container=container, datapath=["verify_isolation:action_result.summary.isolated"]))
    tag_rows = phantom.collect2(container=container, datapath=["read_host_tags:action_result.status", "read_host_tags:action_result.data.*.tags"])
    read_status, current = _first(tag_rows, 0), _first(tag_rows, 1)

    if verified is not False:
        tag_action, new_tags, why = "skip", None, "the release is not confirmed yet, so the tags were left unchanged"
    elif read_status != "success":
        tag_action, new_tags, why = "skip", None, "the endpoint's current tags could not be read"
    else:
        list_ok, _message, list_rows = phantom.get_list(list_name=_SETTINGS_LIST)
        settings = _settings(list_rows if list_ok else [])
        tag_action, new_tags, why = _build_tag(current, _MARKER, _OTHER_MARKER,
                                               settings.get("tag_trigram"), settings.get("tag_separator"))

    build_tag__tag = new_tags
    build_tag__tag_action = tag_action
    phantom.save_run_data(key="build_tag:tag", value=json.dumps(new_tags))
    phantom.save_run_data(key="build_tag:tag_action", value=json.dumps(tag_action))
    phantom.save_run_data(key="build_tag:reason", value=json.dumps(why))
    phantom.save_run_data(key="build_tag:tags_before", value=json.dumps(current))

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="build_tag__inputs:0:verify_isolation:action_result.summary.isolated", value=json.dumps(verify_isolation_summary_isolated))
    phantom.save_block_result(key="build_tag__inputs:1:read_host_tags:action_result.status", value=json.dumps(read_host_tags_result_item_0))
    phantom.save_block_result(key="build_tag__inputs:2:read_host_tags:action_result.data.*.tags", value=json.dumps(read_host_tags_result_item_1))

    phantom.save_block_result(key="build_tag:tag", value=json.dumps(build_tag__tag))
    phantom.save_block_result(key="build_tag:tag_action", value=json.dumps(build_tag__tag_action))

    phantom.save_block_result(key="build_tag_called", value="True")

    tag_released(container=container)

    return


@phantom.playbook_block()
def tag_released(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("tag_released() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Write the new tag string back, unless build_tag found nothing to write.
    ################################################################################

    build_tag__tag = json.loads(_ if (_ := phantom.get_run_data(key="build_tag:tag")) != "" else "null")  # pylint: disable=used-before-assignment
    check_inputs__hostname = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:hostname")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if build_tag__tag is not None and check_inputs__hostname is not None:
        parameters.append({
            "tag": build_tag__tag,
            "hostname": check_inputs__hostname,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################

    # Only a "write" decision reaches Tehtris; otherwise go straight to the note,
    # and the return below skips the generated update tag call.
    if json.loads(phantom.get_run_data(key="build_tag:tag_action") or '"skip"') != "write":
        note_result(container=container)
        return

    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update tag", parameters=parameters, name="tag_released", assets=["tehtris_mock"], callback=note_result)

    return


@phantom.playbook_block()
def note_result(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("note_result() called")

    ################################################################################
    # Write the Tehtris Release note: request, verification and tag outcome.
    ################################################################################

    remove_from_isolation_result_data = phantom.collect2(container=container, datapath=["remove_from_isolation:action_result.status","remove_from_isolation:action_result.message"], action_results=results)
    release_decision__analyst_response = json.loads(_ if (_ := phantom.get_run_data(key="release_decision:analyst_response")) != "" else "null")  # pylint: disable=used-before-assignment

    remove_from_isolation_result_item_0 = [item[0] for item in remove_from_isolation_result_data]
    remove_from_isolation_result_message = [item[1] for item in remove_from_isolation_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################

    def run_value(key, default):
        raw = phantom.get_run_data(key=key)
        return json.loads(raw) if raw else default

    hostname = run_value("check_inputs:hostname", "")
    reason = run_value("check_inputs:reason", "")
    approver = run_value("route_pre_check:approver", "")
    answer = run_value("release_decision:analyst_response", None)

    send = phantom.collect2(container=container, datapath=["remove_from_isolation:action_result.status",
                                                           "remove_from_isolation:action_result.message",
                                                           "remove_from_isolation:action_result.summary.applied"])
    send_status, send_message, applied = _first(send, 0), _first(send, 1), _first(send, 2)
    verify = phantom.collect2(container=container, datapath=["verify_isolation:action_result.status",
                                                             "verify_isolation:action_result.message",
                                                             "verify_isolation:action_result.summary.isolated"])
    verify_status, verify_message, verified = _first(verify, 0), _first(verify, 1), _first(verify, 2)

    tag_action = run_value("build_tag:tag_action", "skip")
    tag_reason = run_value("build_tag:reason", "")
    tags_before = run_value("build_tag:tags_before", None)
    new_tags = run_value("build_tag:tag", None)
    if tag_action == "write":
        tag = phantom.collect2(container=container, datapath=["tag_released:action_result.status",
                                                              "tag_released:action_result.message"])
        if _first(tag, 0) == "success":
            tag_applied, tag_text = "written", "{} → {}".format(_code(tags_before), _code(new_tags))
        else:
            tag_applied = "failed"
            tag_text = "writing {} failed: {}".format(_code(new_tags), _code(_first(tag, 1) or "no result"))
    elif tag_action == "already":
        tag_applied, tag_text = "already", tag_reason
    elif send_status != "success":
        tag_applied, tag_text = "skipped", "not written: the release request failed"
    else:
        tag_applied, tag_text = "skipped", "not written: " + tag_reason

    if send_status != "success":
        status = "failed"
        headline = "Tehtris refused or failed the release of {}.".format(_code(hostname))
    elif applied is False:
        status = "queued"
        headline = "Tehtris queued the release of {}; it is not applied yet.".format(_code(hostname))
    elif verified is False:
        status = "released"
        headline = "{} is released from Tehtris EDR isolation (verified).".format(_code(hostname))
    else:
        status = "applied_not_confirmed"
        headline = ("Tehtris accepted the release of {}, but the read-back does not confirm it yet — "
                    "check again in a minute.".format(_code(hostname)))

    lines = [
        "# Tehtris release: {}".format(_code(hostname)),
        "",
        headline,
        "",
        "- **Approved by:** {} ({})".format(_code(approver), _code(answer)),
        "- **Reason:** {}".format(_code(reason) if reason else "none given"),
        # A refusal for a shared hostname lists every endpoint's uuid: keep it whole.
        "- **Release request:** {} — {}".format(_code(send_status or "not run"), _code(send_message, 2000)),
        "- **Read-back:** {}".format(
            "isolated" if verified is True else "not isolated" if verified is False else
            "unknown — {}".format(_code(verify_message or verify_status or "not run"))),
        "- **Tehtris tags:** {}".format(tag_text),
    ]
    content = "\n".join(lines)
    phantom.add_note(
        container=container,
        note_type="general",
        title="Tehtris Release: {}".format(hostname),
        content=content,
        note_format="markdown",  # the content is markdown; add_note() defaults to html
    )
    phantom.save_run_data(key="playbook_output", value=json.dumps({
        "status": status,
        "release_requested": True,
        "release_verified": verified is False,
        "tag_applied": tag_applied,
        "analyst_response": answer,
        "message": re.sub(r"[`*]", "", headline),
    }))

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="note_result__inputs:0:remove_from_isolation:action_result.status", value=json.dumps(remove_from_isolation_result_item_0))
    phantom.save_block_result(key="note_result__inputs:1:remove_from_isolation:action_result.message", value=json.dumps(remove_from_isolation_result_message))
    phantom.save_block_result(key="note_result__inputs:2:release_decision:custom_function:analyst_response", value=json.dumps(release_decision__analyst_response))

    phantom.save_block_result(key="note_result_called", value="True")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    output = {
        "status": [],
        "release_requested": [],
        "release_verified": [],
        "tag_applied": [],
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
    # The 8.6 VPE initialises every output above to [], so an output no block
    # set is normalised to null here, whichever form a save wrote.
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

