"""
Runs tehtris_host_posture, then tehtris_host_isolate with the posture summary in its approval prompt, and returns both outcomes.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


################################################################################
## Global Custom Code Start
################################################################################
################################################################################

# The children do every check, prompt and note themselves. Both playbook
# blocks are synchronous, so the isolation prompt comes after the posture note
# and carries its summary; an unknown host stops in the isolation pre-check.


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
    # Check the hostname input; read the optional reason and lookback.
    ################################################################################

    playbook_input_hostname = phantom.collect2(container=container, datapath=["playbook_input:hostname"])
    playbook_input_reason = phantom.collect2(container=container, datapath=["playbook_input:reason"])
    playbook_input_lookback_minutes = phantom.collect2(container=container, datapath=["playbook_input:lookback_minutes"])

    playbook_input_hostname_values = [item[0] for item in playbook_input_hostname]
    playbook_input_reason_values = [item[0] for item in playbook_input_reason]
    playbook_input_lookback_minutes_values = [item[0] for item in playbook_input_lookback_minutes]

    check_inputs__hostname = None
    check_inputs__reason = None
    check_inputs__lookback_minutes = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################

    # Read again here so this block does not depend on the generated variable names.
    values = {}
    for name in ("hostname", "reason", "lookback_minutes"):
        rows = phantom.collect2(container=container, datapath=["playbook_input:" + name])
        values[name] = str(_first(rows) or "").strip()

    if not values["hostname"]:
        problem = "No hostname was given. Run the playbook again with the endpoint's hostname as Tehtris shows it."
        phantom.error(problem)
        phantom.add_note(
            container=container,
            note_type="general",
            title="Tehtris Response - Error",
            content=problem,
            note_format="markdown",  # the content is markdown; add_note() defaults to html
        )
        phantom.save_run_data(key="playbook_output", value=json.dumps({"status": "error", "message": problem}))
        return

    check_inputs__hostname = values["hostname"]
    check_inputs__reason = values["reason"]
    # Blank = tehtris_host_posture's own default lookback.
    check_inputs__lookback_minutes = values["lookback_minutes"] or None

    phantom.save_run_data(key="check_inputs:hostname", value=json.dumps(check_inputs__hostname))
    phantom.save_run_data(key="check_inputs:reason", value=json.dumps(check_inputs__reason))
    phantom.save_run_data(key="check_inputs:lookback_minutes", value=json.dumps(check_inputs__lookback_minutes))

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="check_inputs__inputs:0:playbook_input:hostname", value=json.dumps(playbook_input_hostname_values))
    phantom.save_block_result(key="check_inputs__inputs:1:playbook_input:reason", value=json.dumps(playbook_input_reason_values))
    phantom.save_block_result(key="check_inputs__inputs:2:playbook_input:lookback_minutes", value=json.dumps(playbook_input_lookback_minutes_values))

    phantom.save_block_result(key="check_inputs:hostname", value=json.dumps(check_inputs__hostname))
    phantom.save_block_result(key="check_inputs:reason", value=json.dumps(check_inputs__reason))
    phantom.save_block_result(key="check_inputs:lookback_minutes", value=json.dumps(check_inputs__lookback_minutes))

    phantom.save_block_result(key="check_inputs_called", value="True")

    run_posture(container=container)

    return


@phantom.playbook_block()
def run_posture(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_posture() called")

    ################################################################################
    # Posture of the host: tehtris_host_posture writes its own note.
    ################################################################################

    check_inputs__hostname = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:hostname")) != "" else "null")  # pylint: disable=used-before-assignment
    check_inputs__lookback_minutes = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:lookback_minutes")) != "" else "null")  # pylint: disable=used-before-assignment

    inputs = {
        "hostname": check_inputs__hostname,
        "lookback_minutes": check_inputs__lookback_minutes,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/tehtris_host_posture", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/tehtris_host_posture", container=container, name="run_posture", callback=run_isolate, inputs=inputs)

    return


@phantom.playbook_block()
def run_isolate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_isolate() called")

    ################################################################################
    # tehtris_host_isolate behind its analyst prompt, with the posture summary.
    ################################################################################

    check_inputs__hostname = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:hostname")) != "" else "null")  # pylint: disable=used-before-assignment
    check_inputs__reason = json.loads(_ if (_ := phantom.get_run_data(key="check_inputs:reason")) != "" else "null")  # pylint: disable=used-before-assignment
    run_posture_output_summary = phantom.collect2(container=container, datapath=["run_posture:playbook_output:summary"])

    run_posture_output_summary_values = [item[0] for item in run_posture_output_summary]

    inputs = {
        "hostname": check_inputs__hostname,
        "reason": check_inputs__reason,
        "posture_summary": run_posture_output_summary_values,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/tehtris_host_isolate", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/tehtris_host_isolate", container=container, name="run_isolate", callback=report_outcome, inputs=inputs)

    return


@phantom.playbook_block()
def report_outcome(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("report_outcome() called")

    ################################################################################
    # Return both children's outcomes as this playbook's outputs.
    ################################################################################

    run_posture_output_status = phantom.collect2(container=container, datapath=["run_posture:playbook_output:status"])
    run_isolate_output_status = phantom.collect2(container=container, datapath=["run_isolate:playbook_output:status"])
    run_isolate_output_message = phantom.collect2(container=container, datapath=["run_isolate:playbook_output:message"])

    run_posture_output_status_values = [item[0] for item in run_posture_output_status]
    run_isolate_output_status_values = [item[0] for item in run_isolate_output_status]
    run_isolate_output_message_values = [item[0] for item in run_isolate_output_message]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    ################################################################################
    ################################################################################

    def child_output(block, field):
        return _first(phantom.collect2(container=container, datapath=["{}:playbook_output:{}".format(block, field)]))

    posture_status = child_output("run_posture", "status")
    isolation_status = child_output("run_isolate", "status")
    message = child_output("run_isolate", "message")
    phantom.save_run_data(key="playbook_output", value=json.dumps({
        # The isolation outcome is the response's outcome; the posture one is kept beside it.
        "status": isolation_status or "error",
        "posture_status": posture_status,
        "isolation_status": isolation_status,
        "message": message or "tehtris_host_isolate returned no outcome; see its playbook run.",
    }))

    ################################################################################
    ################################################################################
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="report_outcome__inputs:0:run_posture:playbook_output:status", value=json.dumps(run_posture_output_status_values))
    phantom.save_block_result(key="report_outcome__inputs:1:run_isolate:playbook_output:status", value=json.dumps(run_isolate_output_status_values))
    phantom.save_block_result(key="report_outcome__inputs:2:run_isolate:playbook_output:message", value=json.dumps(run_isolate_output_message_values))

    phantom.save_block_result(key="report_outcome_called", value="True")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    output = {
        "status": [],
        "posture_status": [],
        "isolation_status": [],
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

