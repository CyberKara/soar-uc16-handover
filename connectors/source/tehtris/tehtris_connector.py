# Copyright (c) 2025-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#!/usr/bin/python
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports

import json
import time

# Phantom App imports
import phantom.app as phantom

# Usage of the consts file is recommended
# from tehtris_consts import *
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

from tehtris_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class TehtrisConnector(BaseConnector):
    def __init__(self):
        # Call the BaseConnectors init first
        super().__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._api_key = None
        self._last_status_code = None

    def _process_empty_response(self, response, action_result, status_hints=None):
        # 204 is Tehtris' success reply for writes and for "no content"; 202 means
        # the task was queued for an EDR agent that is not connected.
        if response.status_code in (200, 202, 204):
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR,
                "Empty response. Status Code: {}{}".format(response.status_code, self._status_hint(response.status_code, status_hints)),
            ),
            None,
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = f"Status Code: {status_code}. Data from server:\n{error_text}\n"

        message = message.replace("{", "{{").replace("}", "}}")
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result, status_hints=None):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Unable to parse JSON response. Error: {e!s}",
                ),
                None,
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {}{} Data from server: {}".format(
            r.status_code, self._status_hint(r.status_code, status_hints), r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    @staticmethod
    def _status_hint(status_code, status_hints):
        hint = (status_hints or {}).get(status_code)
        return f" ({hint})." if hint else "."

    def _process_response(self, r, action_result, status_hints=None):
        self._last_status_code = r.status_code

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, "add_debug_data"):
            action_result.add_debug_data({"r_status_code": r.status_code})
            action_result.add_debug_data({"r_text": r.text})
            action_result.add_debug_data({"r_headers": r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result, status_hints)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result, status_hints)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {}{} Data from server: {}".format(
            r.status_code, self._status_hint(r.status_code, status_hints), r.text.replace("{", "{{").replace("}", "}}")
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", status_hints=None, **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, f"Invalid method: {method}"),
                resp_json,
            )

        # Create a URL to connect to
        url = self._base_url + endpoint
        username = "api"
        password = self._api_key

        kwargs.setdefault("timeout", TEHTRIS_DEFAULT_TIMEOUT)
        try:
            r = request_func(
                url,
                auth=(username, password),  # basic authentication
                verify=config.get("verify_server_cert", True),
                **kwargs,
            )
        except requests.exceptions.Timeout:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Tehtris did not answer within {kwargs['timeout']} seconds ({endpoint})",
                ),
                resp_json,
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Error Connecting to server. Details: {e!s}",
                ),
                resp_json,
            )

        return self._process_response(r, action_result, status_hints)

    def _lookup_inventory(self, hostname, action_result, missing_ok=False):
        """Return the inventory entries whose hostname is exactly ``hostname``.

        The inventory's ``hostname`` filter matches substrings, so a query for
        ``ws-01`` also returns ``ws-010`` and ``ws-01-old``, in no guaranteed
        order. Only a case-insensitive exact match on the entry's ``hostname``
        counts. Several exact matches are possible (a re-installed agent keeps
        its hostname under a new uuid); they come back newest ``lastSeen`` first.

        No exact match is an error, unless ``missing_ok``: then the action
        result is set to success with the not-found message and the list is
        empty, so a caller can tell "no such host" from "the call failed".
        """
        if not hostname:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Parameter 'hostname' is required"), None)

        self.save_progress(f"Resolving hostname {hostname} in the EDR inventory")

        ret_val, response = self._make_rest_call(
            TEHTRIS_GET_INVENTORY_ENDPOINT,
            action_result,
            params={"hostname": hostname},
            headers=None,
            method="get",
        )
        if phantom.is_fail(ret_val):
            return RetVal(action_result.get_status(), None)

        entries = [e for e in ((response or {}).get("data") or []) if isinstance(e, dict)]
        wanted = hostname.strip().lower()
        exact = [e for e in entries if str(e.get("hostname") or "").strip().lower() == wanted]
        if not exact:
            if entries:
                others = ", ".join(sorted(str(e.get("hostname")) for e in entries)[:10])
                missing = TEHTRIS_ERR_HOST_NOT_EXACT.format(hostname, len(entries), hostname, others)
            else:
                missing = TEHTRIS_ERR_HOST_NOT_FOUND.format(hostname)
            if not missing_ok:
                return RetVal(action_result.set_status(phantom.APP_ERROR, missing), None)
            self.save_progress(missing)
            return RetVal(action_result.set_status(phantom.APP_SUCCESS, missing), [])

        exact.sort(key=lambda e: str(e.get("lastSeen") or ""), reverse=True)
        return RetVal(phantom.APP_SUCCESS, exact)

    def _resolve_host(self, hostname, action_result, write=False):
        """Resolve a hostname to its Tehtris ``(applianceId, edrUuid)`` pair.

        Every host-scoped action needs this lookup, so it lives in one place.
        The upstream app indexed ``response["data"][0]`` of a substring search:
        an unknown hostname raised ``IndexError``, and a hostname that is a
        prefix of another could resolve to the other host. With several exact
        matches, a read uses the most recently seen endpoint and a write
        (``write=True``) is refused, so an isolation never picks between
        endpoints on its own.
        """
        ret_val, exact = self._lookup_inventory(hostname, action_result)
        if phantom.is_fail(ret_val):
            return RetVal(action_result.get_status(), None)

        if len(exact) > 1:
            listing = "; ".join(f"uuid {e.get('uuid')} (appliance {e.get('applianceId')}, last seen {e.get('lastSeen')})" for e in exact)
            if write:
                return RetVal(
                    action_result.set_status(phantom.APP_ERROR, TEHTRIS_ERR_HOST_AMBIGUOUS.format(hostname, len(exact), listing)),
                    None,
                )
            self.save_progress(f"{len(exact)} endpoints are named {hostname}; using the most recently seen: {listing}")

        entry = exact[0]
        uuid = entry.get("uuid")
        appliance_id = entry.get("applianceId")
        if not uuid or appliance_id is None:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, TEHTRIS_ERR_INVENTORY_SHAPE.format(hostname)),
                None,
            )

        self.save_progress(f"Resolved {hostname} to appliance {appliance_id}")
        return RetVal(phantom.APP_SUCCESS, (appliance_id, uuid))

    def _as_data(self, record):
        """Wrap a payload for ``add_data()``, adding a ``raw_json`` copy.

        The vendor API reference leaves several responses loosely typed: the
        events endpoint declares no schema, live-response rows are untyped, and
        the inventory's ``os``/``versions`` are free-form objects. So each action
        forwards the payload verbatim and also exposes it as a ``raw_json``
        string; a field the manifest does not declare is still reachable there.
        """
        if isinstance(record, dict):
            data = dict(record)
        elif isinstance(record, list):
            data = {"items": record, "item_count": len(record)}
        else:
            data = {"value": record}
        data["raw_json"] = json.dumps(record, default=str)
        return data

    def _add_records(self, action_result, response):
        """Add a response to the action result, unwrapping a list if present.

        An empty body (HTTP 204, "no content" or "cursor reached its end") adds
        nothing and counts as zero records.
        """
        if response in (None, {}, []):
            return 0

        records = response
        if isinstance(response, dict):
            for key in ("data", "list", "items", "results"):
                if isinstance(response.get(key), list):
                    records = response.get(key)
                    break

        if isinstance(records, list):
            for record in records:
                action_result.add_data(self._as_data(record))
            return len(records)

        action_result.add_data(self._as_data(response))
        return 1

    @staticmethod
    def _live_rows(response):
        """Turn a live-response ``{columns, data}`` payload into dict rows.

        ``columns`` names each field; ``data`` rows are untyped in the vendor
        API reference, so a list row is zipped with the column names and a dict
        row is kept as it is.
        """
        if not isinstance(response, dict):
            return []
        names = [c.get("name") for c in (response.get("columns") or []) if isinstance(c, dict)]
        rows = []
        for row in response.get("data") or []:
            if isinstance(row, dict):
                rows.append(row)
            elif isinstance(row, (list, tuple)) and names:
                rows.append(dict(zip(names, row, strict=False)))
            else:
                rows.append({"value": row})
        return rows

    def _extract_isolation_state(self, response):
        """Read the boolean isolation state.

        The vendor API reference defines the reply as ``IsolationStatus``,
        ``{"status": <boolean>}`` with ``status`` required; the other keys are
        a fallback only. Returns None when the state cannot be determined (for
        example a 204 "no content" reply) -- callers must treat that as
        "unknown", never as "not isolated".
        """
        if isinstance(response, bool):
            return response
        if isinstance(response, dict):
            for key in ("status", "isolated", "isolation", "state"):
                if key in response:
                    value = response.get(key)
                    if isinstance(value, bool):
                        return value
                    if isinstance(value, str):
                        return value.strip().lower() in ("true", "enabled", "enable", "isolated", "on")
        return None

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")

        t = time.time()

        params = {"fromDate": t}
        # make rest call
        ret_val, _response = self._make_rest_call(TEHTRIS_GET_EVENTS_ENDPOINT, action_result, params=params, headers=None)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_get_events(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        from_date = param.get("from_date")
        to_date = param.get("to_date")
        # Paging stops on the first page shorter than limit, so limit 0 would never stop.
        try:
            limit = int(param.get("limit", 100))
        except (TypeError, ValueError):
            limit = 0
        if not 1 <= limit <= TEHTRIS_EVENTS_MAX_LIMIT:
            return action_result.set_status(
                phantom.APP_ERROR, f"Parameter 'limit' must be an integer from 1 to {TEHTRIS_EVENTS_MAX_LIMIT} (the Tehtris maximum page size)"
            )
        offset = param.get("offset") or 0
        filter_id = param.get("filter_id")
        hostname = param.get("hostname")
        wanted_host = (hostname or "").strip().lower()

        params = {
            "fromDate": from_date,
            "toDate": to_date,
            "limit": limit,
            "offset": offset,
            "filterID": filter_id,
        }
        # make rest call
        fetched_all_events = False
        while not fetched_all_events:
            ret_val, response = self._make_rest_call(
                TEHTRIS_GET_EVENTS_ENDPOINT,
                action_result,
                params=params,
                headers=None,
                method="get",
            )

            if phantom.is_fail(ret_val):
                # the call to the 3rd party device or service failed, action result should contain all the error details
                # for now the return is commented out, but after implementation, return from here
                self.save_progress("Failed to fetch events")
                return action_result.get_status()

            # If success. Same rule as host resolution: exact, case-insensitive
            # (Windows agents report hostnames in upper case).
            for event in response:
                if str(event.get("hostname__") or "").strip().lower() == wanted_host:
                    action_result.add_data(event)

            if len(response) == limit:
                params["offset"] += limit
            else:
                fetched_all_events = True
                self.save_progress("Successfully collected events")

        summary = action_result.update_summary({})
        summary["num_events"] = action_result.get_data_size()
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_send_for_isolation(self, param):
        return self._send_isolation_action(param, "enable")

    def _handle_remove_from_isolation(self, param):
        return self._send_isolation_action(param, "disable")

    def _send_isolation_action(self, param, isolation_action):
        """POST an isolation action; shared by send for / remove from isolation.

        Tehtris answers 204 when the action was applied and 202 when the EDR
        agent is not connected and the task is queued until it reconnects.
        Both are success, told apart by ``summary.applied``.
        """
        action_result = self.add_action_result(ActionResult(dict(param)))
        hostname = param.get("hostname")
        self.save_progress("Obtaining uuids")

        ret_val, host = self._resolve_host(hostname, action_result, write=True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        appliance_id, uuid = host

        ret_val, response = self._make_rest_call(
            TEHTRIS_POST_FOR_ISOLATION_ENDPOINT.format(appliance_id, uuid),
            action_result,
            params={"isolationAction": isolation_action},
            headers=None,
            method="post",
            status_hints=TEHTRIS_ISOLATION_STATUS_HINTS,
        )

        verb = "isolate" if isolation_action == "enable" else "release from isolation"
        if phantom.is_fail(ret_val):
            self.save_progress(f"Failed to {verb} {hostname}")
            return action_result.get_status()

        if response:
            action_result.add_data(response)
        applied = self._last_status_code != 202
        if applied:
            message = f"Sent the request to {verb} {hostname} (uuid {uuid})"
        else:
            message = (
                f"Queued, not yet applied: the EDR agent on {hostname} (uuid {uuid}) is not connected; Tehtris will {verb} it when it reconnects"
            )
        self.save_progress(message)
        summary = action_result.update_summary({})
        summary["result"] = message
        summary["applied"] = applied

        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_list_processes(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        hostname = param.get("hostname")
        pid = param.get("pid")
        create_time = param.get("create_time")
        number_of_parents = param.get("number_of_parents")
        limit = param.get("limit", 1000)

        ret_val, host = self._resolve_host(hostname, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        appliance_id, uuid = host

        # Geting process tree
        params = {
            "pid": pid,
            "createTime": create_time,
            "nbParents": number_of_parents,
            "limit": limit,
        }

        ret_val, response = self._make_rest_call(
            TEHTRIS_GET_PROCESSES_TREE.format(appliance_id, uuid),
            action_result,
            params=params,
            headers=None,
            method="get",
            status_hints=TEHTRIS_HTTP_STATUS_HINTS,
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Failed to get processes tree")
            return action_result.get_status()

        # When succeeded; a 204 (no process matched the seed) adds nothing.
        if response:
            action_result.add_data(response)
        self.save_progress(f"Successfully fetched processes for {uuid}")
        summary = action_result.update_summary({})
        summary["num_events"] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_update_tag(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        hostname = param.get("hostname")
        tag = param.get("tag")

        self.save_progress("Obtaining uuids")

        ret_val, host = self._resolve_host(hostname, action_result, write=True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        _appliance_id, uuid = host
        uuid_list = [uuid]

        # One tag string per call; Tehtris requires the "XXX_tags" pattern
        # (trigram, underscore, tags) and does not say whether it replaces or
        # appends to the endpoint's existing tags.
        data = {"edrUuidList": uuid_list, "tags": tag}

        ret_val, response = self._make_rest_call(
            TEHTRIS_PUT_TAG, action_result, json=data, headers=None, method="put", status_hints=TEHTRIS_HTTP_STATUS_HINTS
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Failed to update tags")
            return action_result.get_status()

        # When succeeded
        message = f"Set tags '{tag}' on {hostname} (uuid {uuid}); this may have replaced the endpoint's existing tags"
        self.save_progress(message)
        summary = action_result.update_summary({})
        summary["result"] = message
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def _handle_create_app_policy(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        # policy_name = param.get('policy_name')
        sha256 = [s.strip() for s in (param.get("sha256") or "").split(",") if s.strip()]
        hostnames = [h.strip() for h in (param.get("hostnames") or "").split(",") if h.strip()]
        order = param.get("order")
        if not sha256 or not hostnames:
            return action_result.set_status(phantom.APP_ERROR, "Parameters 'hostnames' and 'sha256' need at least one value each")
        self.save_progress("Obtaining uuids")

        # Getting uuid and appliance id
        appliance_id_list = []
        for hostname in hostnames:
            ret_val, host = self._resolve_host(hostname, action_result, write=True)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            appliance_id, uuid = host
            # Tehtris rejects a repeated appliance id (uniqueItems), and two hosts often share one.
            if appliance_id not in appliance_id_list:
                appliance_id_list.append(appliance_id)

        # Creating new policy
        body = {
            "name": f"New test policy for appliances {appliance_id_list}",
            "appliances": appliance_id_list,
            "orderedRules": [
                {
                    "name": f"New test policy for appliances {appliance_id_list}",
                    "order": order,
                    "conditions": [{"type": "Sha256", "content": sha256}],
                },
            ],
        }

        ret_val, response = self._make_rest_call(
            TEHTRIS_POST_APP_POLICY,
            action_result,
            params=None,
            json=body,
            headers=None,
            method="post",
        )

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress(f"Failed to post app policy for {uuid}")
            return action_result.get_status()

        # When succeeded
        action_result.add_data(response)
        self.save_progress(f"Successfully posted new app policy for {uuid}")
        summary = action_result.update_summary({})
        summary["result"] = f"Successfully posted new app policy for {uuid}"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_isolation_status(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        hostname = param.get("hostname")

        ret_val, host = self._resolve_host(hostname, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        appliance_id, uuid = host

        ret_val, response = self._make_rest_call(
            TEHTRIS_GET_ISOLATION_ENDPOINT.format(appliance_id, uuid),
            action_result,
            headers=None,
            method="get",
            status_hints=TEHTRIS_HTTP_STATUS_HINTS,
        )
        if phantom.is_fail(ret_val):
            self.save_progress("Failed to read isolation status")
            return action_result.get_status()

        self._add_records(action_result, response)
        isolated = self._extract_isolation_state(response)

        summary = action_result.update_summary({})
        summary["isolated"] = isolated
        summary["hostname"] = hostname
        if isolated is None:
            self.save_progress("Isolation state could not be determined from the response; see raw_json")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_host_detail(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        hostname = param.get("hostname")

        # Every endpoint named exactly `hostname`, most recently seen first. No
        # such endpoint is a success with total_hosts 0 and the not-found
        # message, so a playbook can route "not found" apart from "call failed".
        ret_val, entries = self._lookup_inventory(hostname, action_result, missing_ok=True)
        if phantom.is_fail(ret_val):
            self.save_progress("Failed to fetch host detail")
            return action_result.get_status()

        count = self._add_records(action_result, entries)
        first = entries[0] if entries else {}

        summary = action_result.update_summary({})
        summary["total_hosts"] = count
        summary["uuid"] = first.get("uuid")
        summary["appliance_id"] = first.get("applianceId")
        if not entries:
            return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_processes(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        hostname = param.get("hostname")

        ret_val, host = self._resolve_host(hostname, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        appliance_id, uuid = host

        # Unlike "list processes" (a tree around a seed pid), this endpoint
        # returns a listing and needs no seed -- time-bound it instead.
        query_params = {"limit": param.get("limit", 500)}
        optional = (
            ("time_from", "timeFrom"),
            ("time_to", "timeTo"),
            ("username", "username"),
            ("path", "path"),
            ("cmdline", "cmdline"),
            ("sha256", "sha256"),
        )
        for source, target in optional:
            value = param.get(source)
            if value not in (None, ""):
                query_params[target] = value

        ret_val, response = self._make_rest_call(
            TEHTRIS_GET_PROCESSES_ENDPOINT.format(appliance_id, uuid),
            action_result,
            params=query_params,
            headers=None,
            method="get",
            status_hints=TEHTRIS_HTTP_STATUS_HINTS,
        )
        if phantom.is_fail(ret_val):
            self.save_progress("Failed to fetch processes")
            return action_result.get_status()

        count = self._add_records(action_result, response)
        summary = action_result.update_summary({})
        summary["num_processes"] = count
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_system_info(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        hostname = param.get("hostname")

        ret_val, host = self._resolve_host(hostname, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        appliance_id, uuid = host

        ret_val, response = self._make_rest_call(
            TEHTRIS_GET_SYSTEM_INFO_ENDPOINT.format(appliance_id, uuid),
            action_result,
            headers=None,
            method="get",
            status_hints=TEHTRIS_HTTP_STATUS_HINTS,
        )
        if phantom.is_fail(ret_val):
            self.save_progress("Failed to fetch system info")
            return action_result.get_status()

        count = self._add_records(action_result, response)
        summary = action_result.update_summary({})
        summary["total_objects"] = count
        summary["hostname"] = hostname
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_network_info(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        hostname = param.get("hostname")

        ret_val, host = self._resolve_host(hostname, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        appliance_id, uuid = host

        # Live network activity (netstat). The /edr/v2/data/.../network endpoint
        # returns the host's network configuration, not its connections.
        ret_val, response = self._make_rest_call(
            TEHTRIS_GET_NETSTAT_ENDPOINT.format(appliance_id, uuid),
            action_result,
            headers=None,
            method="get",
            status_hints=TEHTRIS_HTTP_STATUS_HINTS,
        )
        if phantom.is_fail(ret_val):
            self.save_progress("Failed to fetch network activity")
            return action_result.get_status()

        rows = self._live_rows(response)
        for row in rows:
            action_result.add_data(self._as_data(row))
        summary = action_result.update_summary({})
        summary["num_connections"] = len(rows)
        summary["hostname"] = hostname
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_file_info(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        hostname = param.get("hostname")
        path = param.get("path")
        if not path:
            return action_result.set_status(phantom.APP_ERROR, "Parameter 'path' is required")

        ret_val, host = self._resolve_host(hostname, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        appliance_id, uuid = host

        ret_val, response = self._make_rest_call(
            TEHTRIS_GET_FILE_INFO_ENDPOINT.format(appliance_id, uuid),
            action_result,
            params={"path": path},
            headers=None,
            method="get",
            status_hints=TEHTRIS_HTTP_STATUS_HINTS,
        )
        if phantom.is_fail(ret_val):
            self.save_progress("Failed to fetch file info")
            return action_result.get_status()

        # 204 "no content": the agent returned nothing for that path.
        found = self._add_records(action_result, response) > 0
        summary = action_result.update_summary({})
        summary["hostname"] = hostname
        summary["file_found"] = found
        summary["sha256"] = response.get("sha256") if found and isinstance(response, dict) else None
        if not found:
            return action_result.set_status(phantom.APP_SUCCESS, f"No file information returned for {path} on {hostname}")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_software(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        hostname = param.get("hostname")

        ret_val, host = self._resolve_host(hostname, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        appliance_id, uuid = host

        ret_val, response = self._make_rest_call(
            TEHTRIS_GET_SOFTWARE_ENDPOINT.format(appliance_id, uuid),
            action_result,
            headers=None,
            method="get",
            status_hints=TEHTRIS_HTTP_STATUS_HINTS,
        )
        if phantom.is_fail(ret_val):
            self.save_progress("Failed to fetch the software list")
            return action_result.get_status()

        rows = self._live_rows(response)
        for row in rows:
            action_result.add_data(self._as_data(row))
        summary = action_result.update_summary({})
        summary["num_software"] = len(rows)
        summary["hostname"] = hostname
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_quarantined_files(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        hostname = param.get("hostname")

        ret_val, host = self._resolve_host(hostname, action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        appliance_id, uuid = host

        ret_val, response = self._make_rest_call(
            TEHTRIS_QUARANTINE_ENDPOINT.format(appliance_id, uuid),
            action_result,
            headers=None,
            method="get",
            status_hints=TEHTRIS_QUARANTINE_STATUS_HINTS,
        )
        if phantom.is_fail(ret_val):
            self.save_progress("Failed to list quarantined files")
            return action_result.get_status()

        # One record per file, so each quarantine path can feed "restore file".
        paths = (response.get("quarantinePaths") if isinstance(response, dict) else None) or []
        for quarantine_path in paths:
            action_result.add_data(self._as_data({"quarantinePath": quarantine_path}))
        summary = action_result.update_summary({})
        summary["num_files"] = len(paths)
        summary["hostname"] = hostname
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_quarantine_file(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        hostname = param.get("hostname")
        path = param.get("path")
        if not path:
            return action_result.set_status(phantom.APP_ERROR, "Parameter 'path' is required")

        ret_val, host = self._resolve_host(hostname, action_result, write=True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        appliance_id, uuid = host

        params = {"path": path}
        if param.get("notification"):
            params["notification"] = param.get("notification")

        ret_val, response = self._make_rest_call(
            TEHTRIS_QUARANTINE_ENDPOINT.format(appliance_id, uuid),
            action_result,
            params=params,
            headers=None,
            method="post",
            status_hints=TEHTRIS_QUARANTINE_STATUS_HINTS,
        )
        if phantom.is_fail(ret_val):
            self.save_progress(f"Failed to quarantine {path} on {hostname}")
            return action_result.get_status()

        if response:
            action_result.add_data(self._as_data(response))
        applied = self._last_status_code != 202
        if applied:
            message = f"Sent the request to quarantine {path} on {hostname} (uuid {uuid})"
        else:
            message = f"Queued, not yet applied: the EDR agent on {hostname} (uuid {uuid}) is not connected; Tehtris will quarantine {path} when it reconnects"
        return self._report_write(action_result, message, applied)

    def _handle_restore_file(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        hostname = param.get("hostname")
        # Tehtris restores by the path the file has IN quarantine, as listed by
        # "list quarantined files" -- not by its original location.
        quarantine_path = param.get("quarantine_path")
        if not quarantine_path:
            return action_result.set_status(phantom.APP_ERROR, "Parameter 'quarantine_path' is required")

        ret_val, host = self._resolve_host(hostname, action_result, write=True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        appliance_id, uuid = host

        ret_val, response = self._make_rest_call(
            TEHTRIS_QUARANTINE_ENDPOINT.format(appliance_id, uuid),
            action_result,
            params={"path": quarantine_path},
            headers=None,
            method="patch",
            status_hints=TEHTRIS_QUARANTINE_STATUS_HINTS,
        )
        if phantom.is_fail(ret_val):
            self.save_progress(f"Failed to restore {quarantine_path} on {hostname}")
            return action_result.get_status()

        restored_path = response.get("restoredPath") if isinstance(response, dict) else None
        if response:
            action_result.add_data(self._as_data(response))
        applied = self._last_status_code != 202
        if not applied:
            message = f"Queued, not yet applied: the EDR agent on {hostname} (uuid {uuid}) is not connected; Tehtris will restore the file when it reconnects"
        elif restored_path:
            message = f"Restored {restored_path} on {hostname} from quarantine"
        else:
            message = f"Sent the request to restore {quarantine_path} on {hostname}; Tehtris returned no restored path"
        action_result.update_summary({"restored_path": restored_path})
        return self._report_write(action_result, message, applied)

    def _report_write(self, action_result, message, applied):
        """Finish a write action: 204/200 applied, 202 queued for an offline agent."""
        self.save_progress(message)
        summary = action_result.update_summary({})
        summary["result"] = message
        summary["applied"] = applied
        return action_result.set_status(phantom.APP_SUCCESS, message)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == "test_connectivity":
            ret_val = self._handle_test_connectivity(param)
        if action_id == "get_events":
            ret_val = self._handle_get_events(param)
        if action_id == "send_for_isolation":
            ret_val = self._handle_send_for_isolation(param)
        if action_id == "list_processes":
            ret_val = self._handle_list_processes(param)
        if action_id == "update_tag":
            ret_val = self._handle_update_tag(param)
        if action_id == "remove_from_isolation":
            ret_val = self._handle_remove_from_isolation(param)
        if action_id == "create_app_policy":
            ret_val = self._handle_create_app_policy(param)
        if action_id == "get_isolation_status":
            ret_val = self._handle_get_isolation_status(param)
        if action_id == "get_host_detail":
            ret_val = self._handle_get_host_detail(param)
        if action_id == "get_processes":
            ret_val = self._handle_get_processes(param)
        if action_id == "get_system_info":
            ret_val = self._handle_get_system_info(param)
        if action_id == "get_network_info":
            ret_val = self._handle_get_network_info(param)
        if action_id == "get_file_info":
            ret_val = self._handle_get_file_info(param)
        if action_id == "list_software":
            ret_val = self._handle_list_software(param)
        if action_id == "list_quarantined_files":
            ret_val = self._handle_list_quarantined_files(param)
        if action_id == "quarantine_file":
            ret_val = self._handle_quarantine_file(param)
        if action_id == "restore_file":
            ret_val = self._handle_restore_file(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get("base_url")
        self._api_key = config.get("api_key")

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = TehtrisConnector._get_phantom_base_url() + "/login"

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = TehtrisConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == "__main__":
    main()
