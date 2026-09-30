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
# Define your constants here
TEHTRIS_GET_EVENTS_ENDPOINT = "/xdr/v1/event"
TEHTRIS_POST_FILTER_ENDPOINT = "/xdr/v2/filter/filter"
TEHTRIS_GET_INVENTORY_ENDPOINT = "/edr/v2/inventory"
TEHTRIS_POST_FOR_ISOLATION_ENDPOINT = "/edr/v2/live/{}/{}/isolation"
TEHTRIS_GET_PROCESSES_TREE = "/edr/v2/data/{}/{}/processes/tree"
TEHTRIS_PUT_TAG = "/edr/v2/inventory/tags"
TEHTRIS_POST_APP_POLICY = "/edr/v2/policies/application"

# --- Local extensions (fork of splunk-soar-connectors/tehtris v1.0.1) ---------
# Read-only posture endpoints. All are host-scoped and take the
# {applianceId}/{edrUuid} pair resolved from a hostname via the inventory
# endpoint above, so every action exposes a plain `hostname` parameter.
TEHTRIS_GET_ISOLATION_ENDPOINT = "/edr/v2/live/{}/{}/isolation"
TEHTRIS_GET_SYSTEM_INFO_ENDPOINT = "/edr/v2/live/{}/{}/systemInfo"
TEHTRIS_GET_PROCESSES_ENDPOINT = "/edr/v2/data/{}/{}/processes"
TEHTRIS_GET_NETSTAT_ENDPOINT = "/edr/v2/live/{}/{}/netstat"
TEHTRIS_GET_FILE_INFO_ENDPOINT = "/edr/v2/live/{}/{}/fileInfo"
TEHTRIS_GET_SOFTWARE_ENDPOINT = "/edr/v2/live/{}/{}/software"
# GET lists quarantined files, POST quarantines a file, PATCH restores one.
TEHTRIS_QUARANTINE_ENDPOINT = "/edr/v2/live/{}/{}/remediation/quarantine"

# The events endpoint rejects a page size above this (vendor API reference).
TEHTRIS_EVENTS_MAX_LIMIT = 1000

# Seconds to wait for each HTTP call (dev-rules FR-05 default); upstream set none.
TEHTRIS_DEFAULT_TIMEOUT = 30

# Status codes the vendor API reference documents with a fixed meaning on the
# host-scoped /edr/v2/live and /edr/v2/data endpoints. Appended to the error
# message so an operator reads the vendor's meaning, not just a number.
TEHTRIS_HTTP_STATUS_HINTS = {
    401: "missing or invalid API key",
    403: "the API key lacks the privileges for this call",
    404: "the EDR endpoint cannot be found",
    422: "Tehtris rejected the request parameters",
    429: "too many open cursors on the tenant; retry later",
    500: "the appliance failed to retrieve the data",
    501: "this API function is not implemented on the endpoint (e.g. an OS the call does not support)",
    504: "the appliance is not reachable or the EDR agent did not respond in time",
}
# 409 means something different on each write endpoint.
TEHTRIS_ISOLATION_STATUS_HINTS = {**TEHTRIS_HTTP_STATUS_HINTS, 409: "cannot isolate an endpoint that uses a local proxy"}
TEHTRIS_QUARANTINE_STATUS_HINTS = {**TEHTRIS_HTTP_STATUS_HINTS, 409: "Tehtris refused the request because of a conflict"}

# Error messages
TEHTRIS_ERR_HOST_NOT_FOUND = (
    "Host '{}' was not found in the Tehtris EDR inventory. "
    "Check the hostname, or whether the agent is still enrolled."
)
TEHTRIS_ERR_HOST_NOT_EXACT = (
    "Host '{}' was not found in the Tehtris EDR inventory. The inventory's hostname "
    "filter matches substrings, and none of the {} entries it returned is named exactly '{}': {}"
)
TEHTRIS_ERR_HOST_AMBIGUOUS = (
    "Hostname '{}' matches {} Tehtris EDR endpoints (for example a re-installed agent), "
    "so this write action was not sent to any of them: {}"
)
TEHTRIS_ERR_INVENTORY_SHAPE = (
    "Unexpected inventory response for host '{}': no usable 'data' entries returned."
)
