# Tehtris EDR — Isolate + Security Posture (UC16) — Implementation Plan

Current design. How it got here (every dated change, test and decision): `uc16_history.md`, not
shipped in the handover. Open work: the Splunk project's `docs/next-steps.md` (not shipped).

## Scope

- An analyst reads a host's security posture from Tehtris EDR, isolates or releases the host, or
  quarantines one file on it, from any SOAR container.
- Every change on a host (isolate, release, quarantine) waits for an approval prompt; nothing runs
  automatically.
- Out of scope: a restore playbook (restore from the Tehtris console with the quarantine path the
  note records; the connector's `restore file` exists), application policies (`create app policy`),
  the `list processes` tree, `hard` isolation and requests queued for offline agents (`persist`).

## Architecture

| Playbook | Type | Label | Role |
|---|---|---|---|
| PB1 `tehtris_host_posture` | data | `*` | Posture note for one host; changes nothing |
| PB2 `tehtris_host_isolate` | data | `*` | Prompt → isolate → verify → tag |
| PB3 `tehtris_host_unisolate` | data | `*` | Prompt → release → verify → tag |
| PB4 `tehtris_edr_response` | data | `*` | Runs PB1, then PB2 with the posture summary in its prompt |
| PB5 `tehtris_file_quarantine` | data | `*` | Prompt → quarantine one file → list the host's quarantine |

No playbook is active (all are run by hand), no custom function. One custom list,
`tehtris_edr_settings`. The action blocks select the asset `tehtris_mock`.

**Connector:** a fork of the Splunk-published `tehtris` app v1.0.1 (classic, Apache-2.0), display
name `Tehtris EDR`, 17 actions. The source keeps the upstream names so vendor fixes still merge;
the handover package ships it renamed `tehtris_edr` (same `appid`, same `package_name`
`phantom_tehtris`, so it upgrades in place). Every host-scoped action takes a plain `hostname`;
the playbooks never handle Tehtris uuids.

**Rules every playbook follows:**

- The first code block checks the inputs; a missing or invalid one stops the run with a
  `Tehtris <Posture|Isolation|Release|Quarantine|Response> - Error` note.
- Logic lives in Custom Code only, so a VPE save cannot break a playbook.
- A prompt is raised from a code block with `phantom.prompt2()`: approver = the container owner,
  else `soar_local_admin`; it expires after 30 minutes. A native prompt block would lose the
  fallback on a save.
- Nothing is sent when the pre-check cannot read the host's state (agent offline: 504; unknown
  host; no state returned): no `persist`, so nothing runs later unseen.
- Notes are markdown, split into `(k/N)` parts under 20,000 characters (the appliance cuts a note at
  about 22,000). Every Tehtris value is an inline code span, so endpoint data stays inert.
- On finish, an output no block set is null (the 8.6 VPE initialises outputs to `[]`), and a run
  that recorded no outcome reports `error`.

## Playbooks

### PB1 — `tehtris_host_posture`

Inputs: `hostname` (required), `lookback_minutes` (default 60, at most 60,480 = 42 days, inside
Tehtris' 43-day events limit). Outputs: `status` (`success`, `partial`, `not_found`, `error`),
`host_found`, `os`, `agent_last_seen`, `isolation_state` (`isolated`, `not isolated`, `unknown`),
`process_count`, `connection_count`, `software_count`, `event_count`, `summary` (three lines, for a
parent playbook or a prompt).

`check_inputs` → `get_host_detail` → `check_host` (found / not found / lookup failed) →
`host_found` (decision):

- found → `get_isolation_status`, `get_system_info`, `get_processes` (the lookback window,
  the connector's default limit 500), `get_network_info`, `list_software`, `get_recent_events` (since the window start) →
  `note_posture`;
- otherwise → `note_no_host` (`not_found`, or `error` with the connector's message).

The note `Tehtris Posture: <host>`: isolation, OS, last/first seen, domain, IPs, tags, endpoint
uuid and appliance, the window; then one table per section (system info, processes, live
connections, software, events). A failed live call reads "not available" with its message and
makes the status `partial`, never a failed playbook. Each table has a character budget
(processes 9,000; the others 4,000); rows past it are counted, not shown. Connections and software
have no declared columns, so their tables use the reply's own keys. Several endpoints with one
hostname: the reads use the most recently seen one and the note says so.

### PB2 — `tehtris_host_isolate`

Inputs: `hostname` (required), `reason`, `posture_summary` (both shown in the prompt). Outputs:
`status` (`isolated`, `applied_not_confirmed`, `queued`, `already_isolated`, `not_sent`,
`declined`, `expired`, `failed`, `error`), `isolation_requested`, `isolation_verified`,
`tag_applied` (`written`, `already`, `skipped`, `failed`, `not attempted`), `analyst_response`,
`message`.

`check_inputs` → `pre_check_isolation` (get isolation status) → `route_pre_check`: state unreadable
→ `not_sent`; already isolated → `already_isolated`; else the prompt (`Isolate host` / `Do not
isolate`) → `isolate_decision`: declined or expired → note; approved → `send_for_isolation` →
`verify_isolation` → `read_host_tags` (get host detail) → `build_tag` → `tag_isolated` (update tag)
→ `note_result` (`Tehtris Isolation: <host>`).

Isolation is sent without `power` (the tenant's `soft` default) and without `persist`. A read-back
that does not show the host isolated yet is `applied_not_confirmed`, not a failure, and the tag is
left alone. A hostname shared by several endpoints is refused by the connector; the note keeps the
whole uuid list.

**Tags.** A host's Tehtris tags are one string of at most 64 characters, starting with the tenant
trigram and an underscore, and `update tag` writes the whole string; so `build_tag` reads the
current string and appends to it:

- tag only when the read-back shows the host isolated;
- non-empty string → remove `soar-released`, append `soar-isolated` with the separator (one marker
  slot, so markers do not accumulate);
- empty string → `<tag_trigram>_soar-isolated`, the trigram from `tehtris_edr_settings`; no trigram
  set → no write, noted;
- marker already present → no write (`already`); result over 64 characters → no write, noted;
  existing tags are never cut.

`tag_isolated` skips the write by returning from its own Custom Code when `build_tag` found nothing
to write. The read and the write are two calls: a tag edited in the console in between is
overwritten; the note shows the string before and after.

### PB3 — `tehtris_host_unisolate`

PB2 in the other direction: inputs `hostname`, `reason`; outputs `status` (`released`,
`applied_not_confirmed`, `queued`, `not_isolated`, `not_sent`, `declined`, `expired`, `failed`,
`error`), `release_requested`, `release_verified`, `tag_applied`, `analyst_response`, `message`.
Not isolated → `not_isolated`, nothing sent. The prompt is `Release host` / `Do not release`; the
tag swaps `soar-isolated` for `soar-released`, only when the read-back shows the host released.
Note `Tehtris Release: <host>`.

### PB4 — `tehtris_edr_response`

Inputs: `hostname`, `reason`, `lookback_minutes`. `check_inputs` → `run_posture`
(`local/tehtris_host_posture`, synchronous) → `run_isolate` (`local/tehtris_host_isolate`,
synchronous, `posture_summary` = PB1's `summary` output) → `report_outcome`. Outputs: `status`
(PB2's, or `error`), `posture_status`, `isolation_status`, `message`. It adds no capability: the
children check, prompt and write their own notes, and the isolation prompt appears only after the
posture note exists.

### PB5 — `tehtris_file_quarantine`

Inputs: `hostname`, `path` (the file's full path on the host; Windows: drive letter and
backslashes), `reason`, `notification` (text Tehtris shows the Windows user; blank sends none).
Outputs: `status` (`quarantined`, `queued`, `not_found`, `not_sent`, `declined`, `expired`,
`failed`, `error`), `file_found`, `sha256`, `quarantined`, `quarantine_paths`,
`analyst_response`, `message`.

`check_inputs` → `get_file_info` → `route_file_info`: unreadable → `not_sent`; no such file →
`not_found`; else the prompt (path, SHA-256, original name, product and version, signatures,
reason, notification; `Quarantine file` / `Do not quarantine`) → `quarantine_decision` →
`quarantine_file` → `list_quarantined` → `note_result` (`Tehtris Quarantine: <host>`).

Tehtris lists quarantine paths only, so the listing cannot be matched to the original file:
`quarantined` reflects `quarantine file`'s own reply and the note lists every quarantine path, the
one a restore takes. A shared hostname passes `get file info` (a read uses the newest endpoint) and
is refused at `quarantine file`.

## Data model and API facts

**Contract source:** Tehtris' own OpenAPI document, "TEHTRIS XDR Platform API" v14.00.00.05 (250
paths, `servers: /api`, HTTP basic auth), kept beside the connector source. It is not public and is
never shipped.

**Connector actions** (upstream's 7, then the 10 added for UC16):

| Action | Call | Used by |
|---|---|---|
| `test connectivity` | `GET /xdr/v1/event` from now | — |
| `get events` | `GET /xdr/v1/event` (paged, page size 1-1000, filtered by host after paging) | PB1 |
| `send for isolation` / `remove from isolation` | `POST /edr/v2/live/{appliance}/{uuid}/isolation` | PB2 / PB3 |
| `list processes` | process tree around a seed pid | — |
| `update tag` | `PUT /edr/v2/inventory/tags` | PB2, PB3 |
| `create app policy` | application policy, scoped by appliance | — |
| `get isolation status` | `GET …/live/…/isolation` → `{status: bool}` | PB1, PB2, PB3 |
| `get host detail` | `GET /edr/v2/inventory?hostname=` | PB1, PB2, PB3 |
| `get processes` | `GET …/data/…/processes` (first cursor page) | PB1 |
| `get system info` | `GET …/live/…/systemInfo` | PB1 |
| `get network info` | `GET …/live/…/netstat` | PB1 |
| `list software` | `GET …/live/…/software` | PB1 |
| `get file info` | `GET …/live/…/fileInfo?path=` | PB5 |
| `list quarantined files` | `GET …/live/…/remediation/quarantine` | PB5 |
| `quarantine file` | `POST …/live/…/remediation/quarantine?path=` | PB5 |
| `restore file` | `PATCH …/live/…/remediation/quarantine?path=<quarantine path>` | — |

- **Host resolution:** the inventory's `hostname` filter matches substrings, so the connector keeps
  a case-insensitive exact match only. Several exact matches (a re-installed agent): a read uses
  the newest `lastSeen`, a write is refused with every uuid listed. `get host detail` on an
  unknown host succeeds with `total_hosts` 0; every other action fails before sending anything.
- **Live vs data:** `/edr/v2/live/…` calls need the agent connected (504 otherwise);
  `/edr/v2/data/…` and the inventory work while it is offline.
- **Replies:** 204 is success for writes; 202 is "EDR not connected, task will be done later"
  (`summary.applied` false), which the spec ties to `persist`; 409 on isolation = endpoint behind
  a local proxy; 501 = not implemented on the endpoint (`systemInfo` names only `windows`); 422 =
  parameters rejected. The vendor's meaning is appended to the error message.
- **Isolation status** with no state (204) is `unknown`, never `not isolated`.
- **Tags:** `UpdateTags.tags` is one string, `maxLength` 64, `<trigram>_…`; the spec does not say
  whether a write replaces or appends, so UC16 treats it as replacing.
- **Quarantine:** quarantine takes the file's path on the host; `list quarantined files` returns
  `quarantinePath`, which `restore file` takes (not the original path).
- **Netstat and software** replies are `{columns, data}`; the column names are not in the spec.
- **Retries:** one `requests.Session` per action run, `trust_env` off; 429/500/502/503 retried on
  GET and PUT only, honouring `Retry-After`; never a POST/PATCH, never 504, never a read timeout.
  Timeout per call: asset field `timeout` (default 30 s, at most 300).

## Setup Guide

1. **Connector:** Apps > Install App with the `tehtris_edr` package. Over an earlier install it
   upgrades in place. Do not install the official Splunk Tehtris app next to it: both use
   `package_name` `phantom_tehtris`.
2. **Asset:** the playbooks ship pointed at `tehtris_mock`. Keep that name, or re-point the action
   blocks of PB1, PB2, PB3 and PB5 to your asset in the VPE and save.

   | Field | Value |
   |---|---|
   | `base_url` | must end in `/api`, e.g. `https://<trigram>.api.tehtris.net/api` (without it every action is a 404) |
   | `api_key` | an API key from the tenant (*parameters → API keys*), sent as basic auth with user `api` |
   | `verify_server_cert` | default true |
   | `timeout` | optional, seconds per call, default 30, at most 300 |

   Then Test Connectivity, and `get host detail` with one real hostname.
3. **Custom list `tehtris_edr_settings`:** key/value rows, no header row. `tag_trigram`: the tenant's
   three-letter tag prefix, used only for a host with no tags yet; `tag_separator`: the character
   between tags (empty = comma). Both may stay empty.
4. **Import** the five playbooks. PB4 starts PB1 and PB2 by name from the `local` repository; if
   the VPE shows its playbook blocks unconfigured, pick the two playbooks again and save.
5. **Nothing to activate:** all five are data playbooks, run from a container with Playbooks > Run
   Playbook. The approver is the container owner, else `soar_local_admin`.

## Verification

- **Lab mock:** `mock_tehtris.py` (port 8448, `mock-tehtris.service`) follows the vendor spec and
  resets on restart. Hosts: `ws-finance-01` (Windows, not isolated), `ws-hr-07` (isolated) and
  `ws-hr-070` (the substring trap), `srv-db-02`, `ws-offline-09` (504), `ws-proxy-11` (409),
  `ws-reimaged-05` (two endpoints), `ghost-host-01` (unknown). Data playbooks run over REST with
  `POST /rest/playbook_run` and `inputs`; prompts are answered in the GUI.
- **Every path:** PB1 found / partial / not found / error; PB2 and PB3 isolated / released,
  declined, expired, already in the state, not sent (offline, unknown), refused (local proxy,
  shared hostname); PB4 end to end and expired; PB5 quarantined, declined, not found, not sent. The
  tag cases (no tags yet, separator, 64 characters, the swap) are covered offline.
- **Target:** Test Connectivity and `get host detail`; PB1 on one host; isolate then release one
  TEST host; quarantine one TEST file; then report the open points below.

## Known limitations

- **A real tenant still has to settle:** the `get events` response fields (no schema in the spec),
  netstat and software column names, the tag separator and whether `update tag` replaces, how soon
  `get isolation status` reflects an isolation, the quarantine path format, and whether offline
  hosts need `persist` (then 202 = queued) or `hard` isolation is ever wanted.
- `queued` and `applied_not_confirmed` cannot be produced on the mock (no `persist`, immediate
  read-back).
- `get processes` reads the first cursor page only; `limit` caps it.
- `create app policy` covers every endpoint on the listed hosts' appliances, not only those hosts.
