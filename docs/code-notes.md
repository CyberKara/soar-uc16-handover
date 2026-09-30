# Code notes: connector and playbook

The design and vendor-behaviour notes that currently live in code comments,
collected here so the comments can be trimmed later without losing them
(`TODO.md` lists the trimming). Line numbers are for commit `dd2ff0a`.

Where things are written down already:

- Fork provenance and the 12 fixes to upstream behaviour:
  `connectors/source/tehtris/README.md`.
- Design, decisions and operations log: `docs/uc16_tehtris_edr_implementation_plan.md`.

## Connector (`connectors/source/tehtris/`)

### Behaviour the code relies on

| Topic | What is true | Code |
|---|---|---|
| Hostname lookup | The inventory's `hostname` filter matches **substrings**: a query for `ws-01` also returns `ws-010` and `ws-01-old`, in no guaranteed order. Only a case-insensitive exact match on `hostname` counts. | `_lookup_inventory` (197) |
| Duplicate hostnames | A re-installed agent keeps its hostname under a new uuid, so several exact matches are possible. They come back newest `lastSeen` first. A read uses the most recent; a write (`write=True`) is refused, so an isolation never picks between endpoints on its own. | `_resolve_host` (242) |
| Unknown host | An error, except with `missing_ok` (used by `get host detail`): then it is a success with the not-found message and no hosts, so a playbook can tell "no such host" from "call failed". | `_lookup_inventory` (197), `_handle_get_host_detail` (670, comment 674) |
| HTTP 204 / 202 | 204 is Tehtris' success reply for writes and for "no content"; 202 means the task was queued for an EDR agent that is not connected. | `_process_empty_response` (56) |
| HTML errors | A proxy between SOAR and the API answers errors with HTML; it is parsed into the error message whatever the API speaks. | `_process_html_response` (70) |
| Debug data | Status, body and headers of every reply are attached to the action result so they reach the logs when an action fails. | `_process_response` (117) |
| Timeout | 30 s per call (`TEHTRIS_DEFAULT_TIMEOUT`); the error names the endpoint. Upstream had none. | `_make_rest_call` (150) |
| Loosely typed replies | The vendor reference leaves several replies untyped (events have no schema, live rows are untyped, inventory `os`/`versions` are free-form). Each action forwards the payload verbatim and also exposes it as a `raw_json` string. | `_as_data` (278) |
| Record unwrapping | A list under `data` / `list` / `items` / `results` becomes one record each; an empty body is zero records. | `_add_records` (296) |
| Live rows | Live replies are `{columns, data}`; a list row is zipped with the column names, a dict row is kept as is. | `_live_rows` (321) |
| Events | Paging stops on the first page shorter than `limit`, so `limit` 0 would never stop. The host filter is exact and case-insensitive (Windows agents report upper-case hostnames). `limit` must be 1 to 1000, the vendor's maximum page size. | `_handle_get_events` (392, comments 397, 435) |
| Tags | One tag string per call. Tehtris requires the `XXX_tags` pattern (trigram, underscore, tags) and does not say whether an update replaces or appends. **Open question**, see `HANDOVER.md` step 3. | `_handle_update_tag` (548, comment 561) |
| App policy | Tehtris rejects a repeated appliance id (`uniqueItems`) and two hosts often share one, so ids are de-duplicated. | `_handle_create_app_policy` (583, comment 600) |
| Processes | `list processes` is a tree around a seed pid (needs `pid` and `create_time`). `get processes` is a listing with no seed, bounded by time. For `list processes`, a 204 (no process matched the seed) adds nothing. | `_handle_list_processes` (503, comment 539), `_handle_get_processes` (693, comment 702) |
| Network | `get network info` calls the live `netstat` endpoint. `/data/.../network` returns the host's network configuration, not its connections. | `_handle_get_network_info` (761, comment 770) |
| File info | A 204 means the agent returned nothing for that path. | `_handle_get_file_info` (791, comment 815) |
| Quarantine | One record per file, so each quarantine path can feed `restore file`. Tehtris restores by the path the file has **in quarantine** (as listed by `list quarantined files`), not its original location. | `_handle_list_quarantined_files` (853, comment 873), `_handle_restore_file` (919, comment 922) |

### Constants (`tehtris_consts.py`)

- `TEHTRIS_EVENTS_MAX_LIMIT = 1000`: the events endpoint rejects a larger page.
- `TEHTRIS_HTTP_STATUS_HINTS`: the vendor's fixed meaning of a status code on the
  host-scoped `/edr/v2/live` and `/edr/v2/data` endpoints, appended to the error
  so an operator reads the meaning and not just a number.

  | Code | Meaning |
  |---|---|
  | 401 | missing or invalid API key |
  | 403 | the key lacks the privileges for this call |
  | 404 | the EDR endpoint cannot be found |
  | 422 | Tehtris rejected the request parameters |
  | 429 | too many open cursors on the tenant; retry later |
  | 500 | the appliance failed to retrieve the data |
  | 501 | not implemented on the endpoint (e.g. an OS the call does not support) |
  | 504 | the appliance is not reachable, or the EDR agent did not answer in time |

  409 differs per write endpoint: isolation says "cannot isolate an endpoint
  that uses a local proxy"; quarantine says "refused because of a conflict".
- Error templates: `TEHTRIS_ERR_HOST_NOT_FOUND`, `_HOST_NOT_EXACT` (the filter
  returned entries but none is named exactly), `_HOST_AMBIGUOUS` (a write that
  matched several endpoints), `_INVENTORY_SHAPE` (no usable `data` entries).

## Playbook (`playbooks/source/tehtris_host_posture/`)

### Design (the block now at `tehtris_host_posture.py:16-24`)

- **Read-only.** Every action is an investigate action, so the playbook is safe
  to run and re-run on any container (label `*`). The hostname input is the
  check that the host belongs.
- **Existence check.** `get host detail` runs first; an unknown host is a
  success with `total_hosts` 0 (connector v1.2.1 and later), a failed status
  means the lookup itself failed. `check_host` routes to `host_found` or
  `note_no_host` on that.
- **Live calls can fail without failing the run.** Isolation status, system info,
  netstat and software need the agent connected (504 otherwise); system info is
  Windows-only (501). A failed call becomes "not available" in the note and the
  playbook ends with status `partial`.
- **Why the notes sit in the code:** a VPE save replaces the module docstring,
  so the notes were put in the global custom code, which a save keeps. With
  them here, that copy is no longer needed.

### Flow

`on_start` > `check_inputs` > `get_host_detail` > `check_host` >
(`host_found` > `get_isolation_status` > `get_system_info` > `get_processes` >
`get_network_info` > `list_software` > `get_recent_events` > `note_posture`)
or `note_no_host`. SOAR then calls `on_finish`.

### Constants and inputs

| Item | Why |
|---|---|
| `_NOTE_MAX_CHARS` 20000 | The target SOAR shows about 22,000 characters of a note. A longer note is split by `_note_parts()` / `_pack()`, headed "title (k/N)". |
| `_MAX_LOOKBACK_MINUTES` 42 days | Tehtris refuses an events query that starts more than 43 days back. |
| `_TABLE_BUDGETS`, `_CELL_MAX_CHARS`, `_SUMMARY_MAX_CHARS` | Each table gets a character budget so it is never split across note parts; rows past the budget stay in the action result. |
| Two time formats (`check_inputs`, 358) | `get processes` takes ISO 8601 date-times, `get events` takes epoch seconds. |
| Run data (`check_inputs`, 366) | The values are also saved as run data because later blocks read them in their own custom code. |
| Inputs re-read (`check_inputs`, 326) | So the block does not depend on the generated variable names. |
| `note_format="markdown"` (352, 783, 839) | `add_note()` defaults to html. |
| Output normalisation (`on_finish`, 886) | The 8.6 VPE initialises every output to `[]` (8.5 wrote `None`); an output no block set is normalised to null. |

### Generated text: do not hand-edit

`## Custom Code Start/End` markers, `# pylint: disable=used-before-assignment`,
`# Write your custom code here...`, `# check for 'if' condition 1` and the
commented `phantom.debug('Action: ...')` lines are written by the VPE and come
back on the next save. The playbook ships pointed at the asset `tehtris_mock_8446`
(see `HANDOVER.md`).
