# Tehtris EDR — Splunk SOAR connector

Host isolation, file quarantine and restore, and read-only endpoint posture against the Tehtris
XDR/EDR platform. Used by **UC16** (`soar-playbooks`,
`docs/usecases/uc16_tehtris_edr_implementation_plan.md`). The handover package ships it renamed
`tehtris_edr` (folder, manifest, modules); `appid` and `package_name` stay the same.

## Provenance — a fork, not a new app

Forked from the Splunk-published
[`splunk-soar-connectors/tehtris`](https://github.com/splunk-soar-connectors/tehtris) at **v1.0.1**
(commit `638383ec`), Apache-2.0. Upstream filenames, `package_name` and module layout are
deliberately **unchanged** so vendor fixes can still be diffed and merged: that mergeability is why
this stays a classic `BaseConnector` fork (FR-01 exemption, `docs/dev-rules.md`).

| Field | Upstream | Here | Why |
|---|---|---|---|
| `appid` | `d91ead7b-…` | `bf34e3e5-…` | never reuse another connector's appid |
| `name` | Tehtris | Tehtris EDR | tells the fork apart in the app list |
| `app_version` | 1.0.1 | 1.2.x | upstream 1.0.1 plus local extensions |
| `python_version` | `3.9, 3.13` | `3.13` | soar8 targets 3.13 only (`pip39_dependencies` dropped) |
| `publisher` | Splunk | Ted | the local changes are not Splunk's work |
| `license` | Splunk copyright | Apache-2.0 + Splunk copyright | attribution for a fork |
| logos | `tehtris*.svg` | `logo.svg`, `logo_dark.svg` | repo naming convention |

> **Install caveat:** `package_name` is still `phantom_tehtris`, as upstream's. Do not install this
> fork and the official app on one appliance.

## Actions

Every host-scoped action takes a plain **`hostname`**; the connector resolves it to `applianceId` +
`edrUuid`, so callers never handle Tehtris uuids. Upstream's seven are `test connectivity`,
`get events`, `send for isolation`, `remove from isolation`, `list processes`, `update tag` and
`create app policy`. Added for UC16:

| Action | Type | API call |
|---|---|---|
| `get isolation status` | investigate | `GET /edr/v2/live/{applianceId}/{uuid}/isolation` |
| `get host detail` | investigate | `GET /edr/v2/inventory?hostname=` |
| `get processes` | investigate | `GET /edr/v2/data/{applianceId}/{uuid}/processes` |
| `get system info` | investigate | `GET /edr/v2/live/{applianceId}/{uuid}/systemInfo` |
| `get network info` | investigate | `GET /edr/v2/live/{applianceId}/{uuid}/netstat` |
| `get file info` | investigate | `GET /edr/v2/live/{applianceId}/{uuid}/fileInfo?path=` |
| `list software` | investigate | `GET /edr/v2/live/{applianceId}/{uuid}/software` |
| `list quarantined files` | investigate | `GET /edr/v2/live/{applianceId}/{uuid}/remediation/quarantine` |
| `quarantine file` | contain | `POST /edr/v2/live/{applianceId}/{uuid}/remediation/quarantine?path=` |
| `restore file` | correct | `PATCH /edr/v2/live/{applianceId}/{uuid}/remediation/quarantine?path=<quarantine path>` |

- **`get processes`** returns a listing bounded by `time_from`/`time_to`/`limit` (plus optional
  `username`/`path`/`cmdline`/`sha256` filters); upstream's `list processes` builds a tree around a
  seed `pid` + `create_time`. Tehtris serves the listing through a cursor and the action reads the
  first page, so `limit` caps it.
- **`get host detail`** is the existence check: a hostname no endpoint carries exactly is a
  *success* with `total_hosts` 0 and the not-found reason as message. Every other host-scoped action
  fails on an unknown host before sending anything.
- **`get network info`** is live `netstat`; the `/edr/v2/data/…/network` endpoint is network
  configuration. Rows are keyed by the column names each reply carries (not in the reference).
- **`get system info`** is OS details only; the reference's `name` enum holds only `windows`, so
  another OS may answer 501.
- **Quarantine and restore take different paths.** `quarantine file` takes the file's path on the
  host; `restore file` takes its path **in quarantine** (`quarantinePath` from
  `list quarantined files`), as a `quarantine_path` parameter with its own `contains` type
  (`tehtris quarantine path`), so the pair has no manifest `undo` link. `quarantine file`'s
  optional `notification` is passed as is (Windows only, format undocumented).
- `/edr/v2/live/…` calls need the agent connected (504 otherwise); `/edr/v2/data/…` and the
  inventory work while it is offline.

## Fixes to upstream behaviour

1. **Unguarded `response["data"][0]`** in five places: an unknown host raised `IndexError`. All
   go through `_resolve_host()`, which names the missing host.
2. **`read_only: true` on write actions** (isolation, `update tag`, `create app policy`): now `false`.
3. **Read actions typed `contain`:** `get events` and `list processes` are `investigate`.
4. **`create app policy` list items were not trimmed** (`"h1, h2"` looked up `" h2"`): trimmed,
   empties dropped, an empty list is a parameter error.
5. **`get events` looped forever on `limit` 0** (paging stops on a short page): `limit` must be
   positive.
6. **Two malformed `get events` output datapaths** (a duplicate `cmdline`, `threat.framework`
   without `*`).
7. **A hostname could resolve to another host.** The inventory's `hostname` filter matches
   substrings and upstream took the first entry, so `ws-hr-07` could resolve to — and isolate —
   `ws-hr-070`. Only a case-insensitive exact match is kept; with several (a re-installed agent),
   a read uses the newest `lastSeen` and the write actions refuse and list the uuids.
8. **Write replies:** 204 is success with no body; 202 is the vendor's "EDR not connected, task will
   be done later" (`summary.applied` false), which the reference ties to `persist`, never sent here.
   Errors carry the vendor's meaning of the code (409 local proxy or conflict, 501 not implemented on
   the endpoint, 504 agent unreachable, 422 rejected parameters).
9. **`create app policy` repeated appliance ids** (`uniqueItems`): de-duplicated; `order` is the
   vendor enum.
10. **`get events` page size** is 1–1000 (the reference's limit; upstream's text said 100); an empty
    (204) reply counts as zero records.
11. **`get events` host filter** was exact and case-sensitive while Windows agents report upper-case
    hostnames: same case-insensitive rule as host resolution.
12. **No request timeout:** every call now has one (asset field `timeout`, default 30 s, at most
    300) and goes through one `requests.Session` per action run with `trust_env` off. Retries:
    up to 3 with exponential backoff on 429/500/502/503, honouring `Retry-After`, on **GET and PUT
    only** — an isolation or quarantine POST/PATCH is never replayed. 504 is not retried (an agent
    that is not connected), nor is a read timeout (Tehtris may have acted).

Also: `undo` pairing between `send for isolation` and `remove from isolation`, `allow_list` on the
comma-separated `hostnames`/`sha256`, `contains: ["host name"]` on the hostname parameters.
**`create app policy`** scopes by appliance (the request carries `appliances`, no endpoint field),
so a policy "for host X" covers every endpoint on X's appliance; kept as upstream. **`update tag`**
sends one tag string (`XXX_tags`: trigram, underscore, tags, at most 64 characters) and the
reference does not say whether it replaces the endpoint's tags: read them with `get host detail`
first.

## Contract source: the vendor OpenAPI reference

`tehtris_api_reference.json` (this folder, excluded from the package and never shipped) is Tehtris'
own OpenAPI 3.0.2 document, "TEHTRIS XDR Platform API" v14.00.00.05 (250 paths, `servers: /api`,
HTTP basic auth). It is not public. It settles every path, method, parameter and enum the connector
uses (`tests/test_api_reference.py` checks them offline), the response shapes and the status codes
above.

Still open, so every action keeps its `raw_json` passthrough: the `get events` response fields (no
schema), netstat and software column names, the keys inside inventory `os`/`versions`, whether
`update tag` replaces, how the process cursor continues, the quarantine path format. Only a real
tenant settles those.

## Asset configuration

| Field | Notes |
|---|---|
| `base_url` | **Must end in `/api`**, e.g. `https://<trigram>.api.tehtris.net/api`; without it every action is a 404 |
| `api_key` | API key from the tenant (*parameters → API keys*), sent as HTTP basic auth with the username `api` |
| `verify_server_cert` | default true |
| `timeout` | optional, seconds per call, default 30, at most 300; anything else fails the action at start |

The `api` username comes from upstream's code and Swimlane's independent implementation (the
reference does not name one). If a real appliance rejects auth, check the asset first (password
fields do not cross an air gap as usable values), then the username.

## Tests

`tests/` (excluded from the package) stubs the `phantom` modules and runs every action through
`handle_action` over real HTTP against `mock_tehtris.py` (`soar8/migration/mock-backend/`, port 8448),
plus manifest↔connector and connector↔reference checks and `test_session.py` (the retry rules
against a scripted server). The mock follows the reference: substring inventory search, 204/202/201
replies, 422 validation, a duplicate hostname, an offline agent (504), a host behind a local proxy
(409), a Linux host (501), file info, software and a stateful quarantine. The live suite skips
itself when the mock is unreachable; `TEHTRIS_MOCK_URL` (ending in `/api`) points it elsewhere.

```
uv run --python 3.13 --with pytest --with requests --with beautifulsoup4 \
    pytest connectors/tehtris/tests
```

A pristine upstream v1.0.1 checkout for diffing lives (gitignored) at `reference_connectors/tehtris/`:
`git clone https://github.com/splunk-soar-connectors/tehtris && git checkout 638383ec`.
