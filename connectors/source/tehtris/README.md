# Tehtris EDR — Splunk SOAR connector

Host isolation plus read-only endpoint security posture against the Tehtris
XDR/EDR platform. Consumed by **UC16** (`soar-playbooks`,
`docs/usecases/uc16_tehtris_edr_implementation_plan.md`).

## Provenance — this is a fork, not a new app

Forked from the official Splunk-published app
[`splunk-soar-connectors/tehtris`](https://github.com/splunk-soar-connectors/tehtris)
at **v1.0.1** (commit `638383ec`, 2026-07-20), Apache-2.0. Upstream filenames,
`package_name` and module layout are deliberately **unchanged** so vendor fixes
can still be diffed and merged in — that mergeability is the whole reason this
is a classic `BaseConnector` fork rather than an SDK rewrite (FR-01 discussion
in the UC16 plan).

What differs from upstream:

| Field | Upstream | Here | Why |
|---|---|---|---|
| `appid` | `d91ead7b-…` | `bf34e3e5-…` | dev-rules: never reuse another connector's appid |
| `name` | Tehtris | Tehtris EDR | distinguishes this fork in the GUI app list |
| `app_version` | 1.0.1 | 1.2.1 | signals "upstream 1.0.1 + local extensions" |
| `python_version` | `3.9, 3.13` | `3.13` | dev-rules: soar8 targets 3.13 only |
| `publisher` | Splunk | Ted | the local modifications are not Splunk's work |
| `license` | Splunk copyright | Apache-2.0 + Splunk copyright | accurate attribution for a fork |
| logos | `tehtris*.svg` | `logo.svg`, `logo_dark.svg` | repo naming convention |

`pip39_dependencies` was dropped (dead config once 3.9 is no longer declared).
Upstream's `contributors` entry is kept.

> **Install caveat:** `package_name` is still `phantom_tehtris`, the same as
> upstream. Installing both this fork and the official app on one appliance is
> therefore not supported — pick one. The official app is not installed on soar8
> (`GET /rest/app?_filter_name__icontains="tehtris"` returned 0 when this fork
> was created).

## Added actions (10)

All take a plain **`hostname`** — the connector resolves hostname →
`applianceId` + `edrUuid` internally, so callers never handle Tehtris UUIDs. The
first five (2026-09-08) are read-only posture; the last five (2026-09-29) were
requested by the airgapped-site team and bring file quarantine into UC16.

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

**`get processes` vs upstream's `list processes`:** upstream's action builds a
process *tree* around a seed process and requires both `pid` and `create_time`,
so it cannot answer "what ran on this host". `get processes` returns a listing,
needs no seed, and is bounded by `time_from`/`time_to`/`limit` plus optional
`username`/`path`/`cmdline`/`sha256` filters. Tehtris serves it through a
cursor; the action reads the first page, so `limit` caps the result.

**`get host detail` treats an unknown host as zero hosts (v1.2.1).** It is the
existence check a playbook runs first, so a hostname no endpoint carries exactly
is a *success* with `total_hosts` 0, empty data and the not-found reason as the
message; a failure means the call itself failed. Every other host-scoped action
still fails on an unknown host, before it sends anything.

**`get network info` is live network activity (`netstat`).** Until v1.2.0 it
called `/edr/v2/data/{applianceId}/{uuid}/network`, which the vendor reference
describes as the host's network *configuration* (`{data: object, timestamp}`),
so its `num_connections` was always 1. The reference names each netstat reply's
columns but does not list them; rows come back keyed by those column names.

**`get system info` is OS details only** — `name`, `type` (desktop/server),
`architecture`, `release`, `version` per the reference, whose `name` enum holds
only `windows`. A host on another OS may answer 501 (not implemented on the
endpoint).

**Quarantine and restore use different paths.** `quarantine file` takes the
file's path on the host. `restore file` takes the path the file has **in
quarantine** — Tehtris' reference says to use the paths `list quarantined files`
returns (`quarantinePaths`) — so a restore lists first, then restores; the
parameter is named `quarantine_path`, with its own `contains` type
(`tehtris quarantine path`) so the GUI only offers it for values that came from
the list. For the same reason the pair has no manifest `undo` link. `get file
info` is the natural check before quarantining (hashes, original name, product,
signature validity). `quarantine file`'s optional `notification` is passed as is
(Windows only; Tehtris does not document its format). All five are live calls:
the agent must be connected (504 otherwise).

## Fixes to upstream behaviour (12)

1. **Unguarded `response["data"][0]`.** Upstream indexed the inventory response
   unconditionally in **five** places, so an unknown or de-enrolled hostname
   raised `IndexError` and surfaced as an opaque connector failure. All five now
   route through one `_resolve_host()` helper that returns an explicit
   *"Host '<name>' was not found in the Tehtris EDR inventory"* error. Callers
   can distinguish "host does not exist" from "call failed" — UC16's design
   depends on that.
2. **`read_only` was `true` on write actions.** Upstream marked
   `send for isolation`, `remove from isolation`, `update tag` and
   `create app policy` as read-only. Corrected to `false`.
3. **Read-only actions typed as `contain`.** Upstream declared every action
   `contain`, including `get events` and `list processes`. Those two are now
   `investigate`, so the VPE groups them correctly.
4. **`create app policy` split its lists without trimming.** `"h1, h2"` looked
   up `" h2"` (leading space) and failed "host not found"; the same applied to
   `sha256`. Each item is now trimmed and empties dropped, and an empty list is
   a clear parameter error.
5. **`get events` never stopped paging on `limit` 0.** Paging ends on the first
   page shorter than `limit`, so a zero page size looped forever against the
   tenant. `limit` must now be a positive integer.
6. **Two malformed `get events` output datapaths.** `action_result.data.*.cmdline`
   was declared twice, and `action_result.data.threat.framework` lacked its `*`.
7. **A hostname could resolve to a different host.** The inventory's
   `hostname` filter matches **substrings** (vendor reference), and upstream
   used the first entry returned, so `ws-hr-07` could resolve to `ws-hr-070` —
   and *isolate it*. The pre-fix code, run against the rebuilt mock, reported
   the isolated `ws-hr-07` as not isolated because it read the wrong host.
   `_resolve_host()` now keeps only a case-insensitive **exact** match. Several
   exact matches (a re-installed agent keeps its hostname under a new uuid):
   a read uses the most recently seen endpoint, and the four **write actions
   refuse** and list the uuids, so an isolation never picks between endpoints
   on its own.
8. **Isolation replies.** Success is **204 with no body**; **202** means the
   agent is offline and the task is queued. Both are success, told apart by the
   new `summary.applied`. Errors carry the vendor's meaning of the status code
   (409 local proxy, 501 not implemented on the endpoint, 504 agent unreachable,
   422 rejected parameters).
9. **`create app policy` repeated appliance ids.** Two hosts on one appliance
   sent `appliances: [1, 1]`, which the reference forbids (`uniqueItems`);
   they are now de-duplicated. `order` is offered as the vendor enum
   (`WHITELIST`/`ANALYZE`/`RESUME`/`ALERT`/`KILL`/`QUARANTINE`), not free text.
10. **`get events` page size.** Upstream's parameter text said "Can not be
    greater than 100"; the reference's limit is **1000**, now enforced
    client-side (1 to 1000). Also: an empty (204) reply used to be counted as
    one record by the posture actions; it now counts as zero.
11. **`get events` host filter was exact and case-sensitive** while host
    resolution is case-insensitive, and Windows agents report upper-case
    hostnames — a lower-case input silently returned no events. It now uses the
    same exact, case-insensitive rule.
12. **No request timeout.** Upstream sent every call without `timeout=`, so a
    stalled appliance could hang an action indefinitely. Every call now has a
    30-second timeout (dev-rules FR-05's default) and reports it clearly. **Not
    yet done:** FR-05's *configurable* timeout (asset field), NFR-03's retry with
    backoff (`urllib3.Retry` on a `Session`, which would also carry
    `trust_env = False`), and 429 handling — the reference lists 429 on the
    inventory and processes calls, and SEKOIA's production Tehtris collector
    rate-limits to 5 requests/minute with retries. Tracked in the Splunk
    `docs/next-steps.md` UC16 tasks.

Also added per the repo checklist: `undo` pairing between
`send for isolation` ⇄ `remove from isolation`, `allow_list` on the
comma-separated `hostnames` and `sha256` parameters, and
`contains: ["host name"]` on the hostname parameters upstream left bare.

**`create app policy` scopes by appliance — confirmed by the reference.** The
request body carries `appliances` (required) and no per-endpoint field, so a
policy "for host X" covers **every endpoint on X's appliance**. Upstream
behaviour, kept; narrowing to one host would need a `Hostname` condition in the
rule, which the reference offers but this action does not build.

**`update tag` may overwrite.** The reference takes one tag string per call
(pattern `XXX_tags`: tenant trigram, underscore, tags) and does not say whether
it replaces or adds to the endpoint's tags. The action's description and result
say it may replace them: read the current tags with `get host detail` first.

## Contract source: the vendor OpenAPI reference

`tehtris_api_reference.json` (this folder, excluded from the package) is
Tehtris' own OpenAPI 3.0.2 document, **"TEHTRIS XDR Platform API"
v14.00.00.05** (250 paths, `servers: /api`, HTTP basic auth), supplied by the
user on 2026-09-29. It is not published anywhere public — the 2026-09-08 hunt
across the upstream repo and the FortiSOAR, Tracecat and THC implementations
found nothing. It settles:

- every endpoint path and method the connector calls, and their parameter
  names, types, required flags and enums (`tests/test_api_reference.py`
  checks them offline);
- the response shapes of inventory (`HostWebmListL`), isolation status
  (`IsolationStatus`, `status` boolean, required), process history and tree,
  system info, file info (`FileInfoData`), quarantine list and restore, live
  responses (`{columns, data}`) and app policy creation;
- the status codes above.

What the reference still leaves open, so every action keeps its `raw_json`
passthrough: the **events** endpoint declares no response schema (field names
come from its example alert, e.g. `hostname__`, integer `id`/`lvl`/`pid`);
netstat's and software's column names and row types; the keys inside inventory
`os`/`versions`; whether `update tag` replaces; how the process-history cursor
continues; the quarantine path format and what quarantining an absent file
answers.
Only a real tenant settles those — the remaining reconciliation debt.

## Asset configuration

| Field | Notes |
|---|---|
| `base_url` | **Must end in `/api`** — e.g. `https://<trigram>.api.tehtris.net/api`. The connector appends paths like `/edr/v2/inventory` with no prefix of its own, so omitting `/api` makes every action 404. "Trigram" is Tehtris' term for the per-tenant subdomain token. |
| `api_key` | API key generated in the tenant under *parameters → API keys*. Sent as HTTP basic auth with the username hardcoded to `api`. |
| `verify_server_cert` | Defaults to true (upstream v1.0.1 fix). |

The reference declares plain HTTP basic auth without naming the username; the
`api` username is corroborated by upstream's own code and by Swimlane's
independent implementation. FortiSOAR's sends username `Basic` instead, which
reads as a bug in that connector — if the real appliance rejects auth, this is
the first thing to vary, but check the asset config first (UC17 precedent: a
real-appliance 401 turned out to be password fields not surviving the air gap).

## Tests

`tests/` (excluded from the package) stubs the `phantom` modules and runs every
action through `handle_action` over real HTTP against `mock_tehtris.py`
(`soar8/migration/mock-backend/`, port 8448), plus manifest↔connector and
connector↔vendor-reference checks (88 tests). Since 2026-09-29 the mock follows
the vendor reference: substring inventory search, 204/202/201 replies, 422
validation errors, a duplicate hostname, an offline agent (504), a host behind
a local proxy (409), a Linux host (systemInfo 501), file info and software, and
a stateful quarantine (quarantine → list → restore by quarantine path). The live suite skips
itself when the mock is unreachable; point it elsewhere with
`TEHTRIS_MOCK_URL` (must end in `/api`).

```
uv run --python 3.13 --with pytest --with requests --with beautifulsoup4 \
    pytest connectors/tehtris/tests
```

A pristine upstream v1.0.1 checkout for diffing lives (gitignored) at
`reference_connectors/tehtris/`; re-create it with
`git clone https://github.com/splunk-soar-connectors/tehtris && git checkout 638383ec`.

## Status

- [x] Forked, extended, manifest and connector consistent
- [x] `mock_tehtris.py` (UC16 dependency D2), rebuilt 2026-09-29 against the
      vendor OpenAPI reference
- [x] Local suite: all 17 actions against the mock + reference checks (88 tests)
- [x] v1.1.0 packaged and installed on soar8 — app **201**, 12 actions
      registered; asset **`tehtris_mock`** (id 24, pointed at the mock's `:8448/api`)
- [x] v1.2.1 (v1.2.0's exact hostname match, netstat, isolation replies, 30 s
      timeout and five airgap-team actions, plus `get host detail`'s zero-hosts
      not-found) installed in place on soar8 2026-09-30 — app **201**, 17 actions
      registered, asset 24 still bound; the App Debugger's Test Connectivity loads
      it on Python 3.13.11 and stops at the firewall below
- [ ] Retry/backoff + 429 handling on a `Session` (dev-rules NFR-03/NFR-20),
      configurable timeout (FR-05)
- [ ] `test connectivity` on soar8 — blocked: the ansible controller's firewall
      does not admit soar8 on 8448 (`No route to host`); Ansible-project change
- [ ] Real-tenant check of what the reference leaves open (events fields,
      netstat/software columns, `update tag` semantics, quarantine paths)
