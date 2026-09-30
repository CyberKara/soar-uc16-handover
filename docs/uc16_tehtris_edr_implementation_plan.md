# Tehtris EDR — Isolate + Security Posture (UC16) — Implementation Plan

**Status:** [x] planned | [ ] built | [ ] E2E validated | [ ] code review fixes | [ ] VPE polish | [ ] released

> **Design approved 2026-09-30 (Phase 1 gate cleared) — no playbook code yet.**
> The approved design is "Architecture" below (decisions 1–9, proposals P1–P5).
> Target environment: **soar8** (port 8443), SOAR **8.6.0.530**.

> **2026-09-29 — Tehtris' own OpenAPI reference is now in hand** (supplied by
> the user): "TEHTRIS XDR Platform API" v14.00.00.05, kept as
> `soar8/soar-connectors/connectors/tehtris/tehtris_api_reference.json`. It is
> the contract source from now on, replacing "the mock defines the contract"
> below. Measured against it (connector v1.2.0, mock rebuilt, 67 tests):
> - **Every endpoint and parameter the connector calls exists as called.** The
>   request side reconstructed from four implementations held up.
> - **Wrong-host bug, fixed:** the inventory's `hostname` filter matches
>   **substrings**, and the resolver took the first entry — `ws-hr-07` could
>   resolve to, and isolate, `ws-hr-070`. Now exact match only; a write is
>   **refused** when several endpoints share the hostname (re-installed agent).
> - **Gotcha 5 is gone:** `GET .../isolation` returns `{status: boolean}`, and
>   `get isolation status` exposes it, so PB2/PB3 can pre-check and verify.
> - **`get network info` now reads live `netstat`** (the `/data/.../network`
>   endpoint is network *configuration*); **`get system info` is OS details
>   only and Windows-only** (other OSes may answer 501).
> - **`update tag` may overwrite** the endpoint's tags, and the tag must follow
>   `XXX_tags` (trigram, underscore, tags) — PB2/PB3's `soar-isolated` /
>   `soar-released` tags do not; open design point below.
> - Still open in the reference: the events response schema, netstat column
>   names, tag replace-vs-append. Those need a real tenant.

## Session log

- **2026-08-12** — UC concept raised via `/kara-do-uc-create`: main goal is to
  isolate an asset via Tehtris EDR containment, while also pulling maximum
  security-posture information for that asset. User mentioned a Tehtris EDR
  connector available on GitHub (not present in this repo) and offered to send
  an OpenAPI/Swagger extract.
- **2026-09-08** — **API surface established without the user's extract.** The
  GitHub connector is identified as the official
  **[`splunk-soar-connectors/tehtris`](https://github.com/splunk-soar-connectors/tehtris)**
  (publisher Splunk, `app_version` 1.0.1, `python_version` "3.9, 3.13", last
  commit 2026-07-20). Its `tehtris.json` manifest + `tehtris_connector.py`
  source were read directly and are the authoritative record of what SOAR can
  call today (§API surface below). Tehtris' own Swagger is **not public** — it
  is served behind a login on the customer's own XDR tenant — so the broader
  API surface was corroborated from a second independent implementation, the
  [Swimlane Tehtris XDR connector](https://docs.swimlane.com/connectors/tehtris-xdr),
  which documents method + path for ten endpoints. Sekoia's Tehtris
  integration is ingestion-only (events → intake) and adds nothing for
  response actions.
- **2026-09-08 (later)** — **Deeper Swagger hunt: still not public** — no
  `swagger.json`/`openapi.json` is reachable anywhere, and a GitHub code search
  for a Tehtris spec returns nothing. It is served only from inside a logged-in
  tenant. **But a third independent implementation was found and read:**
  [`fortinet-fortisoar/connector-tehtris-edr`](https://github.com/fortinet-fortisoar/connector-tehtris-edr),
  which implements **43 operations** against this API and is effectively a
  reconstructed spec — far more complete than Swimlane's ten. It **supersedes
  Swimlane as the reference surface**, resolves open question (b), and changes
  the extension plan and PB1's flow (both revised below).

- **2026-09-29/30** — **Phase-1 reconciliation against connector v1.2.0** (as
  built, 17 actions) and the vendor reference: five errors in the 2026-09-08
  draft (time formats, not-found routing, prompt fallback, the `tehtris_edr`
  label, the tag write), the save-safe and note-size rules applied, and the
  offline-agent behaviour. The user decided label `*`, read–append–write-back
  tags, stop-with-a-note on an offline agent, and quarantine without restore
  in v1 (decisions 6–9), then approved P1–P5 — the Phase-1 gate is cleared.
  Connector v1.2.1 (P1) built, 88 tests green, installed on soar8 as app 201.

---

## API surface

### Auth / asset configuration

The connector asset takes three fields: `base_url` (Tehtris XDR base URL),
`api_key` (password-type field — the API key generated in the tenant under
*parameters → API keys*), and `verify_server_cert`. Swimlane's independent
implementation authenticates the same tenant API with **HTTP basic auth**,
username literal `api` + the API key as password — worth knowing if the Splunk
connector's header scheme ever mismatches the appliance.

Tenant base URL format (per Sekoia's client): `https://{tenant_id}.api.tehtris.net/api`.

**Two auth/config gotchas, both from comparing implementations:**

1. **The `/api` prefix belongs in `base_url`** — confirmed by three
   independent sources. Splunk's connector calls
   `self._base_url + "/xdr/v1/event"` (no prefix of its own); FortiSOAR's calls
   `server_url + "/api/xdr/v1/event"`; Sekoia's client hardcodes
   `https://{tenant_id}.api.tehtris.net/api`; and Tracecat's templates build
   `https://{trigram}.api.tehtris.net/api/edr/v2/...`. So the SOAR asset's
   `base_url` must already end in `/api` or **every action 404s**. Set it to
   `https://<trigram>.api.tehtris.net/api` — Tehtris' own name for the
   per-tenant subdomain token is **trigram**.
2. **Basic-auth username is `api`** — 2 clear votes, 1 outlier, 1 abstention.
   Splunk's connector hardcodes `auth=("api", <api_key>)` and Swimlane documents
   username `api` + generated API key. FortiSOAR sends
   `base64("Basic:" + <key>)` — username literally `Basic`, which reads as a bug
   in that connector. Tracecat abstains: it sends
   `Authorization: Basic <apikey>` where its stored `apikey` is already the
   pre-encoded credential blob, so it is consistent with either. **Go with
   `api`.** If the real appliance 401s on `test connectivity`, this is the first
   thing to vary — but note UC17's precedent, where a real-appliance 401 turned
   out to be asset config (password-type fields not surviving the air gap)
   rather than code.

### Actions upstream exposes (7)

> Historical baseline — the local fork now has 12. Kept because the gotchas
> below are properties of this upstream code.

All host-targeting actions take a plain **`hostname`** — the connector resolves
hostname → `uuid` + `applianceId` internally via `GET /edr/v2/inventory?hostname=`.
Playbooks never handle Tehtris UUIDs. This is the single most important design
fact: it keeps every block bindable straight off a CEF `sourceHostName`.

| SOAR action | Type | API call | Required params |
|---|---|---|---|
| `test connectivity` | test | — | — |
| `send for isolation` | contain | `POST /edr/v2/live/{applianceId}/{uuid}/isolation?isolationAction=enable` | `hostname` |
| `remove from isolation` | contain | `POST /edr/v2/live/{applianceId}/{uuid}/isolation?isolationAction=disable` | `hostname` |
| `get events` | contain | `GET /xdr/v1/event` | `from_date` (epoch), `hostname` |
| `list processes` | contain | `GET /edr/v2/data/{applianceId}/{uuid}/processes/tree` | `hostname`, `pid`, `create_time`, `number_of_parents`, `limit` |
| `update tag` | contain | `PUT /edr/v2/inventory/tags` | `hostname`, `tag` |
| `create app policy` | contain | `POST /edr/v2/policies/application` | `hostnames` (CSV), `sha256`, `order` |

Note every action is declared `actionType: contain` in the manifest, including
the read-only ones — cosmetic, but it means the VPE will not group them as
`investigate`.

### Connector gotchas found by reading the source

These are defects/behaviours in `tehtris_connector.py` v1.0.1 that the playbook
design has to absorb — none are documented in the app README.

1. **`list processes` is not "list running processes."** It builds a process
   **tree around a seed process** and every parameter is required — you must
   already know a `pid` and its `create_time`. There is no action that
   enumerates what is currently running on a host. The seed has to come from
   somewhere, and the only in-connector source is `get events`
   (`action_result.data.*.pid` + `action_result.data.*.pCreateDatetime`).
   Within the connector as published, that forces an ordering: `get events`
   first, then `list processes` seeded from an event's pid.
   **Superseded 2026-09-08 (later)** — the API does have a direct process
   listing, `GET /edr/v2/data/{applianceId}/{edrUuid}/processes`, time-filtered
   and needing no seed (FortiSOAR implements it as *get history of processes*).
   It is simply **not implemented** by the Splunk connector. Adding it (D1)
   removes this constraint rather than working around it, which is why PB1 no
   longer does the seed dance. An earlier draft of this doc proposed Swimlane's
   `GET /siem/{rid}/uba/v4/ueba/observe-running-modules` for this; that needed a
   separate SIEM `rid` and has been dropped in favour of the `/data/.../processes`
   endpoint on the identifier pair the connector already resolves.

- **2026-09-08 (later still)** — **Checked the Splunk vendor repo itself for a
  spec: it has none.** Exhaustively, not by top-level listing: all three
  branches (`main`, `next`, `next-archive`), all 10 commits, and both tags. The
  only files ever added are the manifest, connector, consts, icons and CI
  scaffolding — nothing was added-then-removed except a png→svg icon swap, and
  the 13 KB `README.md` is auto-generated connector documentation with **no link
  to Tehtris API docs at all**. The `next` branches are CI scaffolding only (no
  source). The same scan across `fortinet-fortisoar/connector-tehtris-edr`,
  `HakkYahud/tehcat` and `SkallZou/THC` found no spec file either. **Conclusion:
  no Tehtris OpenAPI/Swagger document exists in public anywhere** — the four
  connector implementations are the only map, and `tehtris.json`'s action
  manifest is the closest thing to a machine-readable partial spec.
  A **fourth** implementation was read in passing —
  [`HakkYahud/tehcat`](https://github.com/HakkYahud/tehcat) (Tracecat action
  templates) — which settles the auth question below and adds one endpoint,
  `GET /edr/v2/data/{applianceId}/{uuid}` (bare, "detail of a system").
- **2026-09-08 (D1 built)** — **classic-vs-SDK resolved by user instruction:**
  *"you must use the splunk soar tehtris edr connector as starting point"*. The
  connector was forked into `soar8/soar-connectors/connectors/tehtris/` at
  **v1.1.0** (fresh appid, display name *Tehtris EDR*), extended with the five
  read-only actions, and the three upstream bugs were fixed. Recorded as the
  **second standing FR-01 exemption** in `soar-connectors/docs/dev-rules.md`,
  on mergeability grounds. **D1 code is complete; D1 packaging is not** — see the
  dependency chain. Still no mock (D2) and nothing installed (D3), so nothing is
  runtime-verified yet.
2. **`get events` filters by hostname client-side, after paging.** The handler
   pages `/xdr/v1/event` with `limit`/`offset` and keeps only events whose
   `hostname__` equals the requested hostname, looping until a short page comes
   back. So `limit` is a **page size, not a result cap**, and a wide
   `from_date` on a busy tenant means many sequential REST calls inside one
   action. **Bound `from_date` tightly** (alert time minus a small window) or
   the action is slow and may time out.
3. **Unguarded `response.get("data")[0]`** in all four inventory-resolving
   handlers. An unknown/decommissioned hostname returns an empty `data` array
   and the action dies on `IndexError` — surfacing as an opaque connector
   failure, not a clean "host not found". **The design must not treat action
   failure as proof of anything**; validate the hostname first, or classify a
   failed isolate as "unknown outcome" and route to the analyst.
   **Fixed in D1** (`_resolve_host()`). **A worse trap in the same lookup, found
   2026-09-29 from the vendor reference:** the `hostname` filter matches
   **substrings**, so the first entry could be a different host (`ws-hr-070` for
   `ws-hr-07`). Fixed in v1.2.0: exact match only, writes refused on duplicates.
4. **No `on_poll`.** The connector cannot ingest — Tehtris can never create a
   container in SOAR. **The trigger must come from elsewhere** (SIEM/ES bridge
   or analyst-driven on an existing container). This settles the trigger half
   of the original open question #2: there is no Tehtris-native trigger path
   to choose.
5. **No isolation-status read.** `POST .../isolation` is fire-and-forget; the
   API's `GET .../isolation` (returns a boolean, per Swimlane) is **not
   exposed**. There is no way to pre-check whether a host is already isolated,
   and no way to confirm an isolation actually took effect. Only the POST's own
   success/failure is available.
   **Resolved:** D1 added `get isolation status`, and the vendor reference
   (2026-09-29) confirms the reply, `IsolationStatus {status: boolean}`. The POST
   answers 204 when applied and 202 when the agent is offline and the task is
   queued (`summary.applied`), 409 for a host behind a local proxy.

### Isolation semantics

Tehtris EDR isolation is **not a full network cut**: an isolated EDR Optimus
agent still accepts outbound flows to its management appliance, which is what
lets a SOC keep investigating a contained host. Practical consequence for the
design: **EDR enrichment continues to work after isolation**, so enrich-then-
isolate and isolate-then-enrich are both viable and the ordering can be chosen
on analyst-workflow grounds rather than technical necessity.

### Actions absent from the connector (candidates for extension)

Reconstructed from `fortinet-fortisoar/connector-tehtris-edr`'s 43 operations —
the fullest map of this API available without a tenant login. Only 7 of these
exist in `splunk-soar-connectors/tehtris`; everything below is **absent** and
would have to be added. Adding any is a **`soar8/soar-connectors` task, out of
scope for `/kara-do-uc-create`**.

Host-scoped endpoints all take the same `{applianceId}/{edrUuid}` pair the
connector already resolves from a hostname — so any of them can be exposed as a
clean `hostname`-only SOAR action, exactly like the existing seven.

**Tier 1 — posture core (what UC16 actually needs):**

| Action | API call | Why |
|---|---|---|
| get isolation status | `GET /edr/v2/live/{app}/{uuid}/isolation` | Pre-check + post-verify. Structural for an always-prompt containment UC. |
| get host detail | `GET /edr/v2/inventory` | Already called internally; exposing it gives OS, tags, groups, first/last-seen. Rich filter set: `hostname`, `hostnameRegex`, `domain`, `network`, `os`, `lastSeenFrom/To`, `uuids`, `applianceIds`. |
| **get processes** | `GET /edr/v2/data/{app}/{uuid}/processes` | **The real answer to "what is running."** Time-filterable (`timeFrom`/`timeTo`/`timeFilter`) and filterable by `pids`, `ppids`, `username`, `path`, `cmdline`, `sha256`/`sha1`/`md5`. **No seed pid required.** |
| get system info | `GET /edr/v2/live/{app}/{uuid}/systemInfo` | Live OS details — `name`/`type`/`architecture`/`release`/`version` per the vendor reference, whose `name` enum is Windows-only. |
| get network info | `GET /edr/v2/live/{app}/{uuid}/netstat` | Live network activity for the host — the natural companion to a process list when triaging. (Was `/data/.../network` until v1.2.0; the reference shows that one is network configuration.) |

**Tier 2 — deeper forensic posture:**

| Action | API call |
|---|---|
| get persistence entries (autostart) | `GET /edr/v2/data/{app}/{uuid}/autostart` |
| get connected users | `GET /edr/v2/data/{app}/{uuid}/users` |
| get user access logs | `GET /edr/v2/data/{app}/{uuid}/accesslogs` |
| get USB history | `GET /edr/v2/data/{app}/{uuid}/usb` |
| get browser security | `GET /edr/v2/data/{app}/{uuid}/browsers` |
| get software list | `GET /edr/v2/live/{app}/{uuid}/software` — **requested by the airgapped-site team, 2026-09-29 (D5)** |

**Tier 3 — response and hunting, beyond this UC:**

| Action | API call |
|---|---|
| quarantine file / list / restore | `POST`/`GET`/`PATCH /edr/v2/live/{app}/{uuid}/remediation/quarantine` — **moved INTO UC16 scope 2026-09-29 (decision 5, D5)** |
| disk scan: launch / status / current / stop | `POST`/`GET /edr/v2/live/{app}/{uuid}/scan-disk`, `GET`/`DELETE .../scan-disk/current` |
| offline forensics: start / stop / status / last report | `POST`/`DELETE`/`GET /edr/v2/live/{app}/{uuid}/tof`, `GET .../tof/lastReport` |
| appliance-wide search: binaries / accesslogs / autostart | `GET /edr/v2/search/{app}/{binaries,accesslogs,autostart}` |
| discover unmanaged hosts | `GET /edr/v2/discovery/{app}` |
| global policies list / create | `GET /edr/v2/policies/global/list`, `POST /edr/v2/policies/global` |
| event filters CRUD | `GET`/`POST`/`PUT`/`DELETE /xdr/v2/filter/filter[/{id}]` |
| set event status | `PUT /xdr/v1/event/status/{id}` |
| get tags | `GET /edr/v2/inventory/tags` |

FortiSOAR also ships a generic **`execute an api call`** passthrough (caller
supplies the endpoint). Tempting as a shortcut past all connector work, but it
is the opposite of this project's house style — untyped, unbindable in the VPE,
and invisible to anyone reading the playbook. **Not recommended**; noted only so
the option is on the record.

Two existing-but-unused actions are also worth folding into the design:
**`update tag`** (mark an isolated host in Tehtris' own inventory, giving a
cross-console audit trail without a new connector action) and
**`create app policy`** (block an offending sha256 across a host set — a
containment complement to isolation).

### What this changes

- **Open question (b) is resolved and the `rid` problem disappears.** Rank 3 was
  going to be Swimlane's `list running modules`
  (`GET /siem/{rid}/uba/v4/ueba/observe-running-modules`), which needed a SIEM
  appliance `rid` — a different identifier space, and the reason that action was
  flagged least certain. `GET /edr/v2/data/{app}/{uuid}/processes` does the same
  job on the `{applianceId}/{edrUuid}` pair the connector already resolves.
  **Drop `list running modules` from the plan entirely.**
- **Gotcha 1 stops being a design constraint.** The seed-pid dance existed only
  because `list processes` (tree) needs a seed. With `get processes` there is a
  direct, time-bounded process listing, so the tree becomes an optional
  drill-down rather than the primary process view.
- **Gotcha 2 gets a cheaper workaround.** `get events`' client-side hostname
  filtering is a property of Splunk's *connector*, not the API — the inventory
  endpoint filters server-side on `hostname`. Posture no longer has to lean on
  `get events` for host context, only for alert context.

---

## Decisions (user; 2026-09-08 unless dated)

| # | Question | Decision |
|---|---|---|
| 1 | Trigger path | **Analyst-driven data playbooks on an existing container.** No automation PB, no new trigger label, no ingestion. Matches UC17's shape. |
| 2 | Isolation gate | **Always an analyst prompt** — before isolate *and* before release. No severity-based auto-isolate. Chosen because isolation is disruptive and (gotcha 5) its effect cannot be confirmed after the fact. |
| 3 | v1 enrichment depth | **Gated on extending the connector first.** Build the three missing read actions (ranks 1–3) before any playbook work, rather than shipping around them. |
| 4 | Connector base | **Fork the official `splunk-soar-connectors/tehtris` app** — *"you must use the splunk soar tehtris edr connector as starting point"* (2026-09-08). It is classic `BaseConnector`, so the fork stays classic: converting to SDK would be a rewrite that permanently forks us from vendor fixes. Second standing FR-01 exemption. |
| 5 | File quarantine (2026-09-29) | **Included in UC16** — *"now quarantine is included"*. Requested by the airgapped-site team with `fileInfo` and `software`; moves `list quarantined files` / `quarantine file` / `restore file` out of Tier 3. Shape settled by decision 9; the approval gate and the path source are proposals under "Quarantine" in Architecture. |
| 6 | Label scope (2026-09-30) | **`*`** — offered on every container; the required `hostname` input is the check. Replaces the draft's `tehtris_edr`, which no container would ever carry. |
| 7 | Tehtris tag (2026-09-30) | **Read, append, write back** — read the host's current tag string with `get host detail`, add the marker in `<trigram>_…` form, write the whole string back with `update tag`. |
| 8 | Offline agent in PB2/PB3 (2026-09-30) | **Stop with a note before any prompt** ("agent not connected, nothing sent"). No `persist`, so nothing queues and runs unseen later. |
| 9 | Quarantine shape (2026-09-30) | **Quarantine now, restore later** — v1 builds only `tehtris_file_quarantine`; a restore is done from the Tehtris console for now. `restore file` stays in the connector, unused. |

Decision 2 was argued partly from gotcha 5, which no longer holds (isolation can
now be read and verified); the decision itself is the user's and stands.

Decision 3 means **UC16 playbook code is blocked** — see the dependency chain
below. Decision 2 makes the extension of rank 1 (`get isolation status`) not
merely nice-to-have but structural: the design pre-checks and post-verifies
isolation, and neither is possible with the connector as published.

## Blocking dependency chain

None of this is `/kara-do-uc-create` work — recorded here so the gate is
visible, and mirrored in `/data/splunk/docs/next-steps.md`.

| # | Dependency | Owner | Notes |
|---|---|---|---|
| D1 | Fork + extend the connector | `soar-connectors` project | **CODE DONE 2026-09-08.** `connectors/tehtris/` v1.1.0, appid `bf34e3e5-…`, display name *Tehtris EDR*: upstream's 7 actions + the 5 new read-only ones, 3 upstream bugs fixed, README with provenance, FR-01 exemption recorded. Manifest↔connector cross-checked (every action has a handler and a routing entry; no orphans; all params echoed; `versions: EQ(*)` everywhere). **NOT packaged, NOT installed, NOT runtime-tested** — needs `phenv compile_app -t` + `tools/install_app.sh`, which needs D2 first to have anything to talk to. |
| D2 | `mock_tehtris.py` | Splunk project | **REBUILT 2026-09-29 against the vendor OpenAPI reference** (substring inventory search, 204/202/201 replies, 422 validation, a duplicate hostname, an offline agent → 504, a local-proxy host → 409, Linux systemInfo → 501). First built **2026-09-08:** 596 lines on port **8448**, wired into `mock_start.sh` (`./mock_start.sh tehtris`) and the mock-backend README. All 10 endpoints exercised by curl: auth (missing header, wrong username), the `/api`-prefix 404 guard, events-as-array, inventory hit *and* empty-array miss, isolation read/write/verify/bad-action, systemInfo, processes with `username`/`sha256`/`limit` filters, process tree, network, tag PUT, policy POST. Isolation state is mutable, so pre-check → isolate → verify is testable end to end. |
| D2b | `mock-tehtris.service` + firewall exposure | **Ansible project** | **NOT DONE — now the ONLY blocker for D3 (2026-09-29).** Measured from soar8: 8443 connects, **8448 is refused** (`curl` rc 7 / `No route to host`); the controller's firewalld has rich rules admitting soar8 on 8443/8446/8447 only. Needs a matching 8448 rule. **Not yet filed in `/data/ansible/docs/next-steps.md`** (checked 2026-09-29) — this row was the only record. The other persistent mocks (8443, 8447) run as systemd units under `/etc/systemd/system/`, not via `mock_start.sh` — so without a unit the Tehtris mock only exists while someone runs it by hand. soar8 must also be able to reach port 8448 on the ansible host. Unit file should mirror `mock-efficientip-ddi.service` exactly (User/Group `klab`, WorkingDirectory the mock-backend dir, `--cert-dir …/certs`, `Restart=on-failure`). Creating it is an OS-layer change and therefore **not this project's to make**. |
| D3 | Package + install app on soar8, create asset, `test connectivity` green | Splunk project | **MOSTLY DONE 2026-09-29, last leg blocked on D2b.** Local: `connectors/tehtris/tests/` drives **all 12** actions over HTTP against the mock (38 tests green) and found 3 more upstream defects plus one mock-shape error, all fixed (connector README, "Fixes to upstream behaviour"). Later that day, after the vendor reference: **v1.2.0**, 67 tests green — **not yet packaged or installed; soar8's app 201 is still v1.1.0**, which has the wrong-host bug. soar8: `tools/build.sh` + `tools/install_app.sh` → **app 201**, `GET /rest/app_action?_filter_app=201` = 12; asset **`tehtris_mock`** (id 24, `base_url` `https://<ansible-host>:8448/api`, mock key, verify off). Test Connectivity through `/rest/debug_action/201` (the App Debugger path): the app loads and runs on Python 3.13.11 (asset + app config validated, state file created), then fails `[Errno 113] No route to host` — the firewall, not the connector. **To close:** install v1.2.0 (`tools/build.sh` + `tools/install_app.sh`); once 8448 is admitted, re-run Test Connectivity and the 12 actions on soar8 (needs a container for everything but `test connectivity`). **Update 2026-09-30: v1.2.1 installed in place** (app 201, 17 actions, asset 24 still bound; Test Connectivity loads it on Python 3.13.11, then `No route to host`). **Test Connectivity and all 17 actions PASS on soar8 2026-09-30** through asset `tehtris_mock_8446` (id 25; the mock hand-run on the already-admitted port 8446, user decision) — incl. v1.2.1's unknown host as zero hosts and a quarantine → list → restore round trip. Left: point the playbooks at `tehtris_mock` once D2b is done. |
| D4 | UC16 playbooks (this doc) | `/kara-do-uc-create` | Design approved 2026-09-30. Code can be written and deployed now; running any action on soar8 still needs D2b. |
| D5 | Connector actions for the airgapped-team request | `soar-connectors` project | **CODE DONE 2026-09-29** (connector v1.2.0, repo only — not yet installed; 17 actions, 87 tests green against the rebuilt mock, incl. a stateful quarantine → list → restore round trip and a restore by the original path shown to fail). `get file info` (`fileInfo`), `list software` (`software`), `list quarantined files` / `quarantine file` / `restore file` (`remediation/quarantine` GET/POST/PATCH); `netstat` and `systemInfo` already exist. Shapes and build notes: `/data/splunk/docs/next-steps.md`, entry "UC16 — airgapped-site team request". Mock routes + tests for each. |

### D1 — connector extension spec

**Revised 2026-09-08 (later)** after the FortiSOAR surface landed. Five new
actions, all read-only, all keyed on `hostname` so playbooks never touch Tehtris
UUIDs — preserving the property that makes this connector pleasant to bind
against. The connector already has the hostname→`{applianceId, uuid}` resolution
step; each of these reuses it.

| identifier | action | type | call | params | key outputs |
|---|---|---|---|---|---|
| `get_isolation_status` | get isolation status | investigate | `GET /edr/v2/live/{app}/{uuid}/isolation` | `hostname` (req) | `action_result.data.*.status` (bool), `summary.isolated` |
| `get_host_detail` | get host detail | investigate | `GET /edr/v2/inventory?hostname=` | `hostname` (req) | `uuid`, `applianceId`, `hostname`, `domain`, `tags` (one string), `firstSeen`, `lastSeen`, `localIp`, `remoteIp`, `configUuid`; `os`/`versions` are free-form objects (vendor `HostWebmL`) |
| `get_processes` | get processes | investigate | `GET /edr/v2/data/{app}/{uuid}/processes` | `hostname` (req), `time_from`, `time_to`, `limit`, opt `username`/`path`/`cmdline`/`sha256` | `data.*.pid`, `.ppid`, `.cmdline`, `.username`, `.created`, `.binaries.*.sha256` |
| `get_system_info` | get system info | investigate | `GET /edr/v2/live/{app}/{uuid}/systemInfo` | `hostname` (req) | `name`, `type`, `architecture`, `release`, `version` (Windows only) |
| `get_network_info` | get network info | investigate | `GET /edr/v2/live/{app}/{uuid}/netstat` | `hostname` (req) | one row per connection, keyed by the reply's column names (not listed in the reference) |

`list running modules` and its `rid` parameter are **dropped** — superseded by
`get_processes`, which needs no second identifier space. That was the one open
question blocking D1's scope; it is now closed.

Tier-1 minimum if the extension has to be cut short: `get_isolation_status` +
`get_host_detail` + `get_processes`. The first is structural (decision 2's
always-prompt gate pre-checks and post-verifies), the other two carry the
posture goal. `get_system_info` and `get_network_info` are cheap additions on
the same plumbing and should land in the same pass if possible.

Two fixes to fold in while there:

1. Guard `response.get("data")[0]` in all inventory-resolving handlers so an
   unknown hostname returns a clean "host not found" failure instead of an
   `IndexError` (gotcha 3). The playbook design depends on distinguishing
   "host does not exist" from "call failed".
2. Reclassify the read-only actions from `contain` to `investigate` in the
   manifest — cosmetic upstream, but it is what makes the VPE group them
   correctly.

### D1 — what is NOT known: response field names

> **Superseded 2026-09-29 by the vendor OpenAPI reference** (top of this doc).
> It gives schemas for inventory, isolation, processes, the process tree,
> system info and live responses; the mock and the connector's declared
> outputs now follow it. Still open: the events response (no schema, fields
> from its example alert), netstat column names, `update tag` replace-vs-append.
> The text below is the 2026-09-08 position, kept for the record.

**Every one of the five new actions has an unknown response shape.** This was
checked, not assumed: FortiSOAR's `info.json` declares `output_schema: {}` for
all five operations (it populates them at runtime from sample data via its
`generate_utcs` workflow), Swimlane documents response fields for only a couple
of endpoints, and no Swagger exists to fall back on. What *is* known:

| Action | Known response detail | Source |
|---|---|---|
| `get_isolation_status` | `status` (boolean) | Swimlane |
| `get_host_detail` | `data[]` array wrapper, each with `uuid` + `applianceId` | Splunk connector reads exactly these |
| `get_processes` | nothing | — |
| `get_system_info` | nothing | — |
| `get_network_info` | nothing | — |

Request-side is solid — exact query-parameter names are readable from
FortiSOAR's `operations.py` — so the actions can be *called* correctly. It is
only the parsing of what comes back that is unknown.

**Consequence: D2's mock defines the contract.** Whatever `mock_tehtris.py`
returns becomes what the connector's `output` datapaths declare and what PB1's
format blocks bind to. That is the same posture already accepted for UC13's
`ansible_api_ntw` and UC15's `itsm_generic` — a generic contract, swappable once
the real API shape is known — so it is a known and precedented risk rather than
a new one. But it carries a **reconciliation debt**: the field names must be
re-verified against a real Tehtris appliance before UC16 can be called
validated, exactly as UC17 still owes a real-appliance retest of its
analogy-based field names. Build every new action with a `raw_json` passthrough
fallback the way `efficientip_ddi` does, so a wrong guess degrades to "the data
is there under `raw_json`" rather than "the action returns nothing".

**Classic vs SDK — RESOLVED 2026-09-08 by user instruction** (*"you must use
the splunk soar tehtris edr connector as starting point"*): fork the vendor app,
stay classic. Recorded as the second standing FR-01 exemption. The reasoning
below is kept because it is the justification the exemption rests on, and
because the mergeability argument imposes an ongoing constraint — **do not
restructure the fork's filenames or layout for local taste, or the justification
evaporates.** The reading had cut both ways:

- **For SDK (the rule's letter):** FR-01 says *new connectors MUST use the SDK*,
  and its maintenance carve-out is enumerated **by name** — `cyberark_ccp`,
  `f5bigip_asm`, `proofpoint_trap`, `tenable_ad`, plus the `efficientip_ddi`
  exemption. Tehtris is not on that list; in this repo it would be a new
  connector.
- **For classic (recommended):** the upstream app already *is* classic
  `BaseConnector` and Apache-2.0. Converting it to SDK is a **rewrite**, not an
  extension, and it permanently forks us from upstream — no more pulling vendor
  fixes like the 1.0.1 TLS-verification fix. Extending it in place is
  maintenance-shaped work on someone else's maintained app. FR-01's own
  operational caveat also applies if UC16 ever follows UC1/UC2/UC17 to the
  airgapped site, where the App Debugger is the operator's only hands-on way to
  run an action and SDK apps cannot be dispatched there at all.

**Decided: classic**, on the fork-divergence argument rather than the App
Debugger one — the latter rests on 8.5 evidence that is itself pending an 8.6
retest (open item in `next-steps.md`). If that retest shows 8.6 fixed SDK
dispatch, the App Debugger half of this argument disappears but the
upstream-divergence half does not, so the exemption stands either way.

### D1 — what was actually built

`soar8/soar-connectors/connectors/tehtris/` — 10 files. Deltas from the spec
above, all deliberate:

- **`list running modules` never built** (dropped earlier — superseded by
  `get_processes`, no SIEM `rid` needed).
- **A third upstream fix was added** beyond the two specced: `read_only: true`
  was set on all four *write* actions upstream (`send for isolation`,
  `remove from isolation`, `update tag`, `create app policy`). Corrected.
- **Repo-checklist items upstream lacked** were added while there: `undo`
  pairing between `send for isolation` ⇄ `remove from isolation`, `allow_list`
  on the comma-separated `hostnames` parameter, and `contains: ["host name"]`
  on the hostname parameters.
- **The `_resolve_host()` consolidation** replaced **five** duplicated inventory
  lookups, not the four first counted — `create_app_policy` has one inside a
  loop. Fixing the guard in one helper rather than patching five copies is the
  root-cause fix; it also means the "host not found" error text exists once.
- **`get_processes`' declared output fields are inferred** from upstream's
  documented process-*tree* schema (`pid`, `ppid`, `cmdline`, `username`,
  `created`). Flagged as unconfirmed in the connector README; `raw_json` backs
  every action. **Confirmed 2026-09-29** by the vendor reference
  (`ProcessListWithCursorL`: the same fields, integer ids).

Not done, and blocking: packaging (`phenv compile_app -t`), install, and any
runtime test — all of which need D2, because there is nothing to point an asset
at. **No action in this connector has ever been executed.**

---

## Reconciliation against connector v1.2.0 (2026-09-29; decisions 2026-09-30)

Next-step 3. The architecture below was drafted on 2026-09-08, before the vendor
reference and before the save-safe rules of 2026-09-28/29. It was checked
against v1.2.0's manifest and handlers (`connectors/tehtris/`), the vendor
reference (`tehtris_api_reference.json`) and `docs/vpe-dev/constraints.md`.

**Wrong in the draft — fix before building:**

1. **Two time formats.** `get processes` takes `time_from`/`time_to` as ISO 8601
   date-time strings (vendor `format: date-time`); `get events` takes `from_date`
   as epoch seconds, no earlier than 43 days back. PB1's `compute_window` has to
   produce both — the draft said epoch for all of it. `get processes` also has a
   vendor `timeFilter` (`alive`/`created`/`stopped`, default `alive`) that the
   connector does not send, so the window means "alive during".
2. **`host_found?` cannot read a zero count.** On an unknown hostname
   `get host detail` *fails* the action (`TEHTRIS_ERR_HOST_NOT_FOUND`, or
   `TEHTRIS_ERR_HOST_NOT_EXACT` when only other hostnames contain it), exactly
   like an API error. **Proposal P1:** connector v1.2.1 makes a not-found
   `get host detail` succeed with `summary.total_hosts: 0`, so one decision routes
   found / not found / call failed (UC17 ends a not-found as `status: partial`,
   not an error). Only this read action; every other action keeps failing on an
   unknown host.
3. **The native prompt cannot fall back.** PB2/PB3's prompt uses approver
   `container_owner`, and a prompt block keeps no Custom Code. Following UC2
   PB4/PB5 (constraints.md, Exceptions): a code block raises `phantom.prompt2()`
   with the container owner, else `soar_local_admin`.
4. **Label `tehtris_edr` contradicts decision 1** ("no new trigger label").
   Nothing creates a container with that label (no `on_poll`), and a data
   playbook is only offered on containers carrying its label, so these playbooks
   would never be offered. A VPE save also resets a data playbook's label to `*`.
   **Decided: `*` (decision 6).**
5. **`update tag`** with a fixed `soar-isolated` would be rejected (422) and would
   replace the host's tags. **Decided: read, append, write back (decision 7)** —
   detail under PB2.

**Rules that now apply and the draft predates** (constraints.md):

- Save-safe blocks: logic only inside Custom Code, nothing in `on_start`,
  helpers in Global Custom Code, no label ending in "artifacts"/"container",
  `notRequiredJoins` on alternative-path joins, `requiredParameters` = the
  manifest's required fields only.
- Notes are markdown (`note_format="markdown"`) and at most 20,000 characters,
  split into "Title (k/N)" with UC2's `_note_parts()`. PB1's posture note will
  pass that (up to 500 processes, plus connections and software), so each
  section goes in its own part.
- Data playbooks declare inputs and outputs (already in the draft) and fill the
  outputs through the generated `output` dict.

**From the vendor reference, affecting the flow:**

- **Offline agent.** Every `/live/` call — isolation status and isolate/release,
  system info, netstat, software, file info, quarantine list/add/restore —
  answers 504 when the agent is not connected. The connector never sends
  `persist`, so a write on an offline host fails instead of queuing (202 needs
  `persist`). PB1 marks those sections "not available (agent offline)" and still
  writes its note. PB2/PB3: **stop with a note before any prompt (decision 8).**
- **Isolation power.** The connector sends no `power`, so Tehtris applies its
  default `soft` (the tenant's isolation policy); `hard` enforces isolation
  without that policy. v1 keeps `soft`. Ask the airgapped team alongside
  `persist`.
- **Duplicate hostname** (re-installed agent): reads use the most recently seen
  endpoint and log it; writes are refused with the list of uuids. PB2/PB3 put
  that message in the note and stop.
- **`list software` and `get network info` declare no columns** (`raw_json`
  only). PB1 renders both as tables built from the reply's own keys, and
  `list software` goes in PB1 (proposal P5).

**Still unknown until a real tenant** (reconciliation debt): events response
fields, netstat and software columns, the separator between tags in the tag
string (replace-vs-append is settled: the schema makes the tags one string that
a write replaces), and how soon
`get isolation status` reflects a 204 isolate — so PB2's verify must report
"applied by Tehtris, not yet confirmed", never "failed", when the read lags.

**Decisions A–D were put to the user and answered 2026-09-30** — rows 6–9 of
the Decisions table. Two answers differ from the recommendation: the tag is
kept (read, append, write back), and the quarantine flow ships without restore.

---

## Architecture (revised and approved 2026-09-30 — decisions 6–9, proposals P1–P5)

**4 data playbooks in v1 (+1 optional), 0 custom functions, 1 custom list,
label `*`** (decision 6). PB1 posture, PB2 isolate, PB3 release, PB5
`tehtris_file_quarantine` (decision 9); PB4 orchestrator stays optional. All
`playbook_type: "data"`, so none needs REST activation. No CFs (UC17 precedent).
The custom list `tehtris_edr_settings` is proposal P3 below.

Every playbook follows the save-safe rules (constraints.md): logic only inside
Custom Code; the first code block checks the inputs and stops the run with a
note when `hostname` (or PB5's `path`) is blank, so the playbook is safe to be
offered on every container; notes are markdown and at most 20,000 characters,
split with UC2's `_note_parts()`. A prompt is raised from a code block with
`phantom.prompt2()`, approver = the container owner, else `soar_local_admin`
(UC2 PB4/PB5 precedent, constraints.md Exceptions), 30-minute timeout.

**Proposals — all five approved by the user 2026-09-30** (the rest follows from
decisions 1–9):

| | Proposal |
|---|---|
| P1 | Connector **v1.2.1**: `get host detail` on an unknown hostname succeeds with `summary.total_hosts: 0` instead of failing, so PB1 can tell "not found" from "call failed". Only this action changes. **Built and installed 2026-09-30.** |
| P2 | One marker slot in the tag string: PB2 writes `soar-isolated` (replacing `soar-released` if present), PB3 swaps it back to `soar-released`. No accumulation within the 64-character limit. |
| P3 | Custom list `tehtris_edr_settings`, shipped empty, filled by the operator (UC2 `proofpoint_trap_excluded_senders` precedent): `tag_trigram` (needed only for a host with no tags yet) and `tag_separator` (blank = `,`, to be confirmed on a real tenant). |
| P4 | Quarantine: always prompt (decision 2 extended to quarantine), `path` is an analyst input, and decision 8's offline stop applies to it too. |
| P5 | `list software` goes in PB1 (posture). |

### PB1 — `tehtris_host_posture` (data)

Enrichment only; safe to run standalone and re-run. Answers "what is running on
the host".

- **inputs:** `hostname` (req), `lookback_minutes` (opt, default 60)
- **outputs:** `status`, `host_found`, `os`, `agent_last_seen`, `isolation_state`, `process_count`, `connection_count`, `software_count`, `event_count`, `summary`

```
on_start
 → [Code]     check_inputs       # hostname present; from lookback_minutes builds
                                 #   time_from/time_to (ISO 8601, for get processes)
                                 #   and from_date (epoch seconds, for get events)
 → [Action]   get_host_detail(hostname)          # P1: not found = success, total_hosts 0
 → [Decision] host_lookup
     failed        → [Code] note_lookup_failed → on_finish   # status=error, connector message verbatim
     total_hosts 0 → [Code] note_not_found     → on_finish   # status=not_found
     otherwise     → [Action] get_isolation_status(hostname)   # live
                   → [Action] get_system_info(hostname)        # live; Windows only (501 elsewhere)
                   → [Action] get_processes(hostname, time_from, time_to, limit 500)
                   → [Action] get_network_info(hostname)       # live
                   → [Action] list_software(hostname)          # live (P5)
                   → [Action] get_recent_events(hostname, from_date)
                   → [Code]   note_posture
 → on_finish
```

`note_posture` reads every action's status and writes "Posture: `<host>`"
(split "(k/N)" by section). A failed live call becomes "not available" with the
connector's message — an offline agent answers 504, a non-Windows host 501 on
system info — and never fails the playbook. `get host detail` and
`get processes` read the appliance's data and work while the agent is offline.
Connections and software have no declared columns, so their tables are built
from the reply's own keys. Several endpoints under one hostname: the reads use
the most recently seen one, and the note says so.

`get_recent_events` is for alert context only. Its `from_date` stays tightly
bounded (gotcha 2: the connector filters by hostname after paging). The
`list processes` tree remains an analyst drill-down, not part of v1.

**Built and tested 2026-09-30** — `playbooks/tehtris_edr/tehtris_host_posture`,
live on soar8 as playbook **246** (v2, `passed_validation` true, label `*`);
the usercode-sync, VPE-shape and SOAR-lint gates are clean (0 errors, 0
warnings). Implementation choices within the approved design, for review:

- The lookup routes through a code block `check_host` (found / not_found /
  failed, from `get host detail`'s status and `total_hosts`) and a native
  decision `host_found` with two branches; one code block `note_no_host`
  writes both the not-found and the failed-lookup note (`status` `not_found` or
  `error`). The draft had a three-way decision and two note blocks.
- Each table has a character budget (processes 9,000; connections, software,
  events 4,000 each); rows past it are counted as "N more … are in the action
  result". Whole sections are packed into notes of at most 20,000 characters,
  so a table is never split across parts ("Tehtris Posture: <host> (k/N)").
- `lookback_minutes`: default 60, at most 60,480 (42 days, inside Tehtris' 43-day
  events limit); anything else stops the run with a "Tehtris Posture - Error"
  note, as does a blank hostname.
- Every Tehtris value in the note is an inline code span (pipes escaped,
  backticks removed, cut at 200 characters), so markup and links in endpoint
  data stay inert.
- **Asset:** every action block selects `tehtris_mock_8446` (asset 25, the mock
  hand-run on the already-admitted port 8446, user decision 2026-09-30). Once D2b
  is done: switch the seven `connectorConfigs` to `tehtris_mock`, redeploy, and
  delete asset 25.

Test runs on container 1380, against the mock (all outputs as designed): a
known Windows host `success`; Linux `partial` (system info 501, OS from the
inventory); an offline agent `partial` (the four live sections "not available",
isolation `unknown`, processes and events still read); an unknown host and a
prefix-only name `not_found`; a duplicated hostname `success` with the "2
endpoints" line; a blank hostname and `lookback_minutes=abc` `error`; the mock
stopped → failed lookup `error` (SOAR marks that run `failed` because an action
failed — the outputs carry the outcome).

**VPE save test, 2026-09-30 — corrected.** The user saved id 246 in the VPE; it
became **version 3, id 247** (01:42:58Z). *A first note here said the save made no
new version: that comparison ran at ~01:37, before the save landed.* The save
kept every Custom Code section, the Global Custom Code, inputs/outputs, edges and
labels, so nothing broke; it rewrote the generated scaffold (116 lines): one more
rule line at each end of every Custom Code section, `save_block_result` lines for
the playbook inputs, action parameters in jsonb key order (shorter keys first),
`&#39;` in the module docstring, a computed `hash`, the start block's `y`, and
**outputs initialised to `[]` instead of `None`** — which silently disabled
`on_finish`'s `status is None` → `error` fallback (constraints.md). 247 is the repo
base since (user decision); `on_finish` now turns `[]` into null first; PB2 is
authored in the same generated form. Live after those fixes: PB1 **252**, PB2 **253**.

### PB2 — `tehtris_host_isolate` (data)

- **inputs:** `hostname` (req), `reason` (opt), `posture_summary` (opt — shown in the prompt)
- **outputs:** `status`, `isolation_requested`, `isolation_verified`, `tag_applied`, `analyst_response`, `message`

```
on_start
 → [Code]   check_inputs
 → [Action] pre_check_isolation(hostname)         # get isolation status (live)
 → [Code]   route_pre_check
     call failed (agent offline 504, unknown host, several endpoints)
                → note "nothing sent" + reason, return           # decision 8, status=not_sent
     isolated   → note "already isolated", return                # status=already_isolated
     not isolated → prompt2("Isolate host" / "Do not isolate", hostname, reason,
                    posture_summary), callback isolate_decision, return
 → [Code]   isolate_decision                      # prompt callback
     declined / expired → note, return            # status=declined / expired
 → [Action] send_for_isolation(hostname)
 → [Action] verify_isolation(hostname)            # get isolation status again
 → [Action] read_host_tags(hostname)              # get host detail: current tag string
 → [Code]   build_tag                             # decision 7, P2, P3
 → [Action] tag_isolated(hostname, tag)           # update tag; parameters set in its Custom Code
 → [Code]   note_result
 → on_finish
```

**Tag (decision 7).** A host's tags are **one string, at most 64 characters,
that must start with the tenant trigram and an underscore** (vendor `UpdateTags`:
`maxLength 64`, pattern `^<trigram>_[^%*]*$`), and `update tag` writes that whole
string — so a write replaces, and read–append–write-back is the only way not to
lose tags. `build_tag`:

- tags only when `verify_isolation` reports isolated; a lagging read is noted as
  "applied by Tehtris, not yet confirmed", not as a failure, and leaves the tag alone;
- current string non-empty → it already carries the trigram: remove
  `soar-released`, append `soar-isolated` with the separator (P2, P3);
- current string empty → `<tag_trigram>_soar-isolated`, the trigram from
  `tehtris_edr_settings`; not set → no write, noted;
- `soar-isolated` already present → no write (`tag_applied: already`);
- result over 64 characters → no write, noted; existing tags are never truncated.

`tag_isolated` skips itself by returning from its own Custom Code after calling
`note_result` directly (UC2 `comment_on_trap_incident` returns from an action
block's Custom Code the same way). The read–write is not atomic: a tag edited in
the Tehtris console between the two calls is overwritten — the note shows the
before and after strings.

Isolation is sent without `power` (Tehtris default `soft`, the tenant's isolation
policy) and without `persist`. A write on a hostname shared by several endpoints
is refused by the connector; the note lists their uuids.

### PB3 — `tehtris_host_unisolate` (data)

Mirror of PB2 with the same always-prompt gate (decision 2) and the same offline
stop (decision 8): `pre_check_isolation` (not isolated → note, stop) → prompt →
`remove_from_isolation` → `verify_isolation` → `read_host_tags` → `build_tag`
(swap `soar-isolated` for `soar-released`, P2) → `update tag` → note.

### PB4 — `tehtris_edr_response` (data, orchestrator) — optional for v1

Single entry point so an analyst launches one thing:

```
on_start → [Playbook] run_posture  (local/tehtris_host_posture, inputs: hostname)
        → [Playbook] run_isolate  (local/tehtris_host_isolate,
                                   inputs: hostname,
                                           posture_summary = run_posture:playbook_output:summary)
        → on_finish
```

Defer until PB1–PB3 are validated individually; it adds no capability, only
convenience.

### PB5 — `tehtris_file_quarantine` (data) — decision 9

Quarantine only; a restore is done from the Tehtris console for now, using the
quarantine path this playbook's note records (`restore file` takes the path *in
quarantine*, not the original).

- **inputs:** `hostname` (req), `path` (req, the file's path on the host — P4), `reason` (opt), `notification` (opt, message shown to the Windows user)
- **outputs:** `status`, `file_found`, `sha256`, `quarantined`, `quarantine_paths`, `analyst_response`, `message`

```
on_start
 → [Code]   check_inputs                          # hostname and path present
 → [Action] get_file_info(hostname, path)         # live
 → [Code]   route_file_info
     call failed (agent offline 504, unknown host, several endpoints)
                   → note "nothing sent", return  # decision 8 via P4
     file_found false → note "no such file", return
     found → prompt2("Quarantine file" / "Do not quarantine": path, sha256,
             originalFilename, productName, signature validity, reason),
             callback quarantine_decision, return # P4
 → [Code]   quarantine_decision
     declined / expired → note, return
 → [Action] quarantine_file(hostname, path, notification)
 → [Action] list_quarantined(hostname)            # list quarantined files
 → [Code]   note_result                           # every quarantine path, for a console restore
 → on_finish
```

The listing cannot be matched to the original path (the reply holds quarantine
paths only), so `quarantined` reflects `quarantine file`'s own result (204
applied; 409 conflict → failed) and the note shows the listing as evidence.

### Connector actions used

| Action | Used by |
|---|---|
| `get host detail` | PB1 (existence, OS, last seen), PB2/PB3 (current tag string) |
| `get isolation status` | PB1, PB2 (×2), PB3 (×2) |
| `get processes`, `get system info`, `get network info`, `list software`, `get events` | PB1 |
| `send for isolation` | PB2 |
| `remove from isolation` | PB3 |
| `update tag` | PB2, PB3 |
| `get file info`, `quarantine file`, `list quarantined files` | PB5 |

Not used in v1: `restore file` (decision 9), `list processes` (analyst
drill-down), `create app policy` (a second containment decision with its own
blast radius — its own design pass if ever wanted).

## Next step

**Phase 1 is done (design approved 2026-09-30) and connector v1.2.1 is live on
soar8. The one external blocker is D2b.**

1. **D2b (Ansible project): `mock-tehtris.service` + open port 8448 to soar8.**
   Until then every action on soar8 fails "No route to host" and the mock is
   hand-run only. Mirror `mock-efficientip-ddi.service`. Still not filed in
   `/data/ansible/docs/next-steps.md` (checked 2026-09-30) — an Ansible session
   has to file and do it.
2. **Phase 2 (D4):** PB1 **built and tested 2026-09-30**, saved-version repo base
   (above). PB2 `tehtris_host_isolate` **built 2026-09-30** (live id 253): the
   no-prompt paths pass (already isolated, offline, unknown host, blank); the
   prompt paths (approve → isolate → verify → tag, decline, proxy 409, shared
   hostname) are **not tested yet**, and custom list `tehtris_edr_settings` does not
   exist on soar8 yet. Next: PB2 → PB3 → PB5 (PB4 optional), plus the custom list
   `tehtris_edr_settings` (P3). `tehtris_edr` is in the three deploy-side lists
   (`deploy.py`, `pull_soar.py`, `snapshot.py`); `export_handover.py`'s registry
   waits for the user's export decision. Until D2b, test against the mock
   hand-run on port 8446 (asset `tehtris_mock_8446`, id 25) and stop it after.
3. **Once D2b is done:** switch the playbooks' action blocks from
   `tehtris_mock_8446` to `tehtris_mock`, redeploy, delete asset 25. Test
   Connectivity and all 17 actions already passed on soar8 through asset 25
   (2026-09-30), so D3 is closed apart from that switch.
4. **Ask the airgapped team** (one host is enough): the `tags` string
   `get host detail` returns for a host with two tags (gives the separator and
   the trigram), whether offline hosts need `persist`, and whether `power: hard`
   is ever wanted.
5. **Carry the reconciliation debt forward:** events response fields, netstat and
   software columns, the tag separator, and how soon `get isolation status`
   reflects an isolate need a real Tehtris tenant. UC16 cannot be called
   validated until then.
