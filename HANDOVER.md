# UC16 — Tehtris EDR (connector + 5 playbooks) — Air-Gapped Handover Package

Generated 2026-10-10 22:00 UTC from `tehtris_edr` (source env: `soar8`).

This package is self-contained — everything needed to deploy this use case by hand
in an environment with no network access back to this repo or to `soar8`.

*(Version française : `HANDOVER_french.md` dans ce même dossier.)*

## Contents

| Path | What |
|------|------|
| `connectors/` | Connector app package(s): tehtris_edr-v1.2.4.tgz |
| `connectors/source/` | Same connector(s), extracted — for reading, not for import |
| `playbooks/*.tgz` (PBs) | tehtris_host_posture, tehtris_host_isolate, tehtris_host_unisolate, tehtris_file_quarantine, tehtris_edr_response |
| `playbooks/source/` | Same CFs/playbooks, extracted — for reading, not for import |
| `assets/*.json` | Asset config templates (credentials redacted — see below) |
| `custom_lists/*.json` | Custom lists — the rows this package defines, never the source's data rows (see the custom-list section below) |
| `docs/` | Implementation plan doc, for full design context |

## [!] Upgrading over an earlier install — read this first

These apply only if this app is already installed on the target from a
previous package. On a completely fresh target, skip to Install order.

- **From the first package (connector v1.2.1 + `tehtris_host_posture` only):** install connector v1.2.2 over the existing Tehtris EDR app, a normal in-place upgrade; the asset and its API key stay as they are. v1.2.2 adds the optional asset field `timeout` (seconds per API call, 1-300; empty = 30, the old fixed value) and retries a read or a tag write up to three times when Tehtris answers 429, 500, 502 or 503; an isolation, release or quarantine request is never sent twice. `tehtris_host_posture` is unchanged: keep it, import the four new playbooks and create the custom list `tehtris_edr_settings`. The new playbooks name the asset `tehtris_mock` (the first package said `tehtris_mock_8446`): re-point their action blocks to your Tehtris asset in the VPE and save, as for the first package.

- **Connector 1.2.4 and shorter texts (2026-10-10).** Install `tehtris_edr-v1.2.4.tgz` over the existing Tehtris EDR app: the package now carries the name `tehtris_edr`, but it is the same app (same identifier), so it upgrades in place and the asset keeps its API key. Its action help texts are shorter; the four write actions now say only that `summary.applied` is false when Tehtris answers 202 (queued). Nothing else changes. Re-import the five playbooks: their descriptions, block descriptions and comments are shorter, their behaviour is unchanged. Then re-point the action blocks of `tehtris_host_posture`, `tehtris_host_isolate`, `tehtris_host_unisolate` and `tehtris_file_quarantine` to your Tehtris asset in the VPE and save. The implementation plan in `docs/` now describes the current design only, with a Setup Guide.

## Install order

1. **Install the connector app(s)** — Apps > Install App, upload each file in `connectors/`.
   (`connectors/source/` is the same code extracted for reading — don't import from there,
   the GUI needs the `.tgz`.)
2. **Configure assets from the templates in `assets/`** — Apps > Configure New Asset for
   each. Fields marked in a template's `redacted_fields` list are placeholders
   (`<<SET ME...>>`) — **you must fill these in yourself**; they were never exported
   with usable values. Two different reasons appear in that list, and each placeholder
   says which one applies:

   - **Secrets** (passwords, API keys, certificates/keys) — take these from your own
     vault/CMDB. SOAR encrypts `password`-type fields at rest, so the export process
     cannot read them back in usable form even in principle.
   - **Identities and addresses** (usernames, client/app ids, endpoint URLs) — these
     are not secret, but they belonged to the source environment and are meaningless
     here. Enter the values *your* target system expects. **An identity must match the
     credential you enter beside it** — a real password paired with a leftover username
     from the source environment authenticates as nothing and returns HTTP 401.

   **The playbooks ship pointed at the asset names below.** Either create your assets
   with these names, or keep your own names and re-point each playbook's action blocks
   to your assets in the VPE, then save: every playbook in this package is built to
   survive a save. (A save makes a manually-run playbook available on every container
   label; re-importing it restores the label.)

   | Asset name | App | Used by | Template |
   |---|---|---|---|
   | `tehtris_mock` | Tehtris EDR | `tehtris_file_quarantine`, `tehtris_host_isolate`, `tehtris_host_posture`, `tehtris_host_unisolate` | `assets/tehtris_mock.json` |

3. **Create the custom list(s)** from `custom_lists/*.json` — each file has the exact
   `content` array (the rows this package defines — never the source's data rows) to POST to `/rest/decided_list`:
   ```bash
   curl -sk -u '<user>:<password>' -X POST https://<target>:<port>/rest/decided_list \
     -H 'Content-Type: application/json' \
     -d @custom_lists/<list_name>.json
   ```
   (the file's top-level shape is `{"name": ..., "content": [...]}` — matches the REST
   payload directly.)
4. **Import the playbooks** from `playbooks/*.tgz`, via *Import Playbook* on the Playbooks
   page of the target SOAR GUI. (`playbooks/source/` is the same code extracted for reading — don't
   import from there, the GUI needs the `.tgz`.)
5. **Nothing to activate.** Every playbook in this package is an input (`data`)
   playbook — there is no automation trigger to enable and no **Run As** user to set.
   You run these by hand from a container: open the container, then Playbooks > Run
   Playbook and pick the one you want. See the implementation plan doc in `docs/`.

## Custom lists you fill in

Settings the playbooks read. Create them (step above), then fill them in as each list's
description below says, when you need them; the use case works with them left as shipped.

- `tehtris_edr_settings`: two settings `tehtris_host_isolate` and `tehtris_host_unisolate` read when they tag an endpoint. Each row is a key (column 1) and its value (column 2); there is no header row. `tag_trigram`: your tenant's three-letter tag prefix (for example `FIN`), used only for an endpoint that has no tag yet, which then gets `<trigram>_soar-isolated`; left empty, such an endpoint is isolated but not tagged, and the note says so. `tag_separator`: the character between tags inside the tag string; empty means a comma. An endpoint's tags are one string of at most 64 characters, and the playbooks append `soar-isolated` / `soar-released` to it, never cut it: a result over 64 characters is not written.

## Verification

1. **Check the connector first.** On the Tehtris EDR asset, run *Test Connectivity*, then run `get host detail` from the asset's action panel with the hostname of one real endpoint. An unknown hostname is not an error here: it succeeds with `total_hosts` 0 and says the host was not found. An HTTP 401 means the key or user is wrong; a 404 on every action means `base_url` does not end in `/api`.

2. **Then run `tehtris_host_posture`** from any container (Playbooks > Run Playbook). It asks for `hostname` (required) and `lookback_minutes` (optional, default 60). It writes a *Tehtris Posture: <host>* note: isolation state, OS, processes, live connections, installed software and recent events. It changes nothing on the endpoint. With the agent offline, the live sections read "not available" and the playbook still succeeds (status `partial`).

3. **Isolate and release one TEST endpoint.** Run `tehtris_edr_response` (posture, then isolation) or `tehtris_host_isolate` with that endpoint's `hostname`, then `tehtris_host_unisolate`. Nothing is sent before an approval prompt is answered: it goes to the container owner, or to `soar_local_admin` when the container has none, and expires after 30 minutes. Each run writes a *Tehtris Isolation: <host>* or *Tehtris Release: <host>* note, checks the result by reading the isolation state back, and appends `soar-isolated` / `soar-released` to the endpoint's tags. An offline agent stops the playbook with a note, nothing sent. `tehtris_edr_response` starts the other two by name from the `local` repository; if the VPE shows its two playbook blocks unconfigured, pick the two playbooks again in them and save.

4. **Quarantine one TEST file** with `tehtris_file_quarantine`: `hostname`, the file's full path on the endpoint (Windows: drive letter and backslashes), optionally `reason` and `notification` (text shown to the Windows user). The prompt shows the file's SHA-256, original name, product and signatures. The *Tehtris Quarantine: <host>* note lists the endpoint's quarantine paths: restore a file from the Tehtris console with that path (the path in quarantine, not the original one).

5. **Please report back** what the posture note shows for one endpoint that has two or more Tehtris tags (the *Tags* line: it gives the tag separator and your trigram), the column names of the *Network connections* and *Installed software* tables, whether offline endpoints should have requests queued until they reconnect, whether `hard` isolation is ever wanted (the playbooks use the tenant's default), and how you use the quarantine `notification`. The vendor reference leaves those open.

## What was deliberately NOT exported

- Real credential values for any `password`-type config field (see step 2 above).
- The source environment's own target assets and any custom-list rows — those are
  lab-specific test data, not your infrastructure. See the custom-list section above.
- Anything not explicitly listed in Contents above.
