# UC16 — Tehtris EDR (connector + host posture playbook) — Air-Gapped Handover Package

Generated 2026-09-30 19:14 UTC from `tehtris_edr` (source env: `soar8`).

This package is self-contained — everything needed to deploy this use case by hand
in an environment with no network access back to this repo or to `soar8`.

*(Version française : `HANDOVER_french.md` dans ce même dossier.)*

## Contents

| Path | What |
|------|------|
| `connectors/` | Connector app package(s): tehtris-v1.2.1.tgz |
| `connectors/source/` | Same connector(s), extracted — for reading, not for import |
| `playbooks/*.tgz` (PBs) | tehtris_host_posture |
| `playbooks/source/` | Same CFs/playbooks, extracted — for reading, not for import |
| `assets/*.json` | Asset config templates (credentials redacted — see below) |
| `docs/` | Implementation plan doc, for full design context |

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
   | `tehtris_mock_8446` | Tehtris EDR | `tehtris_host_posture` | `assets/tehtris_mock_8446.json` |

3. **Import the playbooks** from `playbooks/*.tgz`, via *Import Playbook* on the Playbooks
   page of the target SOAR GUI. (`playbooks/source/` is the same code extracted for reading — don't
   import from there, the GUI needs the `.tgz`.)
4. **Nothing to activate.** Every playbook in this package is an input (`data`)
   playbook — there is no automation trigger to enable and no **Run As** user to set.
   You run these by hand from a container: open the container, then Playbooks > Run
   Playbook and pick the one you want. See the implementation plan doc in `docs/`.

## Verification

1. **Check the connector first.** On the Tehtris EDR asset, run *Test Connectivity*, then run `get host detail` from the asset's action panel with the hostname of one real endpoint. An unknown hostname is not an error here: it succeeds with `total_hosts` 0 and says the host was not found. An HTTP 401 means the key or user is wrong; a 404 on every action means `base_url` does not end in `/api`.

2. **Then run `tehtris_host_posture`** from any container (Playbooks > Run Playbook). It asks for `hostname` (required) and `lookback_minutes` (optional, default 60). It writes a *Tehtris Posture: <host>* note: isolation state, OS, processes, live connections, installed software and recent events. It changes nothing on the endpoint. With the agent offline, the live sections read "not available" and the playbook still succeeds (status `partial`).

3. **Please report back** what the note shows for one endpoint that has two or more Tehtris tags (the *Tags* line), and the column names of the *Network connections* and *Installed software* tables. The vendor reference leaves those formats open, and the isolation playbook's tag handling depends on them.

## What was deliberately NOT exported

- Real credential values for any `password`-type config field (see step 2 above).
- Anything not explicitly listed in Contents above.
