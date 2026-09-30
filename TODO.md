# Cleanup TODO

> **Internal.** This file names the lab and air-gap strings on purpose, so it can
> say what to remove. Do not copy it into a repo or package that is shared
> outside your team; delete it once the list is done.

Nothing in the code, JSON or packages has been changed yet. The notes that the
code comments carry are kept in [`docs/code-notes.md`](docs/code-notes.md), so
trimming the comments loses nothing. Line numbers are for commit `dd2ff0a`.

## 0. Decide first: where the lab detail may live

- [ ] The repo is **private**, 0 forks. The lab and air-gap context is in the
      current files **and** in the git history (two commits on `main`), plus inside the
      released `tehtris-v1.2.1.tgz`. No credentials, IPs, emails or internal URLs
      were found.
- [ ] Stay private and scrub forward (history keeps the old text), **or** start a
      new repo with one clean commit and re-publish the connector release there
      (deleting a repo also deletes its releases, PRs and Actions runs, so keep
      the `.tgz` first).

## A. Lab / air-gap strings to remove or generalise

Strings to look for: `soar8`, `tehtris_edr` (source env), `air-gapped` /
`airgapped`, `ansible`, ports `8446` / `8448`, `tehtris_mock*`, `/data/splunk`,
`soar-playbooks`, `UC16`, `dev-rules`, `FR-0x` / `NFR-xx`, app 201, asset ids 24/25.

- [ ] `HANDOVER.md` lines 1, 3, 6, 49 and `HANDOVER_french.md` lines 1, 3, 6, 53
      (title "Air-Gapped", "from `tehtris_edr` (source env: `soar8`)", the asset
      table). These files are generated, so fix the exporter's template too or
      the next refresh brings them back.
- [ ] `assets/tehtris_mock_8446.json`: file name, `name`, and the `note` ("LAB
      MOCK/TEST ASSET", "the air gap").
- [ ] `connectors/source/tehtris/README.md` (**also packed inside the `.tgz`**):
  - [ ] 4-5: "Consumed by UC16 (`soar-playbooks`, `docs/usecases/…`)". The path is
        also wrong, the plan is `docs/uc16_tehtris_edr_implementation_plan.md`.
  - [ ] 14-15, 21, 24, 101, 147-153: FR-01 / dev-rules / FR-05 / NFR-03
        references and `docs/next-steps.md`.
  - [ ] 34: "not installed on soar8".
  - [ ] 43: "requested by the airgapped-site team".
  - [ ] 217-224: mock backend path `soar8/migration/mock-backend/`, port 8448,
        `TEHTRIS_MOCK_URL`.
  - [ ] 238-251: the status log (app 201, asset 24, `:8448`, "No route to host",
        ansible controller firewall). This is a work log, not connector docs;
        move it out or delete it.
- [ ] `connectors/source/tehtris/tehtris.json`: line 4 `description` ends
      "extended for UC16"; decide on `publisher` "Ted" (13) and the upstream
      `contributors` entry (16).
- [ ] `connectors/source/tehtris/tehtris_consts.py` 39: "dev-rules FR-05".
- [ ] `docs/uc16_tehtris_edr_implementation_plan.md`: the whole file is the
      decision log and soar8 operations history (`soar8` x21, `8446` x8,
      `8448` x7, `airgapped` x7, `ansible` x7, `/data/splunk` x2, firewall
      notes). Keep it out of anything shared.
- [ ] Playbook (see C, VPE only): `(UC16 PB1)` in the description, tags
      `tehtris_edr` / `uc16`, asset name `tehtris_mock_8446` used 7 times.

## B. Connector code: scaffold and dead code (behaviour-neutral)

Comment and dead-code removal only; the vendor-quirk comments explain real
behaviour and stay (they are summarised in `docs/code-notes.md`).
`tehtris_connector.py`:

- [ ] 14-17: `#!/usr/bin/python` (not on line 1, so only a comment) and the
      "Phantom sample App Connector python file" banner; 19, 24 import headings;
      27-28 a commented-out import.
- [ ] 44, 49-51: `__init__` template comments.
- [ ] 71, 89, 101, 105, 126, 128, 139, 143, 151, 165: prose that restates the code
      or tells the template reader what to do ("Please specify the status codes
      here", "You should process the error returned in the json").
- [ ] 132-135: the proxy/HTML comment, down to two lines.
- [ ] 363, 366-369, 376, 385: `test connectivity` template comments.
- [ ] 389-390: unreachable comment and commented-out `Action not yet implemented`.
- [ ] 380-381, 430-431, 534-535, 571-572, 627-628: the same two lines, "the call
      to the 3rd party device or service failed…" / "for now the return is
      commented out…".
- [ ] 418 `# make rest call`, 516 `# Geting process tree`, 576 and 632
      `# When succeeded`, 585 commented-out `policy_name`, 593 and 604, 969.
- [ ] 1012-1013, 1016, and 1018-1026: a bare string of template examples inside
      `initialize()` (a no-op statement).
- [ ] 246-248: `_resolve_host` docstring tells the history of upstream's
      `response["data"][0]`. The current behaviour stays; the history is in the
      README, "Fixes to upstream" 1.

`tehtris_consts.py`: [ ] 14 "Define your constants here", [ ] 23 the
"Local extensions (fork of … v1.0.1)" banner, [ ] 39 (see A).

How to check it is behaviour-neutral: parse the file before and after, drop
docstrings and bare string statements, and compare the two ASTs; they must be
equal. Claude can apply this list and run that check on request.

Ship it:

- [ ] Rebuild `connectors/tehtris-vX.Y.Z.tgz` from `connectors/source/tehtris/`
      and bump `app_version` (suggested 1.2.2; `tehtris-v1.2.1` is already a
      published release, so the same version must not get different bytes).
- [ ] Update `HANDOVER.md` / `HANDOVER_french.md` Contents and the README
      `app_version` rows. Merging to `main` publishes the new release
      automatically (`RELEASING.md`).

## C. Playbook: VPE only, never by hand

The `.py` and the `.json` hold the same code (`globalCustomCode` at JSON line
790, plus one code string per block) and the JSON carries a `coa.data.hash` that
cannot be recomputed outside the VPE (it is not a SHA-1 of any part of the file
that was tried). So change these in the VPE, save, re-export, and let it rewrite
both files together.

- [ ] Remove the "Design notes" block, `tehtris_host_posture.py` 16-24 (now in
      `docs/code-notes.md`). Its pointer path `docs/usecases/…` is also wrong.
- [ ] 451: drop "Since connector v1.2.1" from the `check_host` comment.
- [ ] 28: "The target SOAR shows…" is fine technically; reword if "target" is
      too revealing.
- [ ] Description (py docstring line 2, JSON 789): drop "UC16 PB1". The `&#39;`
      in the docstring is the description's HTML-escaped apostrophe.
- [ ] Tags `tehtris_edr`, `uc16` (JSON 900-901).
- [ ] Re-point the 7 actions from `tehtris_mock_8446` to a neutral asset name
      (py 424, 546, 582, 622, 658, 694, 732; JSON 235, 386, 451, 518, 583, 648,
      714), then rename the asset template and the `HANDOVER*.md` table row to
      match.
- [ ] Leave the VPE-generated comments alone (listed in `docs/code-notes.md`).
- [ ] Rebuild `playbooks/tehtris_host_posture.tgz`; **re-pin `.gitleaksignore`**
      (its entries are line numbers in the playbook JSON, 205-683, and move when
      the JSON changes).
