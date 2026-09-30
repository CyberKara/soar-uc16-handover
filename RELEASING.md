# Releasing a connector version

Each `connectors/<name>-vX.Y.Z.tgz` gets a GitHub release (and tag) named
`<name>-vX.Y.Z`, with the `.tgz` attached. It is automatic:

1. A refresh adds `connectors/tehtris-vX.Y.Z.tgz` and lands on `main`.
2. `.github/workflows/release-connector.yml` runs and calls
   `scripts/release-connectors.sh`, which publishes every version that has no
   release yet. The tag points at the commit that first added that `.tgz`.

What it checks before publishing: the file name is `<name>-vX.Y.Z.tgz`, and the
`app_version` in `<name>/<name>.json` inside the package equals `X.Y.Z`. A
mismatch fails the run without publishing that version.

It only ever adds: versions that already have a release are skipped, so
re-running is harmless. To run it by hand, use *Actions > Release connector >
Run workflow*, or locally `DRY_RUN=1 scripts/release-connectors.sh` to see what
it would publish.

If a refresh replaces the old `.tgz` with the new one, the old release stays
on GitHub with its file attached. If a refresh rewrites the whole tree, keep
`.github/` and `scripts/`.
