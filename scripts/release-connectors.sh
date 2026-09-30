#!/usr/bin/env bash
# Publish a GitHub release for every connector package that has none yet.
#
# Packages are connectors/<name>-v<X.Y.Z>.tgz. Each one becomes release/tag
# <name>-v<X.Y.Z> with the .tgz attached. Safe to re-run: versions that already
# have a release are skipped, so it only ever adds.
#
#   DRY_RUN=1 scripts/release-connectors.sh    # list what would be published
#
# Needs gh (GH_TOKEN set), git, tar, python3. Run from CI (.github/workflows/
# release-connector.yml) or by hand from a checkout with full history.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
DRY_RUN=${DRY_RUN:-0}
notes=$(mktemp)
trap 'rm -f "$notes"' EXIT

# Oldest first, so the newest version is created last and ends up "Latest".
mapfile -t packages < <(compgen -G 'connectors/*-v*.tgz' | sort -V || true)
if [[ ${#packages[@]} -eq 0 ]]; then
    echo "No connector packages found in connectors/."
    exit 0
fi

failed=0
for pkg in "${packages[@]}"; do
    base=$(basename "$pkg" .tgz)
    name=${base%-v*}
    version=${base##*-v}
    tag=$base

    if [[ ! $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "::error file=$pkg::Version '$version' in the file name is not X.Y.Z"
        failed=1
        continue
    fi

    # The file name is what names the tag, so it must agree with the app itself.
    if ! manifest=$(tar -xOzf "$pkg" "$name/$name.json" 2>/dev/null); then
        echo "::error file=$pkg::Expected $name/$name.json inside the package"
        failed=1
        continue
    fi
    app_version=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["app_version"])' <<<"$manifest")
    app_name=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["name"])' <<<"$manifest")
    if [[ $app_version != "$version" ]]; then
        echo "::error file=$pkg::File name says $version but $name.json has app_version $app_version"
        failed=1
        continue
    fi

    # Tag the commit that introduced this package, so a backfill points at the
    # right history instead of the tip. Falls back to HEAD on a shallow clone.
    target=$(git log --diff-filter=A --format=%H -n 1 -- "$pkg")
    target=${target:-$(git rev-parse HEAD)}

    if [[ $DRY_RUN == 1 ]]; then
        echo "[dry run] would publish $tag ($app_name v$version) at ${target:0:8}"
        continue
    fi

    if out=$(gh release view "$tag" 2>&1); then
        echo "$tag: release exists, skipping"
        continue
    elif [[ $out != *"release not found"* ]]; then
        echo "::error::Could not check for release $tag: $out"
        failed=1
        continue
    fi

    {
        echo "$app_name connector **v$version**."
        echo
        echo "Install: Apps > Install App, upload \`$base.tgz\`."
        if [[ -d connectors/source/$name ]]; then
            echo
            echo "Readable source: \`connectors/source/$name\` at this tag."
        fi
        echo
        echo "SHA-256: \`$(sha256sum "$pkg" | cut -d' ' -f1)\`"
    } >"$notes"

    echo "$tag: publishing ($app_name v$version at ${target:0:8})"
    gh release create "$tag" "$pkg" \
        --target "$target" \
        --title "$app_name connector v$version" \
        --notes-file "$notes" || failed=1
done

exit "$failed"
