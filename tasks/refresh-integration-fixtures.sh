#!/usr/bin/env bash
#
# Regenerates the testdata/integration corpus from pinned upstream commits.
#
# This script is NETWORK-DEPENDENT and meant to be run by hand when bumping the
# pinned commits below — it is deliberately NOT part of CI. The fixtures it
# produces are audited offline by tasks/integration-test.sh.
#
# It fetches each repo's real build.zig.zon at a pinned commit, vendors the two
# files zonar actually reads (build.zig + build.zig.zon) for the handful of deps
# we want resolved rather than `not_in_cache`, and regenerates the golden JSON.
# We use curl/raw + the dep's own committish rather than `zig fetch`, which is
# unreliable for this (cwd-sensitive, won't unpack into a custom cache dir).
#
# Usage: zig build && ./tasks/refresh-integration-fixtures.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZONAR="$ROOT/zig-out/bin/zonar"
CORPUS="$ROOT/testdata/integration"

[ -x "$ZONAR" ] || { echo "build zonar first: zig build" >&2; exit 1; }

# Pinned upstream commits. Bump deliberately; each repo's SOURCE file records
# the value used so the corpus is reproducible.
MACH_REPO="hexops/mach";            MACH_SHA="4be8e50fc89a532878887dba002f590cc50d8e89"
GHOSTTY_REPO="ghostty-org/ghostty"; GHOSTTY_SHA="5758e149319d244cbf2d21d1ae8d1376adaf1f91"
CAPY_REPO="capy-ui/capy";           CAPY_SHA="fd77077e296a969ae258c595e75a0723183b3138"
ZAP_REPO="zigzap/zap";              ZAP_SHA="f6099ecec496c7ec623c5913baa5b6b5da2e883d"

# zigimg, capy's git dependency. ZIGIMG_SHA and ZIGIMG_HASH must match the
# committish and `.hash` in capy's own build.zig.zon (the hash is the cache
# directory name zonar looks for) — when bumping CAPY_SHA, re-check both against
# capy's manifest, or the vendored package silently resolves as `not_in_cache`.
ZIGIMG_REPO="zigimg/zigimg"
ZIGIMG_SHA="74caab5edd7c5f1d2f7d87e5717435ce0f0affa1"
ZIGIMG_HASH="zigimg-0.1.0-8_eo2nWlEgCddu8EGLOM_RkYshx3sC8tWv-yYA4-htS6"

raw() { curl -fsSL "https://raw.githubusercontent.com/$1/$2/$3"; }

# fetch_manifest <name> <repo> <sha>
fetch_manifest() {
  local name="$1" repo="$2" sha="$3" dir="$CORPUS/$1"
  echo "  $name: build.zig.zon @ ${sha:0:12}"
  mkdir -p "$dir"
  raw "$repo" "$sha" build.zig.zon > "$dir/build.zig.zon"
  printf '%s @ %s\n' "$repo" "$sha" > "$dir/SOURCE"
}

# vendor <name> <dest-rel> <repo> <sha> <src-prefix>
# Copies build.zig + build.zig.zon for a dep into the fixture so it resolves.
vendor() {
  local name="$1" dest="$CORPUS/$1/$2" repo="$3" sha="$4" prefix="$5"
  echo "  $name: vendoring $2 from $repo@${sha:0:12}"
  mkdir -p "$dest"
  raw "$repo" "$sha" "${prefix}build.zig"     > "$dest/build.zig"
  raw "$repo" "$sha" "${prefix}build.zig.zon" > "$dest/build.zig.zon"
}

# regen_golden <name>
regen_golden() {
  local name="$1" dir="$CORPUS/$1"
  echo "  $name: regenerating expected.json"
  "$ZONAR" audit "$dir/build.zig.zon" --cache "$dir/cache" --scan --fail-on=never --json \
    > "$dir/expected.json"
}

echo "Refreshing integration corpus under $CORPUS"

fetch_manifest mach    "$MACH_REPO"    "$MACH_SHA"
fetch_manifest ghostty "$GHOSTTY_REPO" "$GHOSTTY_SHA"
fetch_manifest capy    "$CAPY_REPO"    "$CAPY_SHA"
fetch_manifest zap     "$ZAP_REPO"     "$ZAP_SHA"

# capy: vendor its git dependency (modern hash, immutable commit) so we exercise
# a fully resolved + scanned node alongside the two legacy-hash deps.
vendor capy "cache/p/$ZIGIMG_HASH" "$ZIGIMG_REPO" "$ZIGIMG_SHA" ""

# ghostty: vendor two path dependencies so the `.path = "./pkg/..."` branch
# resolves and scans. wuffs is a clean C shim (no capabilities); gtk4-layer-shell
# runs `wayland-scanner` via addSystemCommand, so --scan flags a real cap_exec.
vendor ghostty "pkg/wuffs" "$GHOSTTY_REPO" "$GHOSTTY_SHA" "pkg/wuffs/"
vendor ghostty "pkg/gtk4-layer-shell" "$GHOSTTY_REPO" "$GHOSTTY_SHA" "pkg/gtk4-layer-shell/"

for name in mach ghostty capy zap; do
  regen_golden "$name"
done

echo "Done. Review the diff and commit testdata/integration."
