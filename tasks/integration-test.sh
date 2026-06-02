#!/usr/bin/env bash
#
# Offline golden-file integration test: audits the real-world manifests under
# testdata/integration/ and diffs zonar's JSON against the committed goldens.
#
# Hermetic — no network. The fixtures are refreshed from pinned upstream commits
# by tasks/refresh-integration-fixtures.sh (run by hand). This script runs in CI.
#
# Both sides are normalized through `python3 -m json.tool` so a failure produces
# a readable line-by-line diff rather than a single-line blob.
#
# Usage: zig build && ./tasks/integration-test.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZONAR="$ROOT/zig-out/bin/zonar"
CORPUS="$ROOT/testdata/integration"

[ -x "$ZONAR" ] || { echo "build zonar first: zig build" >&2; exit 1; }

REPOS="mach ghostty capy zap"
fail=0

for name in $REPOS; do
  dir="$CORPUS/$name"
  got="$("$ZONAR" audit "$dir/build.zig.zon" --cache "$dir/cache" --scan --fail-on=never --json \
    | python3 -m json.tool)"
  if diff <(printf '%s\n' "$got") "$dir/expected.json" >/dev/null; then
    echo "ok   $name"
  else
    echo "FAIL $name (zonar output differs from expected.json):"
    diff <(printf '%s\n' "$got") "$dir/expected.json" || true
    fail=1
  fi
done

# Sanity: the zero-dependency control must stay completely clean.
zap_info="$("$ZONAR" audit "$CORPUS/zap/build.zig.zon" --cache "$CORPUS/zap/cache" --json --fail-on=never \
  | python3 -c 'import json,sys; print(sum(json.load(sys.stdin)["summary"].values()))')"
if [ "$zap_info" != "0" ]; then
  echo "FAIL zap: expected a clean zero-finding audit, got $zap_info findings"
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "All integration fixtures match their goldens."
fi
exit "$fail"
