#!/usr/bin/env bash
#
# Offline golden-file integration test: audits the real-world manifests under
# testdata/integration/ and diffs zonar's JSON against the committed goldens.
#
# Hermetic: no network, no external tools beyond the standard shell. The
# fixtures are refreshed from pinned upstream commits by
# tasks/refresh-integration-fixtures.sh (run by hand). This script runs in CI.
#
# Goldens hold zonar's exact `--json` output (compact), so the comparison is a
# plain `diff`. On a mismatch the diff is a single line; regenerate with the
# refresh tool and `git diff` to inspect a behavioral change.
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
  got="$("$ZONAR" audit "$dir/build.zig.zon" --cache "$dir/cache" --scan --fail-on=never --json)"
  if printf '%s\n' "$got" | diff - "$dir/expected.json" >/dev/null; then
    echo "ok   $name"
  else
    echo "FAIL $name (zonar output differs from expected.json):"
    printf '%s\n' "$got" | diff - "$dir/expected.json" || true
    fail=1
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "All integration fixtures match their goldens."
fi
exit "$fail"
