#!/usr/bin/env bash
#
# Remove paynym-bot. Prints what it would do unless --apply is given.
#
#   ./uninstall.sh                          show the plan, change nothing
#   sudo ./uninstall.sh --apply             stop serving; keep wallet and data
#   sudo ./uninstall.sh --apply --purge-data    also delete the data directory
#   sudo ./uninstall.sh --apply --purge-onion   also delete the onion key
#
# Like install.sh, this resolves Node before escalating, because sudo's
# secure_path will not find a Node installed under ~/.nvm, ~/.local or /opt.

set -euo pipefail
cd "$(dirname "$0")"

NODE_BIN="$(command -v node || true)"
[ -z "$NODE_BIN" ] && { echo "Node.js not found on PATH." >&2; exit 1; }

APPLY=0
for arg in "$@"; do [ "$arg" = "--apply" ] && APPLY=1; done

if [ "$APPLY" -eq 0 ] || [ "$(id -u)" -eq 0 ]; then
  exec "$NODE_BIN" --experimental-strip-types --no-warnings scripts/uninstall.ts "$@"
fi
exec sudo -- "$NODE_BIN" --experimental-strip-types --no-warnings scripts/uninstall.ts "$@"
