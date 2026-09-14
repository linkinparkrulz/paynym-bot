#!/usr/bin/env bash
#
# Guided installer for paynym-bot.
#
# This is only a launcher. It resolves the Node binary belonging to the invoking
# user BEFORE escalating, because sudo's secure_path excludes ~/.nvm, ~/.local
# and /opt — so "sudo ./install.sh" would otherwise fail to find a Node that is
# plainly on the user's PATH. All real work happens in scripts/install.ts.

set -euo pipefail

MIN_MAJOR=22
cd "$(dirname "$0")"

NODE_BIN="$(command -v node || true)"
if [ -z "$NODE_BIN" ]; then
  cat >&2 <<'MSG'
Node.js is not installed, or is not on your PATH.

Debian/Ubuntu packages are usually too old. Install a current release:

  sudo apt-get install -y ca-certificates curl gnupg
  sudo mkdir -p /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" \
    | sudo tee /etc/apt/sources.list.d/nodesource.list > /dev/null
  sudo apt-get update && sudo apt-get install -y nodejs
MSG
  exit 1
fi

MAJOR="$("$NODE_BIN" -p 'process.versions.node.split(".")[0]')"
if [ "$MAJOR" -lt "$MIN_MAJOR" ]; then
  echo "Node ${MIN_MAJOR}+ is required (found $("$NODE_BIN" -v))." >&2
  echo "paynym-bot runs TypeScript directly via --experimental-strip-types." >&2
  exit 1
fi

# --dry-run needs no privileges: it only prints what a real run would do.
for arg in "$@"; do
  if [ "$arg" = "--dry-run" ]; then
    exec "$NODE_BIN" --experimental-strip-types --no-warnings scripts/install.ts "$@"
  fi
done

if [ "$(id -u)" -eq 0 ]; then
  exec "$NODE_BIN" --experimental-strip-types --no-warnings scripts/install.ts "$@"
fi

# Pass the resolved absolute path through, since sudo will not find it again.
exec sudo -- "$NODE_BIN" --experimental-strip-types --no-warnings scripts/install.ts "$@"
