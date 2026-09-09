#!/usr/bin/env bash
# User-level Tor for development: no root, no system changes.
#
# Gives you two things the local environment lacks:
#
#   1. a SOCKS proxy — which the bot itself needs whenever
#      PAYNYM_BOT_ELECTRUM or PAYNYM_BOT_SOROBAN points at an onion (without a
#      running Tor, its "general SOCKS server failure" is exactly what you get),
#   2. a hidden service publishing the storefront, so the page can be reached
#      the way a real customer reaches it: over an onion.
#
# Usage:
#   ./scripts/dev-tor.sh            start (or reuse) and print the onion URL
#   ./scripts/dev-tor.sh stop       shut it down
#
# Environment:
#   PAYNYM_BOT_HTTP_PORT     storefront loopback port (default 8462)
#   PAYNYM_BOT_TOR_DIR       where to keep state (default ~/.paynym-bot/tor)
#   PAYNYM_BOT_TOR_SOCKS_PORT  SOCKS port (default 9051, NOT 9050 — 9050 is
#                             commonly held by the system tor or another app's)

set -euo pipefail

http_port="${PAYNYM_BOT_HTTP_PORT:-8462}"
tor_dir="${PAYNYM_BOT_TOR_DIR:-$HOME/.paynym-bot/tor}"
socks_port="${PAYNYM_BOT_TOR_SOCKS_PORT:-9051}"

mkdir -p "$tor_dir/hs" "$tor_dir/data"
chmod 700 "$tor_dir" "$tor_dir/hs" "$tor_dir/data"

# A dedicated torrc, passed with -f: without it tor reads /etc/tor/torrc, which
# on many distros sets "User tor" (unusable for a non-root user) and defines
# services that conflict with ours.
cat > "$tor_dir/torrc" <<EOF
SocksPort 127.0.0.1:$socks_port
HiddenServiceDir $tor_dir/hs
HiddenServicePort 80 127.0.0.1:$http_port
DataDirectory $tor_dir/data
Log notice file $tor_dir/tor.log
EOF

pidfile="$tor_dir/tor.pid"

is_running() {
  [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null
}

if [[ "${1:-}" == "stop" ]]; then
  if is_running; then
    kill "$(cat "$pidfile")"
    rm -f "$pidfile"
    echo "tor stopped"
  else
    echo "tor is not running"
  fi
  exit 0
fi

if is_running; then
  echo "tor already running (pid $(cat "$pidfile"))"
else
  echo "starting tor (user-level, $tor_dir, socks on $socks_port)..."
  setsid nohup tor -f "$tor_dir/torrc" >"$tor_dir/stdout.log" 2>&1 < /dev/null &
  echo $! > "$pidfile"
fi

# Wait for the hidden service hostname to be published.
hostname_file="$tor_dir/hs/hostname"
for i in $(seq 1 60); do
  if [[ -f "$hostname_file" ]]; then break; fi
  sleep 1
done

if [[ ! -f "$hostname_file" ]]; then
  echo "tor did not publish the hidden service in time; check $tor_dir/tor.log" >&2
  exit 1
fi

onion=$(cat "$hostname_file")
cat <<EOF

  socks proxy:   127.0.0.1:$socks_port
  storefront:    http://$onion
  local target:  127.0.0.1:$http_port

  The bot picks the SOCKS port up from PAYNYM_BOT_TOR_SOCKS_PORT; export the
  same value before running "paynym-bot start" when pointing it at onions.

  Open the storefront in Tor Browser (on another box or your phone — onion
  reachability is not reliably testable from the host that runs the service).

EOF
