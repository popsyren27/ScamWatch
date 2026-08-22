#!/usr/bin/env bash
# ==========================================================================
# run.sh - launcher for THREAT-RECON (macOS / Linux).
# Starts Tor (tor -f torrc) and the app via launch.py.
# Any arguments are forwarded:  ./run.sh scan https://example.com
# ==========================================================================
cd "$(dirname "$0")" || exit 1
exec python3 launch.py "$@"
