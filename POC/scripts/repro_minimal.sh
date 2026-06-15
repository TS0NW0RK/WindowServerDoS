#!/bin/bash
# MINIMAL CONFIRMED REPRO — 5 proxies x 500 iters (2500 total calls)
# WindowServer/DCP hang ~45-60s after completion. SAVE WORK.
set -euo pipefail
cd "$(dirname "$0")/.."
make -s ca-iokit-replay
echo "[!] Minimal repro: 5 x 500, seed 20250610"
exec ./ca-iokit-replay run -u DCPAV -n 500 -S 20250610 --proxies 5 -o logs/repro_minimal.log
