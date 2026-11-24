#!/usr/bin/env bash
# Runs the release Guardian under a virtual X display and fails if it uses more
# than 30 MB of memory or more than 1% of one CPU while idle.
# Usage: xvfb-run -a scripts/pet-budget.sh [seconds]   (after cargo build --release)
set -euo pipefail
SECONDS_IDLE="${1:-20}"
MAX_RSS_KB=$((30 * 1024))
MAX_CPU_PERCENT=1
BIN="$(dirname "$0")/../target/release/qalaa-guardian-pet"
export SLINT_BACKEND=winit-software
# No background service: the pet stays idle and retries the connection every 10 s.
export QALAA_IPC_ENDPOINT="${TMPDIR:-/tmp}/qalaa-budget-none.sock"
"$BIN" > /dev/null 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT
sleep 3  # start-up
HZ=$(getconf CLK_TCK)
ticks() { awk '{print $14 + $15}' "/proc/$PID/stat"; }
START=$(ticks)
sleep "$SECONDS_IDLE"
END=$(ticks)
RSS=$(awk '/VmRSS/ {print $2}' "/proc/$PID/status")
CPU=$(awk -v t=$((END - START)) -v hz="$HZ" -v s="$SECONDS_IDLE" 'BEGIN {printf "%.2f", 100 * t / hz / s}')
echo "Guardian idle for ${SECONDS_IDLE}s: ${RSS} kB resident, ${CPU}% CPU"
awk -v r="$RSS" -v max="$MAX_RSS_KB" 'BEGIN {exit !(r <= max)}' || { echo "Over the 30 MB memory budget"; exit 1; }
awk -v c="$CPU" -v max="$MAX_CPU_PERCENT" 'BEGIN {exit !(c < max)}' || { echo "Over the 1% idle CPU budget"; exit 1; }
