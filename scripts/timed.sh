#!/usr/bin/env bash
# Runs a command and appends its wall time to runs/wall_times.csv (utc, label, seconds, exit status, cpu).
#   scripts/timed.sh evaluate scripts/evaluate.sh
#   scripts/timed.sh acceptance_prove scripts/acceptance_prove.sh
# The exit status of the command is the exit status of this script.
set -uo pipefail
cd "$(dirname "$0")/.."
label=${1:?usage: timed.sh LABEL COMMAND...}; shift
mkdir -p runs
f=runs/wall_times.csv
[ -f "$f" ] || echo "utc,label,seconds,exit,cpu" > "$f"
cpu=$(lscpu 2>/dev/null | sed -n 's/^Model name:[[:space:]]*//p' | head -1 | tr ',' ' ')
t0=$(date +%s)
"$@"
rc=$?
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ),$label,$(( $(date +%s) - t0 )),$rc,$cpu" >> "$f"
exit $rc
