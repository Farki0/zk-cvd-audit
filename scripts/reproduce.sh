#!/usr/bin/env bash
# Regenerates the evidence behind the thesis's evaluation chapter (the single entry point of `just reproduce`
# and of the Docker image).
#
#   scripts/reproduce.sh --smoke     build + executor-only acceptance (EQ1 vectors, 11 attacks, limit case). Minutes.
#   scripts/reproduce.sh             the whole evaluation without proofs (EQ1, EQ2, EQ3 cycle counts, D13). About 10 min.
#   scripts/reproduce.sh --prove     the above, then real proofs: the acceptance with proofs (about 3 h) and the sweeps
#                                    of the short plan (about 9 h). Needs a 16 GB machine; see docs/ARTIFACT.md.
#
# Output: results/ (JSON and CSV, see docs/ARTIFACT.md for the file behind each figure and table). If $OUT is set
# (the Docker image sets it to /out), results/ and the run summaries are copied there at the end.
# Exit status 0 iff everything that ran passed.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$HOME/.risc0/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1
unset RISC0_DEV_MODE        # dev mode makes fake proofs: the scripts refuse to run with it

MODE=full
case "${1:-}" in
    --smoke) MODE=smoke ;;
    --prove) MODE=prove ;;
    "")      ;;
    *)       echo "usage: $0 [--smoke | --prove]"; exit 2 ;;
esac

rc=0
step() {   # step <label> <command...>: run, time and report one step
    local label=$1; shift
    echo "== $label: $*"
    if scripts/timed.sh "$label" "$@"; then echo "   -> $label passed"; else echo "   -> $label FAILED"; rc=1; fi
}

echo "== build (the first build compiles the guests and takes a few minutes)"
cargo build --release 2>&1 | tail -2
[ "${PIPESTATUS[0]}" = 0 ] || { echo "BUILD FAILED"; exit 2; }

case $MODE in
    smoke)
        step acceptance scripts/acceptance.sh
        step plan python3 scripts/bench.py --dry-run A B C D K E
        ;;
    full)
        step evaluate scripts/evaluate.sh
        ;;
    prove)
        step evaluate scripts/evaluate.sh
        step acceptance_prove scripts/acceptance_prove.sh
        for s in K C B D A; do step "bench_$s" python3 scripts/bench.py "$s"; done
        step bench_E python3 scripts/bench.py E --E-lengths 128 512
        step native python3 scripts/cost_extra.py native
        step overhead python3 scripts/overhead.py --bench runs/bench/measurements.csv --bench-env runs/bench/env.json
        ;;
esac

if [ -n "${OUT:-}" ]; then
    mkdir -p "$OUT"
    cp -r results "$OUT"/ 2>/dev/null
    [ -f runs/wall_times.csv ] && cp runs/wall_times.csv "$OUT"/
    for d in runs/eval-* runs/acceptance-* runs/acceptance_prove-* runs/bench; do
        [ -d "$d" ] && mkdir -p "$OUT/runs" && cp -r "$d" "$OUT/runs/" 2>/dev/null
    done
    echo "copied to $OUT"
fi
[ $rc = 0 ] && echo "REPRODUCE ($MODE) PASSED" || echo "REPRODUCE ($MODE) HAD FAILURES"
exit $rc
