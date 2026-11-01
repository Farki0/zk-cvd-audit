#!/usr/bin/env bash
# The whole evaluation that needs no proving (EQ1, EQ2, the coalition limit, the executor part of EQ3).
# Real proofs and timings are separate and take hours: acceptance_prove.sh and bench.py (MEASURE.md).
#   scripts/evaluate.sh            -> runs/eval-<date>/ (env.json, logs), results/*.json|csv, summary results/eval_summary.json
#   scripts/evaluate.sh --prove    -> additionally the aggregate-receipt check of EQ2 with real proofs (S1, Q2; ~1 h)
# A part that fails does not stop the others; its result file is removed first, so the summary never shows an old
# result as new. Known EQ2 findings (docs/EVALUATION.md) are reported but do not fail the run; new ones do.
# Exit status 0 iff every part passed.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$HOME/.risc0/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1
if [ -n "${RISC0_DEV_MODE:-}" ] && [ "${RISC0_DEV_MODE}" != 0 ] && [ "${RISC0_DEV_MODE}" != false ]; then
    echo "RISC0_DEV_MODE is set: refusing to run"; exit 2; fi
echo "== build"
cargo build --release 2>&1 | tail -2
[ "${PIPESTATUS[0]}" = 0 ] || { echo "BUILD FAILED: not running the evaluation with an old binary"; exit 2; }
RUN=runs/eval-$(date +%Y%m%d-%H%M%S); mkdir -p "$RUN"
python3 scripts/envinfo.py "$RUN"
PROVE=""; [ "${1:-}" = "--prove" ] && PROVE="--prove"
rm -f results/eq1_diff.json results/eq2_disclosure.json results/collusion.json results/accept_exec.json \
      results/attacks_exec.json results/eval_summary.json
declare -A STATUS SECS
part() {   # part <name> <command...>
    local name=$1; shift
    echo "== $name: $*"
    local t0=$SECONDS
    if "$@" > "$RUN/$name.log" 2>&1; then STATUS[$name]=passed; else STATUS[$name]=FAILED; fi
    SECS[$name]=$((SECONDS - t0))
    tail -2 "$RUN/$name.log"; echo "   -> ${STATUS[$name]} in ${SECS[$name]} s (log $RUN/$name.log)"
}
part acceptance   scripts/acceptance.sh
ACC=$(ls -td runs/acceptance-2* 2>/dev/null | head -1)
if [ "${STATUS[acceptance]}" = passed ] && [ -f "$ACC/accept.json" ]; then
    cp "$ACC/accept.json" results/accept_exec.json; cp "$ACC/attacks.json" results/attacks_exec.json; fi
part eq1_diff     python3 scripts/eq1_diff.py
part eq2          python3 scripts/eq2_disclosure.py $PROVE
part collusion    python3 scripts/collusion.py
part cycles       python3 scripts/cycles.py
part cost_extra   python3 scripts/cost_extra.py
python3 - "$RUN" <<PY
import json, os, sys
run = sys.argv[1]
st = {$(for k in "${!STATUS[@]}"; do printf '"%s": {"status": "%s", "seconds": %s}, ' "$k" "${STATUS[$k]}" "${SECS[$k]}"; done)}
def load(f):
    p = f'results/{f}.json'
    return json.load(open(p)) if os.path.exists(p) else None
a, t, e1, e2, c = (load(f) for f in ('accept_exec', 'attacks_exec', 'eq1_diff', 'eq2_disclosure', 'collusion'))
s = {'run': run, 'env': json.load(open(f'{run}/env.json')), 'parts': st,
     'EQ1_vectors': a and t and {'journals': f"{a['journals_equal']}/{a['journals_total']}", 'audits': f"{a['audits_equal']}/{a['audits_total']}",
                     'aggregates': f"{a.get('aggregates_ok')}/{a.get('aggregates_total')}",
                     'attacks_as_expected': f"{len(t['rows']) - t['failures']}/{len(t['rows'])}", 'real_proofs': a['real_proofs']},
     'EQ1_differential': e1 and {k: e1[k] for k in ('runs', 'journals_compared', 'vendor_verdicts_compared', 'audits_compared', 'mismatches', 'by_part')},
     'EQ2': e2 and {k: e2.get(k) for k in ('views_checked', 'views_equal_to_simulation', 'findings_by_class', 'views_by_class',
                                           'journal_size_constant_less_instance_id', 'pairs', 'aggregate_receipt')},
     'coalition_limit': c and {k: c[k] for k in ('cases', 'as_predicted', 'accepted_cases')}}
json.dump(s, open('results/eval_summary.json', 'w'), indent=1); json.dump(s, open(f'{run}/eval_summary.json', 'w'), indent=1)
print(json.dumps({k: v for k, v in s.items() if k != 'env'}, indent=1))
PY
FAIL=0; for k in "${!STATUS[@]}"; do [ "${STATUS[$k]}" = passed ] || FAIL=1; done
echo "EVALUATION (no proofs) $([ $FAIL = 0 ] && echo PASSED || echo HAS FAILURES); logs in $RUN"
exit $FAIL
