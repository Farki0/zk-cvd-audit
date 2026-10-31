#!/usr/bin/env bash
# Executor-only acceptance tests (PROTOTYPE_SPEC.md section 4): hash examples, 55 journals, 15 audit outputs,
# 11 attacks and the limit case. The guest runs in the zkVM executor, no proofs are made (minutes, not hours).
# Usage: scripts/acceptance.sh        Exit status 0 iff everything matches.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$HOME/.risc0/bin:$PATH"
cargo build --release 2>&1 | tail -2
RUN=runs/acceptance-$(date +%Y%m%d-%H%M%S); mkdir -p "$RUN"
python3 scripts/envinfo.py "$RUN"
H=target/release/host; V=reference/vectors
echo "== 0. the reference vectors regenerate from the reference code"
PYTHONDONTWRITEBYTECODE=1 python3 reference/code/vectors.py golden "$RUN/regenerated" > /dev/null
diff -r "$V" "$RUN/regenerated"     # on its own line: set -e does not stop at a failing command left of '&&'
echo "ok: vectors/ identical to the output of reference/code/vectors.py golden"
echo "== 1. hash examples"
$H hashes --vectors $V | tee "$RUN/hashes.log" | tail -1
echo "== 2+3. journals of S1-S3 x Q1-Q5 and auditor outputs"
$H accept --vectors $V --out "$RUN/accept.json" 2>&1 | tee "$RUN/accept.log" | tail -1
echo "== 4. attacks and limit case"
$H attacks --vectors $V --out "$RUN/attacks.json" 2>&1 | tee "$RUN/attacks.log" | grep -E "^(ok|FAIL)|cases as expected" | cut -c1-120
echo "ACCEPTANCE (executor only) PASSED; logs in $RUN"