#!/usr/bin/env bash
# The same acceptance tests with real proofs (succinct receipts, the protocol's kind; receipts are verified by the auditor, the
# aggregation guest is proved for the 'verdict' statements).
# Usage: scripts/acceptance_prove.sh [--full] [run-dir]   (re-using a run-dir resumes: proofs are cached in <run-dir>/cache)
#   default (short, about 3 h on the author's machine): scenario S1 under Q1-Q5 (20 organisation proofs, the 3
#     aggregates of Q1, Q2, Q4), all 11 attacks, the limit case and the check-1 case (about 8 more proofs). S1 is the
#     running example and covers every statement kind (two chains, two formulas, both disclosure modes) and the base
#     of every attack; S2 and S3 differ from it only in the private data, which the executor acceptance
#     (acceptance.sh, 55/55 journals) already checks for the same guest binary.
#   --full (about 8 h): S1-S3 under Q1-Q5 (55 proofs, 9 aggregates), the same attacks.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$HOME/.risc0/bin:$PATH"
SCN="S1"; [ "${1:-}" = "--full" ] && { SCN="S1 S2 S3"; shift; }
cargo build --release 2>&1 | tail -2
RUN=${1:-runs/acceptance_prove-$(date +%Y%m%d-%H%M%S)}; mkdir -p "$RUN"
python3 scripts/envinfo.py "$RUN"
H=target/release/host; V=reference/vectors
echo "== hash examples"; $H hashes --vectors $V | tail -1
echo "== journals and audits with real proofs (scenarios: $SCN)"
$H accept --vectors $V --cache "$RUN/cache" --out "$RUN/accept.json" --scenarios $SCN 2>&1 | tee "$RUN/accept.log" | grep -E "^S[0-9]|aggregate|equal"
echo "== attacks with real proofs"
$H attacks --vectors $V --cache "$RUN/cache" --out "$RUN/attacks.json" 2>&1 | tee "$RUN/attacks.log" | grep -E "^(ok|FAIL)|cases as expected" | cut -c1-120
cp "$RUN/accept.json" results/accept_prove.json; cp "$RUN/attacks.json" results/attacks_prove.json   # sources of Table 6.1
echo "ACCEPTANCE (real proofs) PASSED; logs in $RUN; results/accept_prove.json, attacks_prove.json"
