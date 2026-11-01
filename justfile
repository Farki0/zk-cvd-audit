# Recipes of the CVD-audit artifact. `just` lists them; every one runs from this directory.
#   just reproduce         the whole evaluation without proofs (about 10 minutes)
#   just smoke             the quick check (minutes): build + executor-only acceptance
#   just reproduce-prove   with real proofs (about 12 hours; needs 16 GB RAM)
#   just reproduce --smoke the same as `just smoke` (`--prove` = `just reproduce-prove`); the flag goes to scripts/reproduce.sh

default:
    @just --list

# build the host binary and the zkVM guests
build:
    cargo build --release

# quick check: build, executor-only acceptance, and the plan of the sweeps
smoke:
    scripts/reproduce.sh --smoke

# the evaluation without proofs: EQ1, EQ2, coalition limit, cycle counts -> results/ (`--smoke`, `--prove` as above)
reproduce *flags:
    scripts/reproduce.sh {{flags}}

# everything, with real proofs (acceptance with proofs, the short plan of the sweeps)
reproduce-prove:
    scripts/reproduce.sh --prove

# --- one recipe per figure or table of the thesis (the files behind it; docs/ARTIFACT.md has the map) ---

# Table: correctness (EQ1) of the fixed vectors, and the differential test
tab-correctness:
    python3 scripts/eq1_diff.py
    scripts/acceptance.sh

# Table: the eleven attacks replayed on the prototype
tab-attacks:
    scripts/acceptance.sh

# Table: disclosure (EQ2), the auditor's view against its simulation
tab-disclosure:
    python3 scripts/eq2_disclosure.py

# Table: the coalition limit
tab-coalition:
    python3 scripts/collusion.py

# Tables and figure: cycles against slice length and number of vendors, monitor size, record size, native baseline
fig-scalability:
    python3 scripts/cycles.py
    python3 scripts/cost_extra.py

# Real proofs: one vendor against slice length, vendors, ablation, receipt kinds, record size (hours)
fig-proving-times:
    python3 scripts/bench.py K C B D A E

# The price of zero knowledge: native run against the proof, on this machine
tab-overhead:
    python3 scripts/cost_extra.py native
    python3 scripts/overhead.py --bench runs/bench/measurements.csv --bench-env runs/bench/env.json

# print the plan and time estimate of the sweeps without proving
plan:
    python3 scripts/bench.py --dry-run A B C D K E
