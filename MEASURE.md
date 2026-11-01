# Measuring on another machine

## 1. Install (Ubuntu 22.04/24.04, x86-64; Linux or WSL2)

```bash
sudo apt-get install -y build-essential pkg-config libssl-dev python3 python3-pip git curl
curl https://sh.rustup.rs -sSf | sh -s -- -y
curl -L https://risczero.com/install | bash
export PATH="$HOME/.risc0/bin:$HOME/.cargo/bin:$PATH"   # in every new shell (see below)
rzup install cargo-risczero 3.0.6
rzup install r0vm 3.0.6
rzup install rust 1.97.0
rzup install cpp 2024.1.5
rzup show                                   # must list exactly these versions
git clone https://github.com/Farki0/zk-cvd-audit && cd zk-cvd-audit   # every command below runs from the repository root
python3 -m pip install --user -r requirements.txt \
  || python3 -m pip install --user --break-system-packages -r requirements.txt   # Ubuntu 24.04 refuses the first
python3 -c "import cryptography; print(cryptography.__version__)"   # 41.0.7
unset RISC0_DEV_MODE                        # the scripts abort if it is set
```

`source ~/.bashrc` does not put `rzup` on the `PATH` in a non-interactive shell (a script's, or one over ssh): Ubuntu's
`.bashrc` returns early there, before the line the RISC Zero installer appends. Hence the explicit `export PATH`.
`requirements.txt` is needed by the sweeps and the acceptance, which call `reference/code/vectors.py`.
On WSL2, Linux gets half of the host RAM by default; raise `memory=` in `%UserProfile%\.wslconfig` before measuring.

`rustup` picks Rust 1.94.1 for the host from `rust-toolchain.toml`. The first build compiles the guests and takes
a few minutes. Close other heavy programs while measuring, disable CPU frequency scaling surprises if you can
(plugged in, performance mode), and note in the e-mail whether the machine has a GPU (not used: the CPU prover is).
Memory: about 2.5 GB for L <= 128, more for long slices (the largest point is the one to watch).

## 2. Commands, in this order

```bash
scripts/evaluate.sh                         # ~10 min CPU. Acceptance (executor), EQ1/EQ2/coalition checks, cycles; must end
                                            # with "EVALUATION (no proofs) PASSED". Compare runs/eval-*/env.json
                                            # guest_image_ids with results/cycles_env.json: different ids = different
                                            # guest binaries, so the cycle counts of the repo do not apply
python3 scripts/bench.py --dry-run A B C D K    # plan and estimate for THIS machine's rate, see 3.
scripts/acceptance_prove.sh                 # ~3 h. Real proofs: S1 under Q1-Q5 + its 3 aggregates, 11 attacks, limit case
                                            # (--full: S1-S3, 55 proofs + 9 aggregates, ~8 h)

# the SHORT plan (default, --plan short, ~9 h): one run directory (runs/bench), every command resumable
python3 scripts/bench.py K                  # composite vs succinct at L=128, 3 repetitions
python3 scripts/bench.py C                  # ablation (chain, iface) at L=128, 3 repetitions
python3 scripts/bench.py B                  # nu = 1, 2, 4, 8, 16 at L=32, one repetition, every organisation + audit
python3 scripts/bench.py D                  # aggregation guest, nu = 2 and 8, one repetition
python3 scripts/bench.py A                  # Q2, L = 8..512 (3 repetitions), L = 2048 once (longest, last)
```

The short plan: Q2 only in A (Q4 is a formula of the same cost class, see `results/cycles.csv`); 3 repetitions, with
a warm-up only for points estimated under 10 minutes, one run for points over 30 minutes (L = 2048); B and D one
repetition each, B with a single warm-up of one vendor for the whole sweep; C and K at L = 128 only. The long plan
(Q2 and Q4, 5 repetitions, C and K also at L = 2048/512, D also at nu = 16, about 45 h) is `--plan long`:

```bash
python3 scripts/bench.py --plan long K
python3 scripts/bench.py --plan long A --A-lengths 8 32 128 512
python3 scripts/bench.py --plan long B
python3 scripts/bench.py --plan long D
python3 scripts/bench.py --plan long C --C-lengths 128
python3 scripts/bench.py --plan long A C
```

Rows of both plans share the CSV key (sweep, rep, statement, n, L, org, variant, kind), so the long plan run later in
the same directory resumes from the short one. `runs/bench/commands.log` records the options of every command.

If the machine is much faster or slower than the estimates, calibrate after sweep K (from its rows in
`runs/bench/measurements.csv`, repetitions >= 1): `--sec-per-mcycle` = `prove_s / (cycles / 1e6)` of the composite
rows; `--recursion-s` = `(prove_s - cycles / 1e6 * sec_per_mcycle) / (2 * segments - 1)` of the succinct rows (one
lift per segment, one join per pair). Pass both to `--dry-run`. Changing them can change the repetitions of a point
(see below), so use the same values for every later command.

Repetitions (`--reps`, `--reps-large`, `--large-secs`, `--warmup-secs`, `--B-reps`, `--B-warmup`, `--D-reps`; any of
them overrides the preset): long plan: one discarded warm-up plus 5 repetitions per point, no warm-up and
3 repetitions when one proof is estimated over 10 minutes, D 3 repetitions; the warm-up of a B point proves one vendor
only. Short plan as above.

## 3. Expected duration

**Receipt kind (2026-10-26).** Every organisation proof of the acceptance and of sweeps A-D is now a *succinct*
receipt, the protocol's kind: the auditor rejects composite receipts at check 1, and the aggregate of sweep D is
succinct too (a composite aggregate carries the organisations' receipts, see docs/EVALUATION.md). Succinct proving
adds the recursion (one lift per segment, one join per pair, one resolve per assumption); the dry run includes it
since 2026-10-28. On the development machine the S1 aggregate took 755 s as composite and 1,060 s as succinct; one
organisation proof at L = 8 (3 segments after the one-segment split of `prove_org`) took 104 s as composite and 291 s
as succinct, i.e. about 37 s per recursion proof.

The planning model: **265 s per million padded cycles and 37 s per recursion proof, measured on the author's WSL2
machine (i7-9750H, 6 cores / 12 threads, 9.7 GB)**. Scale for your CPU (proving was multi-threaded, ~1000-1100%
CPU) and calibrate after sweep K (section 2). Padded cycles are the sum of 2^po2 of the segments; a single succinct
proof of the largest point (L = 2048, 12.8M padded cycles) is about 72 minutes there, the smallest (L = 8) about 4.5
minutes. Peak memory there: about 1.5 GB at L = 8.

| Step | Command | Estimate on the author's machine |
| --- | --- | ---: |
| executor acceptance | `scripts/acceptance.sh` | minutes |
| real-proof acceptance (short) | `scripts/acceptance_prove.sh` | about 3 h (20 + about 8 organisation proofs of about 5 min, 3 aggregation proofs of about 15-20 min) |
| real-proof acceptance (full) | `scripts/acceptance_prove.sh --full` | about 8 h (55 + about 8 proofs, 9 aggregation proofs) |
| **Short plan** (default) | K, C, B, D, A | K 0.7 h, C 0.8 h, B 2.7 h, D 1.5 h, A 3.2 h: **about 8.9 h** (81 proofs + 2 aggregates) |
| Long plan | `--plan long` K, A, B, D, C | K 2.8 h, A 12.0 h, B 11.1 h, D 11.2 h, C 7.6 h: **about 44.6 h** (321 proofs + 9 aggregates) |

## 4. Send back

From the repository directory (nothing else is needed; do **not** send `receipts/`, `cache/` or `target/`):

* `runs/bench/env.json`, `runs/bench/measurements.csv`, `runs/bench/measurements_audit.csv`, `runs/bench/commands.log`
  (the author copies them to `results/measurements.csv`, `results/measurements_audit.csv`, `results/bench_env.json`,
  `results/bench_commands.log`, which are committed and
  which `thesis/scripts/eval_artifacts.py` reads)
* `results/accept_prove.json`, `results/attacks_prove.json` (written by `acceptance_prove.sh`)
* `runs/acceptance-*/` (logs, `accept.json`, `attacks.json`, `env.json`) and `runs/acceptance_prove-*/` (same, **without** its `cache/`)
* the output of `python3 scripts/bench.py --dry-run A B C D K` and a line on what else ran on the machine
* `git rev-parse HEAD` of the commit you ran (also in each `env.json`)

`measurements.csv` columns: `sweep, rep, statement, n, L, org, role, records, variant, requested_kind, receipt_kind,
cycles, user_cycles, segments, prove_s, peak_rss_mb, receipt_bytes, journal_bytes, verify_s, wall_s, control_id,
control_program` (`cycles` = padded cycles proved, `user_cycles` = instructions executed; `rep` 0 is the discarded
warm-up; `prove_s` = execution + proving + recursion inside `prove_with_opts`, `verify_s` = one `Receipt::verify`,
`wall_s` = the whole host process; `peak_rss_mb` = the larger peak resident memory of the host process and of the
`r0vm` child that proves (`wait4`; the host itself stays small); `control_program` must be `join.zkr` for organisations and `resolve.zkr` for the aggregate,
`bench.py` stops otherwise). The audit time of a repetition (all receipt verifications and checks) is in
`measurements_audit.csv`.