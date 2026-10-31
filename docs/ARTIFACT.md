# Artifact: how to reproduce the evaluation of the thesis

**Retrospective Auditing of Cross-Organizational Processes with Zero-Knowledge Proofs** (Ádám Farkas, BME TDK 2026;
advisors Martin Farkas and Dr. Imre Kocsis). This directory is the prototype and the evaluation of Chapter 6:
the guest program of Algorithm 5.1 on RISC Zero 3.0.6 (CPU prover), the prover host, the auditor (checks 1-7),
the aggregation guest and the scripts that produce every number of the chapter.

* Version: 1.0.0 (`CITATION.cff`). Every reported number is read from a file in `results/`; the machine, toolchain
  and guest image ids behind it are in `results/*env.json` (see the reproduction limits below).
* Repository: https://github.com/Farki0/zk-cvd-audit

## Reproduce

```bash
docker build -t cvd-audit .
docker run --rm -v "$PWD/out:/out" cvd-audit smoke             # minutes: build check + executor-only acceptance
docker run --rm -v "$PWD/out:/out" cvd-audit reproduce         # about 10 min: the evaluation without proofs
docker run --rm -v "$PWD/out:/out" cvd-audit reproduce-prove   # about 12 h: real proofs; 16 GB RAM
```

Without Docker, from this directory: `just smoke`, `just reproduce`, `just reproduce-prove` (the commands behind them
are in `scripts/reproduce.sh`). Pinned: Rust 1.94.1 for the host (`rust-toolchain.toml`), RISC Zero `cargo-risczero 3.0.6`,
`r0vm 3.0.6`, rzup `rust 1.97.0`, `cpp 2024.1.5`, `cryptography 41.0.7` (`requirements.txt`), `Cargo.lock`.
The image was written together with the thesis but has not yet been built by the author; if it fails, the install steps
of `MEASURE.md` section 1 are the reference.

## Results map

One row per table or figure of Chapter 6 and its appendix. "Time" is wall-clock on the machine of the real-proof
runs (AMD Ryzen 9 7950X3D, 16 cores / 32 threads, 96 GB; Omarchy Linux) for the proofs and on an Intel i7-9750H under
WSL2 for the executor-only parts. The whole real-proof run was about 2 h 18 min (`evaluate.sh` 238 s, dry run 5 s,
`acceptance_prove.sh` 1435 s, K 456 s, C 465 s, B 1466 s, D 795 s, A 3372 s).

| Thesis item | Command | Output (under `results/`) | Time |
| --- | --- | --- | --- |
| EQ1 on the fixed vectors (verdict table) | `just tab-correctness` | `accept_exec.json` | minutes |
| EQ1 beyond the vectors (differential test, 120 + 30x15 inputs) | `python3 scripts/eq1_diff.py` | `eq1_diff.json` | minutes |
| The eleven attacks, executor-only and with real proofs | `just tab-attacks`; `scripts/acceptance_prove.sh` | `attacks_exec.json`, `attacks_prove.json` | minutes; 1435 s |
| EQ2 disclosure (view against simulation, 175 views) | `just tab-disclosure` | `eq2_disclosure.json`, `eq2_aggregate_prove.json` | minutes; +30 min with `--prove` |
| Coalition limit (22 cases) | `just tab-coalition` | `collusion.json` | minutes |
| Summary table of the three checks | `scripts/evaluate.sh` | `eval_summary.json` | 238 s |
| Cycles against slice length (series A, C) and vendors (series B) | `just fig-scalability` | `cycles.csv`, `cycles_env.json` | minutes |
| Cycles against monitor size and against record size | `scripts/cost_extra.py stmt record` | `cycles_statement_size.csv`, `cycles_record_size.csv` | minutes |
| Second domain (supply contract with a penalty, end of Chapter 3; reference model only, no proofs) | `python3 scripts/second_domain.py` | `second_domain.json` | seconds |
| Native baseline and the price of zero knowledge | `just tab-overhead` | `native_baseline.csv`, `zk_overhead.csv` | seconds |
| Proving times: series K, C, B, D, A | `python3 scripts/bench.py K C B D A` | `measurements.csv`, `measurements_audit.csv`, `bench_env.json`, `bench_commands.log` | 456 + 465 + 1466 + 795 + 3372 s |
| Proving times with realistic record sizes (series E) | `python3 scripts/bench.py E --E-lengths 128 512` | rows `E256`, `E1024` in `measurements.csv` | 15-20 min on a 7950X3D (planned) |
| Repeated points, cold start | `python3 scripts/bench.py B --B-reps 3`; `--cold` | `measurements.csv`, `measurements_cold.csv`, `wall_times_*.csv` | hours |

The LaTeX tables and the figure data of the thesis are generated from these files by `thesis/scripts/eval_artifacts.py`
in the thesis repository; it writes `thesis/tables/*.tex` and `thesis/figures/data/*.csv`.

## Reproduction limits

* **Deterministic:** verdicts, journals, cycle counts and segment counts depend only on the guest and its input. They
  match the committed files if `guest_image_ids` of `runs/*/env.json` equal `results/cycles_env.json` (a different
  toolchain builds a different guest, and the script says so).
* **Randomness:** the random inputs of the differential test use a fixed seed (2026). Salts and nonces of the
  scenarios built for the EQ2 check come from a CSPRNG, so the receipts differ between runs, and the checks compare
  only what the protocol makes public.
* **Timings vary.** Times of different series for the same point differ by up to 8 % (59.6 s in A, 64.2 s in K at
  L = 128); in the committed results series B and D ran once per point, the other points
  three times (more repetitions: `--B-reps`, `--D-reps`, `--reps`, see `python3 scripts/bench.py --help`). The numbers of the thesis
  are those of one machine. The planning rates in `bench.py` are calibrated on the author's machine.
* **Hardware.** CPU prover only (a GPU is not used). The L = 2048 point peaks at 9.4 GB of memory; under WSL2 raise
  `memory=` in `.wslconfig`. Real proofs are never run in the RISC Zero development mode; the scripts and the host
  refuse to start with `RISC0_DEV_MODE` set, and receipts of kind `Fake` are rejected.
* **Records.** The sweeps pad slices with about 21-byte `work` records. A record of 1,055 bytes costs 3.4 times the
  cycles (`cycles_record_size.csv`); series E measures its proving time.
* **Guest image ids.** The committed real-proof results (`measurements.csv`, `accept_prove.json`) were made with older
  guest binaries than the current code (`bench_env.json`: full `b4ee73...`, iface `9d53f2...`, chain `84ca72...`, agg
  `eff61586...`; the current code, `cycles_env.json`: `2abcd9...`, `35fc03...`, `808fae...`, `e62ec604...`). The thesis
  says which change this is: the interface entries are sorted (at most 2.8 % more user cycles), and the aggregation
  journal has a participant digest (at most 0.34 %, no padded cycles). A new measurement run with the current
  code replaces all of these numbers. An image id also depends on the build environment (the same code gave two ids on two
  machines), so the check across machines is the user-cycle count, not the id.
* **Docker:** the image has no `.git`, so `env.json` records `git_commit: null` there; the version in `CITATION.cff` identifies
  it.

## Cite

Cite the repository and its version (`CITATION.cff`; Zenodo metadata: `.zenodo.json`).
License: MIT, see `LICENSE`.
