# Prototype: zero-knowledge audit of a CVD run (thesis Chapter 6)

Prototype of the thesis: the guest program of Algorithm 5.1, a prover host, the auditor (checks 1-7), the
aggregation guest, the acceptance tests and the benchmark runner. zkVM: **RISC Zero 3.0.6**
(CPU prover). Everything the tests compare against lives in `reference/` (vectors and the Python reference model).

It accompanies the TDK paper *Retrospective Auditing of Cross-Organizational Processes with Zero-Knowledge Proofs*
(Ádám Farkas, BME VIK, 2026; supervisors Martin Farkas and Dr. Imre Kocsis).

## Reproduce

With Docker, from the image of the results tag (no clone or toolchain needed):

```sh
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/out:/out" ghcr.io/farki0/zk-cvd-audit:v1.0.0 reproduce
```

This runs the whole evaluation without proofs (about 10 minutes) and writes the result files to `out/`; `--user`
keeps them owned by you. Other recipes go in place of `reproduce`: `smoke` (build check and executor-only acceptance,
minutes) and `reproduce-prove` (real proofs, about 12 hours, 16 GB RAM). The release workflow publishes the image
for every release tag.

From a clone: `just reproduce`, `just smoke` (or `just reproduce --smoke`), `just reproduce-prove`; or build the image
with `docker build -t cvd-audit .` and run it as above with `cvd-audit` as the image. The repository also opens as a
dev container (`.devcontainer/`, built from the `Dockerfile`). Measuring on another machine: [MEASURE.md](MEASURE.md).

## Results map

One row per table or figure of Chapter 6 and its appendix. Times are wall-clock on an AMD Ryzen 9 7950X3D (16 cores,
96 GB) for real proofs and on an Intel i7-9750H under WSL2 for the executor-only parts. Details:
[docs/ARTIFACT.md](docs/ARTIFACT.md#results-map).

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

## Reproduction limits

* Verdicts, journals, cycle and segment counts are deterministic. They match the committed files when the guest
  image ids of `runs/*/env.json` equal `results/cycles_env.json`; another build environment gives another image id,
  so across machines compare user cycles.
* The differential test uses the fixed seed 2026. Salts and nonces of the EQ2 scenarios come from a CSPRNG, so
  receipts differ between runs; the checks compare only what the protocol makes public.
* Proving times depend on the machine; points of different series at the same size differ by up to 8 %. The
  thesis's times are from one machine.
* CPU prover only. The L = 2048 point peaks at 9.4 GB of memory. The scripts refuse to run with `RISC0_DEV_MODE` set.

Details: [docs/ARTIFACT.md](docs/ARTIFACT.md#reproduction-limits).

## One command per task

| Task | Command | Time |
| --- | --- | --- |
| Executor-only acceptance (hash examples, 55 journals, 15 audits, 11 attacks, limit case; also checks that `reference/vectors` regenerates byte for byte) | `scripts/acceptance.sh` | minutes (mostly the first build) |
| The same with real proofs, plus the aggregation guest for the *verdict* statements | `scripts/acceptance_prove.sh [run-dir]` | hours (see MEASURE.md); resumable |
| Plan a sweep without running it | `scripts/bench.py --dry-run A B C D K` | seconds |
| Run sweeps (A slice length, B vendors, C ablation, D aggregation, K receipt kinds) | `scripts/bench.py A` ... | hours; resumable, CSV after every proof |
| Machine-independent cycle counts (executor only) -> `results/cycles.csv` | `scripts/cycles.py` | about a minute |
| **The whole evaluation without proofs**: acceptance, EQ1 differential test, EQ2 simulation check, coalition-limit cases, cycles, native baseline, monitor- and record-size series -> `results/`, summary `results/eval_summary.json` (see docs/EVALUATION.md) | `scripts/evaluate.sh` | about 10 minutes |
| The same plus the EQ2 check of the aggregate receipt with real proofs (S1, Q2) | `scripts/evaluate.sh --prove` | + about 30 minutes |

Every run directory (`runs/...`) starts with `env.json` (CPU, cores, RAM, OS, rustc, risc0 versions, guest image ids,
git commit, `RISC0_DEV_MODE` check). If `RISC0_DEV_MODE` is set the scripts abort, and the host binary refuses to
run; receipts of kind `Fake` are also rejected.

Install and the measurement procedure for another machine: **MEASURE.md**.

## Layout

| Path | Content |
| --- | --- |
| `core/` | `audit-core`: hash and formats, Algorithm 5.1 (`guest`), auditor checks 2, 3, 5, 6, 7. Runs both inside the zkVM and natively |
| `methods/guest/` | zkVM guest binaries: `g_full` (the guest program), `g_iface` and `g_chain` (ablation variants), `g_agg` (aggregation guest) |
| `host/` | `host` binary: `prove`, `exec`, `exec-all`, `native`, `audit`, `accept`, `attacks`, `agg`, `agg-exec`, `audit-agg`, `hashes`, `env`. Prover host and auditor (check 1 = receipt verification against the image id, check 4 = Ed25519) |
| `scripts/` | `acceptance*.sh`, `bench.py`, `cycles.py`, `envinfo.py`; evaluation: `evaluate.sh`, `eq1_diff.py`, `eq2_disclosure.py`, `collusion.py`, `cost_extra.py`, `evalkit.py` |
| `reference/` | copy of the thesis vectors and the Python reference (see `reference/README.md`) |
| `docs/OPTIMISATION.md`, `docs/RECEIPTS.md` | what the guest optimisation changed; receipt kinds, zero knowledge and size |
| `docs/EVALUATION.md` | what each evaluation script checks, its result, and which file backs which claim of Chapter 6 |
| `results/cycles.csv` | executor-only cycles, segments, journal size |

## Design notes

* **How the statement reaches the guest.** As a public input (the `canonical` bytes). The guest hashes it into the
  statement id in the journal. One program image id serves all statements; the auditor compares `sid` with the id it
  asked for (check 2). The message kinds and who may send them are compiled into the guest.
* **Variants.** `full` = hash chain + interface checks + monitors. `iface` = chain + interface checks (no monitors).
  `chain` = hash chain only. Sweep C compares them; the full variant of sweep C is the corresponding point of sweep A.
* **Auditor order.** Checks run in the order 1-7 of the thesis, so check 4 comes before check 5. A back-dated slice
  therefore reports check 4; `attacks.json` accepts "5 (and 4)" for that case.
* **Aggregation guest.** Built (`g_agg`): verifies the organisations' receipts as assumptions with `env::verify`,
  runs checks 2, 3, 5, 6, 7 and outputs sid, instance, guest image id, heads and the verdict. The auditor then verifies
  the single receipt and runs check 4. The aggregate is proved as a **succinct** receipt (`agg --kind succinct`, the default):
  a composite aggregate carries the organisations' receipts as unresolved assumption receipts
  (`CompositeReceipt::assumption_receipts`, risc0-zkvm 3.0.6) and so hands the auditor their claims; the succinct
  prover resolves them. `agg` reports this as `leak` (docs/EVALUATION.md, EQ2). `results/cycles.csv` (sweep D) contains its *executor-only* cost with
  placeholder receipts; proving it (assumption resolution, recursion) is measured by sweep D of `bench.py`.
* **Private input transport.** The slice reaches the guest as one length-prefixed byte blob (see
  docs/OPTIMISATION.md); the protocol's formats are unchanged.

## Pinned versions

Rust 1.94.1 for the host (`rust-toolchain.toml`), `risc0-zkvm = 3.0.6`, `risc0-build = 3.0.6`, RISC Zero toolchain
(`rzup`): `cargo-risczero 3.0.6`, `r0vm 3.0.6`, `rust 1.97.0`, `cpp 2024.1.5`. Both `Cargo.lock` files
(`/Cargo.lock`, `/methods/guest/Cargo.lock`) are committed. Python 3.12 with `requirements.txt`.

## Results tag

The numbers in the thesis come from tag `v1.0.0` (Zenodo version 1.0.0). Later versions change the packaging, never
the results.

## Cite

Cite the thesis and this repository with its version (`CITATION.cff`; Zenodo metadata: `.zenodo.json`).

```bibtex
@software{farkas2026zkcvdaudit,
  author  = {Farkas, Ádám},
  title   = {Artifact for: Retrospective Auditing of Cross-Organizational Processes with Zero-Knowledge Proofs},
  year    = {2026},
  version = {1.0.0},
  url     = {https://github.com/Farki0/zk-cvd-audit}
}
```

## License

MIT, see [LICENSE](LICENSE).
