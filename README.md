# Prototype: zero-knowledge audit of a CVD run (thesis Chapter 6)

Prototype of the thesis: the guest program of Algorithm 5.1, a prover host, the auditor (checks 1-7), the
aggregation guest, the acceptance tests and the benchmark runner. zkVM: **RISC Zero 3.0.6**
(CPU prover). Everything the tests compare against lives in `reference/` (vectors and the Python reference model).

**Reproduce:** `docker run --rm -v "$PWD/out:/out" cvd-audit smoke` or `just smoke` (minutes), `just reproduce`
(about 10 minutes, no proofs). Results map and limits: [docs/ARTIFACT.md](docs/ARTIFACT.md). Measuring on another machine:
[MEASURE.md](MEASURE.md).

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

## Design decisions

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

## License

MIT, see [LICENSE](LICENSE).