# Evaluation: what is checked, how, and what came out (2026-10-26)

The abstract fixes three things to evaluate, from a would-be auditor's view: verdicts on fulfilled, repaired and
violated histories against a reference evaluator (EQ1), what the auditor learns against what the declaration allows
(EQ2), and proving and verification cost against history length and number of vendors (EQ3). This file lists every
check, the command, the result file and the result. Unless marked otherwise everything ran in the zkVM **executor**
(the guest program runs, nothing is proved); real proofs and timings are `acceptance_prove.sh` and `bench.py`
(MEASURE.md). Every number below is read from the named file; rerun to refresh.

One command runs all executor parts (about 7.5 minutes on the development machine, i7-9750H under WSL2):
`scripts/evaluate.sh` -> `results/eval_summary.json` (with `env.json`), logs in `runs/eval-<date>/`. The sources of
the Chapter 6 tables are copied to `results/` (committed). Tables and figures: `thesis/scripts/eval_artifacts.py`
(thesis repository) -> `thesis/tables/tab-*.tex`, `thesis/figures/fig-eq3-*.tex` (+ `data/`), built like the other figures.

Terminology: the prototype and the vectors print `complied`; the thesis writes *fulfilled* (chain, rank 0) and
*satisfied* (formula, Q4/Q5). The generated tables use the thesis words.

## What changed on 26 Oct

| Item | Before | Now |
| --- | --- | --- |
| Receipt kind on the protocol path | organisation proofs composite (acceptance, sweeps A-D), contrary to D11 | succinct everywhere on the protocol path; the auditor rejects any other kind at check 1; composite only in sweep K |
| Aggregate receipt (mode *verdict*) | composite: carries the organisations' receipts (leak, confirmed with real proofs) | succinct; `agg` reports `leak` (assumption receipts embedded, journal bytes or digests readable); sweep D asserts no leak |
| Aggregate journals against the vectors | only with real proofs, never run | also in the executor acceptance: 9/9 |
| EQ1 beyond the 15 fixed pairs | none | `eq1_diff.py`, 1,467 runs |
| EQ2 | argued field by field in the text | `eq2_disclosure.py`, a simulation check; two leaks found and fixed on 28 Oct (salted genesis head; no verdict while open) |
| D13 (collusion limit) | the model showed the single-vendor case | `collusion.py`: 22 cases, all as D13 predicts |
| Baseline, monitor size, record size | missing | `cost_extra.py` |
| Control id of succinct receipts | a one-segment receipt named the lift program of its size | the prover splits a one-segment slice into two, so every organisation receipt ends with `join.zkr` (the aggregate with `resolve.zkr`); the auditor checks this at check 1 |
| Image ids, run environment | missing next to `cycles.csv` | `results/cycles_env.json`; `runs/eval-*/env.json` |
| Tables 6.1-6.3, Figures 6.1-6.2 | hand-typed in WRITING_CONTEXT L | generated from `results/`; time/verification table and panels appear once `results/measurements*.csv` exist |

## EQ1: correctness

**Fixed vectors** (`scripts/acceptance.sh`; `results/accept_exec.json`, `attacks_exec.json`). 10/10 hash examples,
55/55 journals equal to the vectors field by field, 15/15 auditor outputs, 9/9 aggregate journals (Q1, Q2, Q4 on
S1-S3) with the auditor's output on them, 11/11 attacks rejected at the expected place, limit case accepted with
*fulfilled*. `vectors/` regenerates byte for byte from `reference/code/vectors.py`.

**Differential test** (`scripts/eq1_diff.py` -> `results/eq1_diff.json`). Per run: (1) each journal equals the
table-driven Python guest of `vectors.py`; (2) each vendor's settled flag (and its verdict when settled; a journal
that is not settled carries no verdict since 28 Oct) equals the semantics computed
directly by `audit_ref.rank/settled/ltlf_holds` (no automaton), on every slice, settled or not (Theorem 4.1), and its
final verdict (open if not settled) too; (3) the Rust auditor's output (checks 2-7) equals the declared output
computed from the semantics.

| Part | Inputs | Runs | Vendor verdicts f / r / v / open | Differences |
| --- | --- | ---: | --- | ---: |
| V | the vectors S1-S3 x Q1-Q5; their expected outputs also against the semantics | 15 | 31 / 4 / 3 / 2 | 0 |
| R | 120 random CVD histories (1-4 vendors; random internal records before the notify, before/between/after the deadlines; random serving order and schedule; 10% without ack, 15% not closed, 7% never receive a deadline, 7% receive one twice) x Q1-Q5 and three statements of two or three norms | 960 | 955 / 352 / 956 / 113 | 0 |
| G | 30 random reparation chains (generator of the 4.4 self-check plus a number and a string comparison; 2-19 states) compiled by the reference compiler, 15 random histories each | 450 | 350 / 119 / 352 / 268 | 0 |
| S | the scaled sweep scenarios: ν = 1..16 at L = 32, ν = 4 at L = 8..512, ν = 1 at L = 2048 | 42 | 165 / 22 / 30 / 0 | 0 |

5,189 journals, 3,722 vendor verdicts and 1,467 audit outputs, no difference. Seed 2026, reproducible.

Scope: the oracle is independent of the Rust code and of the automata, not of the
author's reading of Definitions 3.5-3.10 (the reference, the generator and the scenarios share that reading);
data atoms are well typed only. On ill-typed comparisons (`coverage < "z"`, `= 3.0`, `>= true`) the guest and
`audit_ref` disagree: Definition 3.1 does not say what such an atom means (open point for the author).

## EQ2: disclosure

`scripts/eq2_disclosure.py` -> `results/eq2_disclosure.json`. A structural check of the public outputs, i.e. of the
deterministic part of Definition 3.11 (the proofs' own zero knowledge is assumption A4 and is not tested; neither are
the distribution of the hash values, timing, nor what several audits reveal together). The script builds the
simulator: pub(I) is the instance, participants, statement id, program id, published slice commitments and the message
log of D8, recorded at the hand-offs and not read from the slices (for the vectors' scenarios it follows from their
fixed choreography); out(S, I) is computed from the semantics; every hash value is a placeholder. The view (ν+1
journals under *verdict, responsible*; the aggregation guest's journal under *verdict*) must equal the simulation field
by field; no hash value may equal one computable from pub(I), and hash values may be equal only where check 5 pairs
them. Random histories use CSPRNG salts and nonces (with the reference model's fixed salts the hashes could be
recomputed).

* 175 views (S1-S3, 30 random histories, ν = 2 and 8; Q1-Q5): **all 175 equal to the simulation, 0 findings**
  (since 2026-10-28; before, 111 equal and 64 differing in the two classes below).
* **Fixed 2026-10-28, genesis head:** the genesis head was H('slice', instance, org), without a salt. The `own_pre` of
  an organisation's first message (and the `peer_pre` its partner stores) equalled it exactly when no internal record
  preceded that message, so the auditor learned whether there was one (64 views). Now the genesis head is
  H('slice', instance, org, salt0) with a private salt kept with the slice (`genesis_salts` in the scenario files, a
  private input of the guest); the check still compares every hash value with the unsalted value as a regression test.
* **Fixed 2026-10-28, open verdict:** under *verdict, responsible* an open vendor's journal carried its current verdict
  (`verdict` plus `settled = false`; e.g. `repaired` for vendor C of S3 under Q3), while the declared output (Def. 3.10)
  says only *open* (5 views). Now a journal that is not settled has `verdict = null`; the vectors of S3 changed
  accordingly (`reference/` regenerated).
* Pair test: the same public layer and declared output with swapped private behaviour gives identical views under Q2
  (aggregated); under Q3 the views differ exactly in the declared responsibility map.
* Journal size: a vendor's journal under Q2 is 1,354 bytes plus the instance identifier for L = 8..2048; the 1,363-1,366
  byte spread is the identifier `CVD-n1-L<L>`.

**The aggregate receipt, real proofs** (`results/eq2_aggregate_prove.json`, S1 under Q2, development machine;
organisation receipts composite, made before the switch). risc0-zkvm 3.0.6 keeps `env::verify` calls as assumptions; a
composite receipt carries the verified receipts in `CompositeReceipt::assumption_receipts`, and only
`composite_to_succinct` resolves them. Measured: the **composite** aggregate is 1,594,255 B, proved in 755 s, embeds 4
assumption receipts, and all four organisation journals can be read out of it; the **succinct** aggregate is
224,268 B, proved in 1,060 s, embeds none, no journal is readable, verifies in 0.027 s, and the auditor outputs
*violated* as expected. Hence the protocol path now uses succinct receipts only.

**Control id.** A succinct receipt carries, in the clear, the control id of the recursion program that produced it
last. risc0-zkvm 3.0.6 (`composite_to_succinct`): one segment gives `lift_rv32im_v2_<po2>.zkr`, whose name contains the
segment size, so the receipt would reveal the length band of a short slice (L of about 8, 32 or 128); two or more
segments end with `join.zkr`, and a receipt with resolved assumptions (the aggregate) with `resolve.zkr`, the same for
every length. The prover (`prove_org`) therefore executes first and, if the slice fits one segment, halves the segment
limit so that it becomes two (one extra join); the auditor rejects at check 1 any organisation receipt not finished
by `join.zkr` and any aggregate not finished by `resolve.zkr`; `bench.py` records `control_id` and
`control_program`. Not yet confirmed with real proofs: `acceptance_prove.sh` and sweep K do that.

## The D13 limit

`scripts/collusion.py` -> `results/collusion.json`. ν = 1, 2, 3 vendors, the colluding vendor in every serving
position, two schedules (phased as in vectors.py; per-vendor: disclosure and grace_end of one vendor before the next),
two rewrites (a patch inserted before the disclosure: violated -> fulfilled; before the grace_end after a mitigation:
violated -> repaired). The prediction comes from the D13 condition on record positions alone (no hashing): accepted
iff no maintainer message with an honest party follows the first maintainer record that stores a rewritten head.

22/22 cases as predicted; 8 accepted with the false verdict, 14 rejected at check 5 through an honest vendor.
Accepted: always for ν = 1; for ν = 2, 3 exactly when the colluder is served last, before the disclosure only under the
per-vendor schedule, before the grace_end under both. A consistency test of one rewrite class (insertion), not a proof.

## EQ3: cost (executor part)

* `results/cycles.csv` (+ `cycles_env.json`, guest image ids): series A, B, C, D as in Tables 6.2-6.3, rerun 28 Oct
  with the salted genesis head: about 1,000-3,000 more user cycles per slice (one extra hash input; e.g. Q2, L = 8:
  162,458 -> 163,537), padded cycles unchanged except C/chain at L = 32 (262,144 -> 524,288); aggregation guest
  unchanged.
* **Monitor size** (`results/cycles_statement_size.csv`): 64 random chains (2-21 states, 1-6 atoms) plus Q2 and Q4,
  ν = 1; cycles per internal record = slope between L = 32 and 128. It is 5,400.9 + 59 x (atoms - 1) for every chain,
  whatever the number of states: one comparison per atom, one table lookup per norm. Scope: one norm, `work` records
  that satisfy no atom; the fixed part grows with the statement's size (its tables are parsed once).
* **Record size** (`results/cycles_record_size.csv`, Q2, L = 128): internal records of 21 / 47 / 95 / 287 / 1,055 bytes
  -> 0.83 / 0.92 / 0.98 / 1.40 / 2.84 M user cycles, about 16 cycles per extra byte per record, not exactly linear
  (SHA-256 blocks). The 21-byte `work` padding of the sweeps is the cheapest case.
* **Native baseline** (`results/native_baseline.csv`, with the CPU in every row; noisy, about 25-35% between runs, so
  only the order of magnitude counts): the same Rust Algorithm 5.1 without the zkVM takes 0.03 ms (L = 8) to 3.4 ms
  (L = 2048), the Python reference guest 0.1-13 ms, the zkVM executor 0.06-0.38 s. The overhead factor of proving needs
  `prove_s` of the same machine.

## Still open

* Real proofs, hours (MEASURE.md): `acceptance_prove.sh` (the "Real proofs" columns, now `[TBD]`), then `bench.py K A B D C`
  (times, memory, receipt sizes, verification and audit time; D11's succinct size).
* Author's decisions: typing of Definition 3.1; whether the message log of D8 is
  published by someone (the simulator assumes it is part of pub(I)).
