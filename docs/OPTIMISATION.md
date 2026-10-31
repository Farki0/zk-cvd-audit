# Guest optimisation: what changed, and what it bought

The first working guest was correct but slow. Proving time on the development machine (a 2019 laptop CPU under WSL2,
12 threads, 9.7 GiB) is proportional to the padded cycle count, about 265 s per million cycles, so cycles are what
matter. This note records what was changed and the measured effect. Nothing about the *protocol* changed: journals,
hash formats, record encoding, statement tables, verdicts and auditor checks are identical, which the acceptance
tests confirm (see "No format changed").

## What was changed

All changes are in `core/src/lib.rs` (shared by guest and host) and in how the host hands the slice to the guest.

1. **Hashing without allocation.** `H(...)` used to build a `String` per call, hex-encode digest bytes with
   `Vec::push`, and make two `update` calls per part. Now `hh()` assembles `len || bytes` of all parts in a 256-byte
   stack buffer, calls the SHA-256 accelerator once, and writes the 64 hex characters into a stack array through a
   256-entry lookup table. The chain step `link(head, H(rec, salt, enc(r)))` runs on these stack values; only the
   final head becomes a `String`. (Every call into the accelerator costs about 300 cycles for small inputs, so fewer,
   larger calls matter more than bytes.)
2. **A flat-JSON scanner instead of `serde_json::Value`.** Records are flat objects as produced by `enc()`. A small
   scanner reads `type` and the other fields as borrowed slices without a tree or per-field allocation. Anything it
   does not understand (escapes, nesting, whitespace) falls back to `serde_json`, so every valid JSON object is still
   accepted, and the semantics of `holds()` (same JSON type on both sides, strings only `=`/`!=`, missing field is
   false) are unchanged. The guest still hashes the encoded string exactly as given and never re-encodes.
3. **Private input as raw bytes.** The slice used to be read with `env::read::<Vec<(String,String)>>()` (risc0's
   word-oriented serde). The host now sends one length-prefixed byte blob (`encode_entries`) read with `read_slice`,
   and the guest borrows `&str` views into it. This is a transport detail of the private input, not a format of the
   protocol.
4. **Tried and dropped:** the `heap-embedded-alloc` feature of the zkVM (a freeing allocator). It raised the user
   cycles and did not lower the padded cycles, so the default bump allocator stays.

The SHA-256 accelerator (RISC Zero's `sha2` fork, `[patch.crates-io]` in `methods/guest/Cargo.toml`) was in use from the
start and is not part of this optimisation.

## Cycle counts before and after

"User cycles" are the instructions the guest executes; "padded" is the sum of 2^po2 over the segments, which is what
the prover pays for (it adds paging and rounds each segment up to a power of two). The *before* numbers were taken
during development from the first working guest, before the repository existed, so there is no commit to point to;
the *after* numbers are reproducible with `scripts/cycles.py` (`results/cycles.csv`).

**S1, statement Q3, vendorB (7 records), one real proof each time:**

|  | user cycles | padded cycles | segments | prove time | peak RSS | receipt |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| before | 204,054 | 524,288 | 1 | 159 s | 4.8 GB | 270,918 B |
| after  | 199,072 | 262,144 | 1 | 66.5 s | 2.4 GB | 258,694 B |

For a short slice the gain comes from the padding: the program now fits into 2^18 instead of 2^19 cycles. The fixed
cost of starting the guest and reading the statement (about 60-100k cycles) dominates there.

**Q2, n = 1, variant full, executor only (user cycles / segments), growing slices:**

| L | before | after |
| ---: | ---: | ---: |
| 32 | 432,828 / 1 | 295,429 / 1 |
| 128 | 1,321,024 / 2 | 830,876 / 1 |
| 512 | 4,892,608 / 6 | 2,989,396 / 4 |
| 2048 | not measured | 11,593,099 / 13 |

The marginal cost per record fell from about 9,300 to about 5,600 cycles (1.65x). What is left is mostly two SHA-256
accelerator calls per record (about 1,000-1,300 cycles each with the hex conversion) plus the scan and the monitor
step. A further gain would need a different chain format (for example hashing raw digests instead of their hex
strings), which would change the vectors, so it was not done.

## No format changed

After the last code change the executor acceptance was run again from a fresh clone (`scripts/acceptance.sh`):
10/10 hash examples, 55/55 journals equal to the vectors field by field, 15/15 auditor outputs equal to
`expected_summary.json`, 11/11 attacks rejected at the expected place and the limit case accepted with `complied`;
and `reference/vectors/` is byte-identical to what `reference/code/vectors.py golden` regenerates. The run's logs are
in its `runs/acceptance-*` directory (not committed; `scripts/acceptance.sh` recreates them).