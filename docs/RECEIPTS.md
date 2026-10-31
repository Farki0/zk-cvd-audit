# Receipt kinds, zero knowledge and receipt size (RISC Zero 3.x)

Which receipt kind the prototype uses, and why. Sources were read on 2026-10-12; quotes are from the
crate source of `risc0-zkvm 3.0.6` (the version this repository pins) unless a URL says otherwise.

## Which receipt kinds exist

| Kind (`InnerReceipt`) | What it is | Made by |
| --- | --- | --- |
| `Composite` | "a non-succinct `CompositeReceipt`, made up of one inner receipt per segment" | `ProverOpts::composite()` (default) |
| `Succinct` | "proving arbitrarily long zkVM computations with a single STARK"; "a constant sized proof can be generated for arbitrarily long computations, and with an arbitrary number of segments" | `ProverOpts::succinct()` (recursion over the composite receipt) |
| `Groth16` | a single Groth16 SNARK over BN254, made by verifying a succinct receipt inside a Groth16 circuit | `ProverOpts::groth16()` |
| `Fake` | "no cryptographic integrity, used only for development" (dev mode) | `RISC0_DEV_MODE` |

This prototype uses succinct receipts on the protocol path (acceptance with real proofs, sweeps A-D, the
aggregate) and composite ones only in sweep K, for comparison. Groth16 is out of scope.

## Zero knowledge

* The `risc0-zkvm 3.0.6` documentation of `InnerReceipt` says: "A lower level receipt, containing the cryptographic
  seal (i.e. zero-knowledge proof) ... **All inner receipt types are zero-knowledge proofs of execution for a RISC-V
  zkVM.**" (`src/receipt.rs`; rendered at <https://docs.rs/risc0-zkvm/3.0.6/risc0_zkvm/enum.InnerReceipt.html>).
  The `Receipt` type is described there as "a zero-knowledge proof of computation".
* The official proof-system overview describes the kinds as "a vector of ZK-STARKs, one for each segment"
  (composite), "a single ZK-STARK proving an entire Session" (succinct) and "a single Groth16 proof for an entire
  Session" (Groth16): <https://dev.risczero.com/proof-system/>. The protocol itself is in the RISC Zero ZKP
  whitepaper linked from that page; the overview does not discuss the zero-knowledge property in more detail.

So, according to the documentation, composite and succinct receipts are zero knowledge, and so is the Groth16 one
(because it only proves that a verifying succinct receipt exists). For Definition 3.10 either composite or succinct is
acceptable. What the documentation does **not** state is the strength (statistical or computational) or the parameters
of the blinding; the thesis should cite the whitepaper for that and not claim more than the documentation says.
`[CHECK]` the whitepaper before writing a precise zero-knowledge theorem.

## Does the receipt size depend on the execution length?

* **Composite: yes.** It contains one segment receipt per segment, and the number of segments (and each segment's
  size parameter po2) follows from the number of cycles. Measured on the development machine (S1, Q3, vendorB, same
  slice, only the segment limit changed): 1 segment of 2^18 cycles -> 258,694 B; 3 segments of 2^17 -> 735,242 B.
  The size therefore reveals the length of the execution, up to the granularity of a segment. The journal size does
  not depend on the slice length (`results/cycles.csv`, column `journal_bytes`: 1,363-1,366 B for L = 8 ... 2048).
* **Succinct: no, by construction** ("constant sized ... for arbitrarily long computations", see the quote above;
  `src/receipt/succinct.rs`). Sweep K measures both kinds at L = 128 and L = 512 (1 and 4 segments); the succinct size
  should be the same at both. This has not been measured yet.
* **Groth16: constant**, not measured here.

Consequence for the protocol (Section 5.4, "Confidentiality", second qualification): with composite receipts the
auditor learns the order of magnitude of each organisation's slice length from the receipt size. Using succinct
receipts removes that channel from the receipt (the proving time and the cycle count are not part of what the
auditor receives). Padding every slice to an agreed length would also work, at the cost shown in sweep A.