# reference/

Copied from the reference package of the thesis (2026-10-12); the code is unchanged apart from one comment and the
locality check of `vectors.py` (`check_local`: every atom of a norm has an event type its bearer role records), which
leaves the vectors byte-identical. `python3 code/vectors.py locality` checks Q1-Q5 and that a non-local norm is rejected.

| Here | Copied from | What it is |
| --- | --- | --- |
| `vectors/` | `vectors/` | hash examples, the five statements Q1-Q5 as monitor tables, scenarios S1-S3, `attacks.json`, `expected_summary.json` |
| `code/audit_protocol.py`, `code/audit_ref.py`, `code/vectors.py` | `code/` | the Python reference model that generated the vectors; `vectors.py` also makes the measurement scenarios (`scenario --vendors N --length L`) |

`scripts/acceptance.sh` regenerates the vectors from `code/vectors.py golden` and checks that they are byte-identical to
`vectors/`, so a drift between the two cannot go unnoticed. Python needs `pip install -r ../requirements.txt`
(`cryptography`, for Ed25519). The other files of the package's `code/` (`.dot` graphs, text outputs) are not needed and
are not copied.