# Publishing checklist

Copy this file to `PUBLISHING.md` at the repository root when you start preparing the Zenodo
release. From then on, the `hygiene` workflow runs the publication gate (`just hygiene --publish`),
which checks everything a script can check. The items below are the rest. Tick each one and
write the evidence after it: a commit, a file and line, a command and its output, or a link. An
advisor signs the list off by approving the pull request that completes it. `.gitattributes`
keeps this file out of the Zenodo archive.

Filled in on 2026-11-01 by Claude Opus 5.5 (Claude Code) for Martin Farkas, on branch `publish/gate`, against
`main` at 90288da. An unticked item is open, with the reason after it.

## Results

- [ ] `just reproduce` regenerates every figure and table in the paper, and `just reproduce --smoke`
      finishes in minutes. Evidence:
      - **Open, blocks `v1.0.0`:** the committed results are not the ones the paper reports. `results/` holds the
        measurement of 2026-10-29 (`results/bench_env.json`: `git_commit` 90125d7, older guest binaries;
        `docs/ARTIFACT.md` "Guest image ids" says so). The paper's numbers come from the later v1.0.0-rc1 rerun on the
        same machine, which is in `cvd-audit/results/` of Farki0/zk-bpmn at `main`. For example, the paper's
        `figures/data/eq3_length.csv` has the L = 8 proving time `38.910080121` s. That value occurs twice in
        zk-bpmn's `measurements.csv` and not at all here. 12 of the 19 shared result files differ, and
        `zk_overhead.csv`, `wall_times_bench.csv` and `wall_times_scripts.csv` are missing here. The code is the same
        apart from comments and one summary key (`D13_collusion` is now `coalition_limit` in `scripts/evaluate.sh`),
        so the rc1 files apply. Bringing them in is Ádám's or Martin's call.
      - The recipes: `just reproduce` (`justfile:19`, `scripts/reproduce.sh`) regenerates the result files (JSON, CSV)
        behind every data table and figure. The LaTeX tables and the figure data are generated from them in the paper
        repository (`docs/ARTIFACT.md:50`). The paper's other figures are drawn diagrams.
      - `just reproduce --smoke` now runs `scripts/reproduce.sh --smoke` (`justfile:19-20`; `just -n reproduce --smoke`
        prints `scripts/reproduce.sh --smoke`). On 2026-11-01, with Docker 29.9.2:
        - `docker build -t zk-cvd-audit:test .` from this branch (image 9.6 GB);
        - `docker run --rm --user 1000:1000 -v …:/out zk-cvd-audit:test reproduce --smoke` →
          `ACCEPTANCE (executor only) PASSED`, `REPRODUCE (smoke) PASSED`, with `out/` owned by 1000:1000;
        - the same in the dev container (`@devcontainers/cli` up, then exec `just reproduce --smoke` as uid 1000) →
          `REPRODUCE (smoke) PASSED`.
        Each run took a few minutes after the build. Before the scripts got their executable bit back, the smoke run
        failed with `scripts/reproduce.sh: Permission denied`.
- [x] Recipes are named after their outputs, such as `fig-scalability` or `tab-robustness`. Evidence:
      `justfile:29-55`: `tab-correctness`, `tab-attacks`, `tab-disclosure`, `tab-coalition`, `fig-scalability`,
      `fig-proving-times`, `tab-overhead`. A few rows of the results map run a script directly (`scripts/evaluate.sh`,
      `scripts/bench.py …`, `README.md:35-47`).
- [ ] The results map has one row per figure and table of the paper, each with its command,
      output path and time on the stated hardware. Evidence: `README.md:27-47`, copied from Ádám's
      `docs/ARTIFACT.md:34-48`: 13 rows, each with command, output and time; the hardware is stated at `README.md:29-31`.
      **Open:** the rows name tables by topic, not by the paper's numbering. The paper's data items are Table
      `tab:eval-summary`, Figures `fig:eq3-length` and `fig:eq3-vendors`, and the appendix tables `tab:eq1-verdicts`,
      `tab:attacks`, `tab:eq3-times`, `tab:cycles-length` and `tab:cycles-vendors`. The times in the map are those of
      the rc1 run (for example A 3372 s), which `results/` does not hold yet (see the first item).
- [ ] Every dependency is pinned in the `Dockerfile` and the lockfiles. Evidence: pinned are Rust 1.94.1
      (`rust-toolchain.toml`), RISC Zero `cargo-risczero 3.0.6`, `r0vm 3.0.6`, rzup `rust 1.97.0`, `cpp 2024.1.5`
      (`Dockerfile:33-36`), `just 1.36.0` (`Dockerfile:16`), `cryptography==41.0.7` (`requirements.txt`), and the crates
      in `Cargo.lock` and `methods/guest/Cargo.lock`. **Open:** the base image is the tag `ubuntu:24.04`, not a digest
      (`Dockerfile:13`); apt packages and Python 3.12 come unpinned from it; the rustup and RISC Zero installer scripts
      are fetched at their latest version (`Dockerfile:30,32`). The toolchains they install are pinned.

## Metadata

- [x] The license was agreed with the advisors: Apache 2.0 for a tool, MIT otherwise. Evidence: MIT, Martin's ruling
      of 2026-10-31 for this artifact (results of a paper, not a tool). `LICENSE`, `.zenodo.json:6`, `CITATION.cff:11`.
- [x] `related_identifiers` in `.zenodo.json` lists `isDerivedFrom` for a fork's upstream and
      `isSupplementTo` for each paper with a DOI, and nothing else. Evidence: no entry. The repository is not a fork,
      and the paper has no DOI or public URL yet (an unpublished TDK paper). Once it has one, add
      `{"identifier": "<paper DOI>", "relation": "isSupplementTo", "resource_type": "publication-article"}` in a later
      version.
- [x] A fork keeps the upstream license, names the upstream authors in `.zenodo.json` and says
      in the README what it changed. Write "not a fork" otherwise. Evidence: not a fork
      (`gh api repos/Farki0/zk-cvd-audit --jq .fork` → `false`). The code moved here from Ádám's own Farki0/zk-bpmn,
      where he wrote it.
- [x] A tool has the tool README sections, `MAINTAINERS.md` and `SECURITY.md`. Write "results
      only" otherwise. Evidence: results only.

## Before going public

The repository is already public (`gh api repos/Farki0/zk-cvd-audit --jq .visibility` → `public`).

- [x] Every history warning of `just hygiene --publish` has been read. The history is not rewritten:
      each warning is either harmless once public or listed here with why it is acceptable. Evidence:
      `python3 scripts/hygiene.py --publish` → `0 error(s), 6 warning(s)`. One is a history warning:
      `results/bench_commands.log` in fb1be11 has `/home/<user>/…` run directories (5 lines). It names a user directory
      only, no credentials. The current file has `runs/bench`, and `scripts/bench.py` now writes relative paths. The
      history has no paper sources, private links or agent identities: all 6 commits are authored and committed by
      `Farki0 <farkasadam02002@gmail.com>`.
- [x] Every secret gitleaks ever found has been rotated: the key, token or wallet no longer
      works or holds anything. Evidence: gitleaks finds none. On a mirror clone (6 commits),
      `docker run --rm -v …/zk-cvd-audit.git:/repo ghcr.io/gitleaks/gitleaks:latest git /repo --redact` →
      `no leaks found` (2026-11-01). No key-like file is tracked (the gate's `secret-file` check passes).
- [x] No link points to a same-year TDK paper. Evidence: `git grep -nIiE "vc-rollup|halo2|fabric-vdr|tamarin|
      byzantine|csillag2004|gaborkoncz73|snktibor|Frigyes309|TDK26"` → no hits. The tree's private-link check passes.
      `docs/ARTIFACT.md:50` names the paper repository's generator by path, without a link.
- [ ] No AI app or bot is a collaborator or installed app with write access (Settings,
      Collaborators and GitHub Apps). Evidence: `gh api repos/Farki0/zk-cvd-audit/collaborators` → `BlackLight54`
      (write) and `Farki0` (admin), both people. **Open:** installed GitHub Apps need the owner's view: Ádám checks
      <https://github.com/Farki0/zk-cvd-audit/settings/installations>.
- [x] A `CLAUDE.md` or `AGENTS.md` that documents the code was renamed, so the archive keeps it.
      Evidence: none is tracked (`git ls-files | grep -iE "claude|agents\.md|\.codex|\.cursor|gemini"` → nothing).

## Release (the student's steps, after the pull request merges)

- [ ] The repository and its ghcr.io package are public, and an anonymous
      `docker manifest inspect ghcr.io/farki0/zk-cvd-audit:v1.0.0` succeeds. Evidence:
- [ ] Zenodo is enabled for the repository, and release `v1.0.0` is tagged on the commit whose
      results match the paper. Evidence:
- [ ] The Zenodo record's files and metadata are checked, including both supervisors. The
      concept DOI badge in the README resolves. Evidence:
