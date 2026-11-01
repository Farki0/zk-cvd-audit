# Runtime image of the CVD-audit artifact (thesis, Chapter 6). A failing line is most likely an installer URL or a
# version tag.
#
#   docker build -t cvd-audit .
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/out:/out" cvd-audit smoke       # minutes: build check + executor-only acceptance
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/out:/out" cvd-audit reproduce   # about 10 minutes: the evaluation without proofs
#   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/out:/out" cvd-audit reproduce-prove   # about 12 hours, real proofs, 16 GB RAM
# `--user` makes the files in out/ yours instead of root's; the toolchains and /cvd-audit are writable for any user.
# Released images: ghcr.io/farki0/zk-cvd-audit:<tag> (built by .github/workflows/release.yml).
# The entry point is `just`: any recipe of the justfile is an argument (`tab-disclosure`, `plan`, ...).
#
# Versions are the ones of rust-toolchain.toml, Cargo.lock and MEASURE.md: RISC Zero 3.0.6 (CPU prover), rzup rust 1.97.0.
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG JUST_VERSION=1.36.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential pkg-config libssl-dev python3 python3-pip git curl ca-certificates xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sSf https://just.systems/install.sh | bash -s -- --tag "${JUST_VERSION}" --to /usr/local/bin

ENV HOME=/root
ENV PATH=/root/.risc0/bin:/root/.cargo/bin:${PATH}

# Rust (the host's version comes from rust-toolchain.toml) and the RISC Zero toolchain, pinned. Everything under /root is
# made writable for any user, so that the image also runs with `--user` (HOME stays /root).
WORKDIR /cvd-audit
COPY rust-toolchain.toml ./
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain none \
    && rustup toolchain install \
    && curl -L https://risczero.com/install | bash \
    && rzup install cargo-risczero 3.0.6 \
    && rzup install r0vm 3.0.6 \
    && rzup install rust 1.97.0 \
    && rzup install cpp 2024.1.5 \
    && rzup show \
    && chmod -R a+rwX /root

COPY requirements.txt ./
RUN python3 -m pip install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .
# Compile the host and the guests once, so that `reproduce` does not start with the long first build.
RUN cargo build --release \
    && chmod -R a+rwX /root/.cargo /cvd-audit

ENV OUT=/out
VOLUME ["/out"]
ENTRYPOINT ["just"]
CMD ["--list"]
