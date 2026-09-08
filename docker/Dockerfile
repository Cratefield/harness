# syntax=docker/dockerfile:1
#
# The Cratefield "forge": the compile engine (Build Anywhere packages 2 & 3)
# in a container. `docker run --rm -v "$PWD":/work cratefield/forge \
# build manifest.json --out dist` generates a Cloudflare venture crate from
# a manifest. The image also carries the wasm target + worker-build, so a
# follow-up `worker-build` compiles the generated venture to a deployable
# Worker — the whole point of the compile engine.
#
# Deploy (wrangler) stays out of the image on purpose: it needs the
# account's Cloudflare credentials (a needs-human step), not something a
# build container should hold.

# ---- build the standalone `fz` binary ----
FROM rust:1.98-bookworm AS builder
WORKDIR /src
# Build context is the harness repo root.
COPY . .
RUN cargo build --release -p cratefield-cli --bin cratefield-cli \
 && cp target/release/cratefield-cli /usr/local/bin/fz

# ---- a working Rust toolchain that can compile a generated venture ----
FROM rust:1.98-bookworm AS forge
LABEL org.opencontainers.image.title="cratefield-forge" \
      org.opencontainers.image.description="Cratefield compile engine: fz build + worker-build"
# The wasm target and worker-build, so `worker-build --release` inside a
# generated venture produces a Worker.
RUN rustup target add wasm32-unknown-unknown \
 && cargo install worker-build
COPY --from=builder /usr/local/bin/fz /usr/local/bin/fz
# Mount the manifest here and collect the generated crate.
WORKDIR /work
ENTRYPOINT ["fz"]
CMD ["--help"]
