# Multi-stage, distroless (issue #19): build the example native venture
# on a Rust image, run it on distroless with nothing but glibc and the
# binary. rustls uses webpki-roots compiled into the binary, so the
# runtime image needs no CA bundle, no shell, no package manager.
#
# Dependency layers are not cached separately (no cargo-chef): this is
# an example, and the workspace-wide COPY keeps the Dockerfile honest
# about what the build needs. Production ventures copy this file from
# the template and add cargo-chef if their CI budget cares.
FROM rust:1-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --bin venture-native

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /build/target/release/venture-native /app/venture-native
ENV LISTEN_ADDR=0.0.0.0:8080
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/venture-native"]
