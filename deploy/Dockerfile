# Build the collector (with the eBPF toolchain) then ship just the binary.
# Build from the crate root:  docker build -f deploy/Dockerfile -t a3s-observer:0.2.0 .
#
# bpf-linker borrows rustc's bundled LLVM (aya-rustc-llvm-proxy), so no system LLVM is
# needed; build.rs compiles the eBPF crate with the nightly toolchain + rust-src.

FROM rust:1-bookworm AS build
RUN rustup toolchain install nightly --component rust-src \
 && cargo install bpf-linker
WORKDIR /src
COPY . .
RUN cargo build --release -p a3s-observer-collector

FROM debian:bookworm-slim
COPY --from=build /src/target/release/a3s-observer-collector /usr/local/bin/a3s-observer-collector
ENV A3S_OBSERVER_JSON=1
ENTRYPOINT ["/usr/local/bin/a3s-observer-collector"]
