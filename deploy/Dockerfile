# Runtime image for a3s-observer-collector.
#
# Two steps (this is what .github/workflows/image.yml does, and what was validated by hand):
#   1. build the binary:   cargo build --release -p a3s-observer-collector
#   2. stage + build:      mkdir -p dist && cp target/release/a3s-observer-collector dist/
#                          docker build -f deploy/Dockerfile -t a3s-observer dist
#
# The base must match the build host's glibc — the binary is dynamically linked. CI builds on
# ubuntu-latest (24.04) and ships on ubuntu:24.04; keep them in lockstep (or build static musl
# for a distroless/scratch base).
FROM ubuntu:24.04
COPY a3s-observer-collector /usr/local/bin/a3s-observer-collector
ENV A3S_OBSERVER_JSON=1
ENTRYPOINT ["/usr/local/bin/a3s-observer-collector"]
