FROM rust:1.85-bookworm AS builder

RUN apt-get update && apt-get install -y \
    cmake clang libclang-dev pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies: copy manifests first, build a dummy, then copy real source
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

# Now copy real source and build
COPY src/ src/
COPY tests/ tests/
RUN touch src/main.rs src/lib.rs && cargo build --release

# Runtime stage — minimal image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/cltv-scan /usr/local/bin/cltv-scan

EXPOSE 3001

CMD ["cltv-scan", "serve", "-p", "3001"]
