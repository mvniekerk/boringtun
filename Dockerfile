# Build stage
FROM rust:1.89 AS builder

WORKDIR /usr/src/boringtun
COPY . .

# Build the boringtun-cli binary
RUN cargo build --release -p boringtun-cli


# Final stage
FROM debian:trixie-slim

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y libc6 libssl3 ca-certificates wireguard && \
    rm -rf /var/lib/apt/lists/*

# Copy the built binary from the builder stage
COPY --from=builder /usr/src/boringtun/target/release/boringtun-cli /usr/local/bin/boringtun-cli

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/boringtun-cli"]