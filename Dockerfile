FROM rust:1.87 as builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY templates ./templates

RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/auth .
COPY --from=builder /app/templates ./templates

EXPOSE 3001
CMD ["./auth"]