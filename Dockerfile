FROM rust:1.89 AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY templates ./templates

RUN cargo build --release

FROM gcr.io/distroless/cc-debian12

WORKDIR /app
COPY --from=builder /app/target/release/auth .
COPY --from=builder /app/templates ./templates
COPY private_key.pem ./private_key.pem
COPY public_key.pem ./public_key.pem
COPY GeoLite2-Country.mmdb ./GeoLite2-Country.mmdb

EXPOSE 3001
CMD ["./auth"]