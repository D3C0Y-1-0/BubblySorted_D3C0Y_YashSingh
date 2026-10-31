FROM rust:1-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /src/target/release/account /usr/local/bin/account
ENV PORT=8080 ACCESS_LOG=/app/logs/access.log
EXPOSE 8080
CMD ["account"]
