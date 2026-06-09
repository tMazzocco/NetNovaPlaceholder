# ---- build ----
FROM rust:1.95-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin wazuh-slack

# ---- runtime ----
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/wazuh-slack /usr/local/bin/wazuh-slack
ENTRYPOINT ["wazuh-slack"]
