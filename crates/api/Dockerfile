# Build from the repo root: docker build -f crates/api/Dockerfile -t antidote-api .
FROM rust:1.93-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p antidote-api

FROM debian:bookworm-slim
COPY --from=build /src/target/release/antidote-api /usr/local/bin/antidote-api
RUN useradd -r antidote && mkdir /data && chown antidote /data
USER antidote
VOLUME /data
EXPOSE 8080
# Mount a signed feed.json + feed.json.minisig at /data and add `--feed /data/feed.json`
ENTRYPOINT ["antidote-api", "--db", "/data/stats.sqlite", "--listen", "0.0.0.0:8080"]
