# PermissionCenter-Server – Multi-Stage-Build
# 1) Web-Oberfläche bauen  2) Server mit eingebetteter UI bauen  3) schlankes Laufzeit-Image

FROM node:24-bookworm-slim AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY --from=web /src/web/dist ./web/dist
RUN cargo build --release --locked -p pc-server \
    && cp target/release/pc-server /usr/local/bin/pc-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /var/lib/permissioncenter permcenter \
    && mkdir -p /var/lib/permissioncenter/client-releases \
    && chown -R permcenter /var/lib/permissioncenter
COPY --from=build /usr/local/bin/pc-server /usr/local/bin/pc-server
USER permcenter
WORKDIR /var/lib/permissioncenter
ENV PC_LISTEN=0.0.0.0:8080 \
    PC_CLIENT_RELEASES_DIR=/var/lib/permissioncenter/client-releases \
    TZ=Europe/Berlin
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD ["pc-server", "healthcheck", "--addr", "127.0.0.1:8080"]
ENTRYPOINT ["pc-server"]
CMD ["serve"]
