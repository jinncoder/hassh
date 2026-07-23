# syntax=docker/dockerfile:1

##############################################################################
# Multi-stage build for cmd/sshproxy.
#
# Development iteration is handled by Docker Compose Watch
# (https://docs.docker.com/compose/how-tos/file-watch/) via the
# `develop.watch` section in docker-compose.yml, not by anything in this
# Dockerfile. `docker compose watch` rebuilds and recreates the service
# automatically whenever a watched file changes -- Docker's own documented
# pattern for compiled languages is `action: rebuild`, which is equivalent
# to Compose running `docker compose up --build` for you on every save.
#
# Because a fresh image is built on every change, there's no need for a bind
# mount, a live-reload daemon, or the Go toolchain in the final image here --
# just a normal multi-stage build. BuildKit cache mounts keep repeated
# `docker compose watch` rebuilds fast without relying on Compose-level
# volumes (which only attach at container runtime, not during `docker
# build`, so they can't speed up `go mod download`/`go build` anyway).
#
#   docker compose watch      # rebuild-on-change dev loop
#   docker compose up         # run once, no watching
##############################################################################

FROM golang:1.25.7-bookworm AS builder

# golang:*-bookworm ships gcc/g++/libc6-dev/make/pkg-config, which CGO needs
# to build gorm's sqlite driver (mattn/go-sqlite3) -- nothing extra required.
ENV CGO_ENABLED=1

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -o /out/hassh-proxy ./cmd/sshproxy

##############################################################################

FROM debian:bookworm-slim

# The compiled binary is dynamically linked against glibc (CGO), so the
# runtime image needs a matching glibc base -- not distroless/alpine/scratch.
RUN groupadd --system sshproxy \
    && useradd --system --gid sshproxy --no-create-home sshproxy \
    && mkdir -p /data \
    && chown sshproxy:sshproxy /data

RUN apt update && apt install -yq sshpass openssh-client && apt clean;

COPY --from=builder /out/hassh-proxy /usr/local/bin/hassh-proxy

USER sshproxy
EXPOSE 2222

ENTRYPOINT ["/usr/local/bin/hassh-proxy"]
CMD ["-listen", ":2222", "-target", "testsshd:22", "-db", "/data/ssh_connections.db"]

HEALTHCHECK --interval=2s --timeout=5s --retries=3 \
    CMD sshpass \
            -p "testpass" \
            ssh -p 2222 \
                -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null \
                testuser@localhost id \
        || exit 1

