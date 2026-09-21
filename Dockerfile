# optimusIssuer — the frontend is built first and embedded into the Go binary,
# so the runtime image is a single static executable with no web server, no
# node runtime and nothing else to keep patched.

# ── stage 1: build the single-page application ──────────────────────────────
FROM node:26-alpine AS web
WORKDIR /web
COPY web/package*.json ./
# npm ci installs exactly what package-lock.json pins, which is what a
# reproducible build needs — but it refuses to run without a lockfile. Fall
# back to npm install on a fresh checkout that has not generated one yet.
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY web/ ./
RUN npm run build
# vite writes to ../cmd/issuerd/webdist, which lands at /cmd/issuerd/webdist

# ── stage 2: build the service ──────────────────────────────────────────────
FROM golang:1.27-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# .dockerignore excludes cmd/issuerd/webdist, so this copy is the only source
# of the embedded assets and never races with a stale local build.
COPY --from=web /cmd/issuerd/webdist ./cmd/issuerd/webdist

# The assets must exist before go build, because cmd/issuerd/main.go embeds
# them. An empty embed is otherwise silent until someone opens a browser, so
# fail here with a message that names the cause.
RUN ls -la ./cmd/issuerd/webdist \
 && test -f ./cmd/issuerd/webdist/index.html \
 || (echo "ERROR: webdist/index.html missing — stage 1 produced nothing" && exit 1)
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
        -o /out/issuerd ./cmd/issuerd \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
        -o /out/issuerctl ./cmd/issuerctl

# ── stage 3: runtime ────────────────────────────────────────────────────────
FROM alpine:3.19

LABEL org.opencontainers.image.title="optimusIssuer" \
      org.opencontainers.image.description="Credential issuance for the OptimusDB swarm" \
      org.opencontainers.image.source="https://github.com/georgeGeorgakakos/optimusIssuer" \
      org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -u 10001 issuer

COPY --from=build /out/issuerd   /usr/local/bin/issuerd
COPY --from=build /out/issuerctl /usr/local/bin/issuerctl

# The key is mounted read-only at runtime; it is never baked into the image.
USER 10001
EXPOSE 8090

# Reports unhealthy while the agent is unreachable, which is the condition that
# stops issuance. Verification by the agents is a separate path and unaffected.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8090/api/v1/issuer/health >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/issuerd"]
