# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/sub-manager ./cmd/server

FROM alpine:3.21
ARG VERSION=dev
ARG VCS_REF=unknown
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 10001 app \
    && adduser -S -D -H -u 10001 -G app app \
    && mkdir -p /data \
    && chown app:app /data
ENV ADDR=:8080 \
    DATA_DIR=/data \
    TZ=Asia/Shanghai
LABEL org.opencontainers.image.title="SubManager" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.source="https://github.com/saitomikuya/sub-manager"
COPY --from=builder /out/sub-manager /usr/local/bin/sub-manager
USER app
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD wget -q -O - http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/sub-manager"]
