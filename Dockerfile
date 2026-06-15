# syntax=docker/dockerfile:1.7
FROM golang:1.26-alpine3.24 AS build

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG VERSION=dev
ARG GIT_COMMIT=unknown
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build \
      -ldflags "-s -w -X 'main.Version=${VERSION}' -X 'main.GitCommit=${GIT_COMMIT}'" \
      -o /out/local-kms ./cmd/local-kms


# Build the final container with just the resulting binary
FROM alpine:3.24

ARG VERSION=dev
ARG GIT_COMMIT=unknown

LABEL org.opencontainers.image.title="local-kms" \
      org.opencontainers.image.description="Mock AWS KMS for local dev/testing." \
      org.opencontainers.image.source="https://github.com/DAcodedBEAT/local-kms" \
      org.opencontainers.image.url="https://github.com/DAcodedBEAT/local-kms" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}"

RUN apk add --no-cache wget ca-certificates \
 && mkdir -p /init /data

COPY --from=build /out/local-kms /usr/local/bin/local-kms

ENV KMS_ACCOUNT_ID=111122223333 \
    KMS_REGION=eu-west-2 \
    KMS_DATA_PATH=/data \
    PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q --spider "http://127.0.0.1:${PORT}/_health" || exit 1

ENTRYPOINT ["local-kms"]
