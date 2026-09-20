# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS build
WORKDIR /src

# Dependencies are their own layer, so editing code does not redownload them.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

# CGO off produces a static binary that runs on a distroless base.
# -trimpath drops local paths, -s -w drops the symbol table.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
      -trimpath -ldflags="-s -w" \
      -o /out/api ./cmd/api

# Distroless carries CA certs, which the Google OIDC calls in phase 4 need, and
# tzdata. It ships no shell, so there is nothing to exec into if the image is
# ever compromised.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/api /api
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/api"]
