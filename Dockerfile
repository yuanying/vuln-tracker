# Build vuln-tracker as a static binary and ship it with the trivy binary on a
# base with nothing else on it.
#
# trivy is copied from its own image, so the version is stated in one place
# and Renovate moves it. Keep it on the minor of the Trivy server the tracker
# scans through (ADR 0003): trivy-operator's server is 0.75.

FROM golang:1.27 AS build
WORKDIR /src

COPY go.mod go.sum ./
COPY cmd/ cmd/
COPY internal/ internal/

# CGO off makes the result static, which is what lets it run on a base image
# with no libc. The caches are mounts rather than layers so that rebuilding
# after an edit does not start from an empty module cache.
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/vuln-tracker ./cmd/vuln-tracker

FROM mirror.gcr.io/aquasec/trivy:0.75.0 AS trivy

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=build /out/vuln-tracker /vuln-tracker
# 65532 is distroless's "nonroot"; the Deployment names the same number so the
# manifest and the image cannot disagree about who this runs as.
USER 65532:65532
ENTRYPOINT ["/vuln-tracker"]
