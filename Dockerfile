# syntax=docker/dockerfile:1.7
#
# PodPulse multi-arch image. Contains all three binaries
# (pp-detector, pp-tailer, podpulse) in /usr/local/bin.

FROM --platform=$BUILDPLATFORM golang:1.26 AS build

WORKDIR /src

# Cache deps separately from sources.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETOS TARGETARCH
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go build -trimpath -ldflags="-s -w" -o /out/pp-detector ./cmd/pp-detector && \
    go build -trimpath -ldflags="-s -w" -o /out/pp-tailer   ./cmd/pp-tailer   && \
    go build -trimpath -ldflags="-s -w" -o /out/pp-connect  ./cmd/pp-connect  && \
    go build -trimpath -ldflags="-s -w" -o /out/podpulse    ./cmd/podpulse

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/pp-detector /usr/local/bin/pp-detector
COPY --from=build /out/pp-tailer   /usr/local/bin/pp-tailer
COPY --from=build /out/pp-connect  /usr/local/bin/pp-connect
COPY --from=build /out/podpulse    /usr/local/bin/podpulse

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/pp-detector"]
