# Build on the build machine's architecture and cross-compile for the target
# (no emulation needed for multi-arch images).
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27-trixie AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN go test ./... \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/traefik-gatekeeper ./cmd/traefik-gatekeeper

# Run: distroless, no shell, no package manager.
FROM gcr.io/distroless/static-debian13
COPY --from=build /out/traefik-gatekeeper /traefik-gatekeeper
# Non-root by default. With rootless Docker/Podman, where the mounted files are
# owned by your host account (uid 0 inside the container), run with user 0:0.
USER 65532:65532
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/traefik-gatekeeper", "healthcheck"]
ENTRYPOINT ["/traefik-gatekeeper"]
