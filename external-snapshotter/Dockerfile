# Stage 1: build binary
FROM golang:1.23.6 AS builder
WORKDIR /workspace
COPY . .
RUN cd cmd/snapshot-controller && go build -o /workspace/snapshot-controller

# Stage 2: minimal runtime image
FROM gcr.io/distroless/base-debian12
COPY --from=builder /workspace/snapshot-controller /snapshot-controller
ENTRYPOINT ["/snapshot-controller"]
