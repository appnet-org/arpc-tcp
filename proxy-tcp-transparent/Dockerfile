# Set Go image
FROM golang:1.24.0-bullseye AS builder

ENV CGO_ENABLED=0
ENV GO111MODULE=on

# Create workspace
WORKDIR /app

# Copy the entire repository to handle the replace directive
COPY go.mod go.sum ./
COPY pkg/ ./pkg/
COPY proxy-tcp-transparent/ ./proxy-tcp-transparent/

# Build from the proxy-tcp-transparent directory
WORKDIR /app/proxy-tcp-transparent
RUN go build -o myproxy

# Final image
FROM ubuntu:22.04

WORKDIR /app
COPY --from=builder /app/proxy-tcp-transparent/myproxy /app/proxy
RUN chmod +x /app/proxy

# Note: TPROXY requires CAP_NET_ADMIN capability
# Run with: docker run --cap-add=NET_ADMIN --cap-add=NET_RAW ...

