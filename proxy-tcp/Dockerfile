# Set Go image
FROM golang:1.24.0-bullseye AS builder

ENV CGO_ENABLED=0
ENV GO111MODULE=on

# Create workspace
WORKDIR /app

# Copy the entire repository to handle the replace directive
COPY go.mod go.sum ./
COPY pkg/ ./pkg/
COPY proxy-tcp/ ./proxy-tcp/

# Build from the proxy-tcp directory
WORKDIR /app/proxy-tcp
RUN go build -o myproxy

# Final image
FROM ubuntu:22.04

WORKDIR /app
COPY --from=builder /app/proxy-tcp/myproxy /app/proxy
RUN chmod +x /app/proxy