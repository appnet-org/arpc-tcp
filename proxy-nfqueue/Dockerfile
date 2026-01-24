FROM golang:1.24.0-bullseye AS builder

ENV CGO_ENABLED=0
ENV GO111MODULE=on

WORKDIR /app

COPY go.mod go.sum ./
COPY pkg/ ./pkg/
COPY proxy-nfqueue/ ./proxy-nfqueue/

WORKDIR /app/proxy-nfqueue
RUN go build -o myproxy

FROM ubuntu:22.04

WORKDIR /app
COPY --from=builder /app/proxy-nfqueue/myproxy /app/proxy
RUN chmod +x /app/proxy
