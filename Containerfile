FROM golang:alpine AS builder

ARG TARGETARCH

RUN apk add --no-cache \
    clang \
    llvm \
    elfutils-dev \
    libbpf-dev \
    linux-headers \
    musl-dev

WORKDIR /build

COPY . .

RUN rm go.mod && rm go.sum
RUN go mod init github.com/amaumene/xdp-etherip && \
    go mod edit -replace github.com/x86taka/xdp-etherip=./ && \
    go mod tidy

RUN mkdir -p include && \
    ln -s /usr/include/bpf/bpf_helper_defs.h include/ && \
    ln -s /usr/include/bpf/bpf_helpers.h include/ && \
    ln -s /usr/include/bpf/bpf_core_read.h include/ && \
    ln -s /usr/include/bpf/bpf_endian.h include/

RUN go generate pkg/coreelf/elf.go

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w -extldflags '-static'" \
    -o /build/bin/xdp-etherip \
    ./cmd/xdp-etherip

FROM scratch
COPY --from=builder /build/bin/xdp-etherip /xdp-etherip
