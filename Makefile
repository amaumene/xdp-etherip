NAME := xdp-etherip

#branch name version
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
ARCH ?= arm64

PKG_NAME=$(shell basename `pwd`)

LDFLAGS := -ldflags="-s -w  -X \"github.com/x86taka/xdp-etherip/pkg/version.Version=$(VERSION)\" -extldflags \"-static\""
SRCS    := $(shell find . -type f -name '*.go')

.DEFAULT_GOAL := build
build: $(SRCS)
	go build $(LDFLAGS) -o ./bin/$(NAME) ./cmd/$(NAME)

.PHONY: run
run:
	go run $(LDFLAGS) ./cmd/$(NAME)

.PHONY: gen
gen:
	go generate pkg/coreelf/elf.go

.PHONY: container-build
container-build:
	podman build --platform linux/$(ARCH) -f Containerfile -t $(NAME)-static .
	mkdir -p bin
	podman create --name $(NAME)-extract $(NAME)-static
	podman cp $(NAME)-extract:/$(NAME) bin/$(NAME)-static-aarch64
	podman rm $(NAME)-extract

.PHONY: clean
clean:
	rm -rf ./bin

.PHONY: test
test:
	go test -v -race ./...
test-bpf:
	go test -v -exec sudo ./pkg/coreelf/...

.PHONY: fmt
fmt:
	go fmt ./...
	find . -iname '*.h' -o -iname '*.c' | xargs clang-format -i -style=Google

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: cover
cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
