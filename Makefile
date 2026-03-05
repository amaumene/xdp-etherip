NAME := xdp-etherip

#brunch name version
VERSION := $(shell git rev-parse --abbrev-ref HEAD)

PKG_NAME=$(shell basename `pwd`)

LDFLAGS := -ldflags="-s -w  -X \"github.com/x86taka/xdp-etherip/pkg/version.Version=$(VERSION)\" -extldflags \"-static\""
SRCS    := $(shell find . -type f -name '*.go')

.DEFAULT_GOAL := build
build: $(SRCS) gen
	go build $(LDFLAGS) -o ./bin/$(NAME) ./cmd/$(NAME)

.PHONY: run
run:
	go run $(LDFLAGS) ./cmd/$(NAME)

.PHONY: gen
gen:
	go generate pkg/coreelf/elf.go

.PHONY: container-build
container-build:
	podman build --platform linux/arm64 -f Containerfile -t $(NAME)-static .
	mkdir -p bin
	podman create --name $(NAME)-extract $(NAME)-static
	podman cp $(NAME)-extract:/$(NAME) bin/$(NAME)-static-aarch64
	podman rm $(NAME)-extract

.PHONY: clean
clean:
	rm -rf ./bin

.PHONY: test
test:
	go test -v -exec sudo -race ./pkg/...

.PHONY: fmt
fmt:
	go fmt ./...
	find . -iname *.h -o -iname *.c | xargs clang-format -i -style=Google 
