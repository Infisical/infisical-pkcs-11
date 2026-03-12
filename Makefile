MODULE_NAME = libinfisical-pkcs11
VERSION ?= dev

# Detect OS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    EXT = .dylib
else ifeq ($(UNAME_S),Linux)
    EXT = .so
else
    EXT = .dll
endif

OUTPUT = $(MODULE_NAME)$(EXT)
LDFLAGS = -s -w -X main.version=$(VERSION)

.PHONY: build clean test lint

build:
	CGO_ENABLED=1 go build -buildmode=c-shared -ldflags="$(LDFLAGS)" -o $(OUTPUT)

test:
	go test -v -race ./...

clean:
	rm -f $(MODULE_NAME).so $(MODULE_NAME).dylib $(MODULE_NAME).dll $(MODULE_NAME).h

lint:
	go vet ./...

# Cross-compilation targets (require appropriate C cross-compilers)
build-linux-amd64:
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC=x86_64-linux-musl-gcc \
		go build -buildmode=c-shared -ldflags="$(LDFLAGS)" -o $(MODULE_NAME)-linux-amd64.so

build-linux-arm64:
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC=aarch64-linux-musl-gcc \
		go build -buildmode=c-shared -ldflags="$(LDFLAGS)" -o $(MODULE_NAME)-linux-arm64.so

build-darwin-amd64:
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 \
		go build -buildmode=c-shared -ldflags="$(LDFLAGS)" -o $(MODULE_NAME)-darwin-amd64.dylib

build-darwin-arm64:
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 \
		go build -buildmode=c-shared -ldflags="$(LDFLAGS)" -o $(MODULE_NAME)-darwin-arm64.dylib

build-windows-amd64:
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc \
		go build -buildmode=c-shared -ldflags="$(LDFLAGS)" -o $(MODULE_NAME)-windows-amd64.dll
