# Build the box. `make` = debug build; `make release` = obfuscated; `make slim` = obfuscated + packed.
# Cross-compile: make release GOOS=linux GOARCH=amd64
BIN     := m365-scan
PKG     := ./cmd/m365-scan
DIST    := dist
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build release slim clean help

## build: plain build with symbols stripped, for local use
build:
	go build -trimpath -ldflags "-s -w $(LDFLAGS)" -o $(DIST)/$(BIN) $(PKG)

## release: obfuscated build (garble) — renames symbols, encrypts literals, strips line info
release:
	garble -literals -tiny -seed=random build \
		-trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN) $(PKG)

## slim: release build, then pack with upx (smallest binary)
slim: release
	upx --best --lzma $(DIST)/$(BIN)

## clean: remove build output
clean:
	rm -rf $(DIST)

## help: list targets
help:
	@sed -n 's/^## //p' $(MAKEFILE_LIST)
