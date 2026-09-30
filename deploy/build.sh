#!/usr/bin/env bash
# Build the binary the Ansible role ships. The box has no Go toolchain and
# go.mod asks for a newer Go than Debian packages, so this runs on a workstation
# and the artifact travels as a file.
#
# OBFUSCATE=1 builds with garble (obfuscated symbols/literals) and packs with
# upx. Off by default: obfuscation kills panic stack traces, and this binary
# runs on a box where crash triage matters. Turn it on for release artifacts.
set -euo pipefail
cd "$(dirname "$0")/.." > /dev/null   # repo root; CDPATH would echo the target

arch=${1:-amd64}
version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
out=deploy/ansible/roles/m365_scan/files/m365-scan-$arch

if [ "${OBFUSCATE:-0}" = "1" ]; then
	CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
		garble -literals -tiny -seed=random build \
		-trimpath -ldflags "-X main.version=$version" -o "$out" ./cmd/m365-scan
	upx --best --lzma "$out" > /dev/null
	echo "$out  ($version, obfuscated+packed)"
else
	CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
		go build -trimpath -ldflags "-s -w -X main.version=$version" -o "$out" ./cmd/m365-scan
	echo "$out  ($version)"
fi
