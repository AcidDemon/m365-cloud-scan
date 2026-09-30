#!/usr/bin/env bash
# Cross-build what the VM runs. The VM has no Go toolchain, so both binaries are
# built here and travel in through the rsync'd /repo.
set -euo pipefail
cd "$(dirname "$0")/../.." > /dev/null   # repo root; CDPATH would echo the target

out=deploy/dev-vm/.build
mkdir -p "$out"
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64
go build -trimpath -o "$out/m365-scan" ./cmd/m365-scan
go build -trimpath -o "$out/devsetup" ./scripts/devsetup
