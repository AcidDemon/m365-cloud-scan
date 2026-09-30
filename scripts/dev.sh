#!/usr/bin/env bash
# Run the box on a workstation: build, prepare ./.dev, print the password, serve.
# Pass --fresh to throw the demo data away and start from an empty box.
#
# This serves on 8445. The Vagrant VM in deploy/dev-vm forwards host 8444, so the
# port tells you which box you are looking at. This one cannot create a share:
# that needs useradd and Samba, which is what the VM is for.
set -euo pipefail
cd "$(dirname "$0")/.." > /dev/null   # CDPATH would otherwise echo the target

if [ "${1:-}" = "--fresh" ]; then
	rm -rf .dev
fi

go build -o .dev/m365-scan ./cmd/m365-scan
go run ./scripts/devsetup

cfg="$PWD/.dev/etc/config.json"
addr=$(sed -n 's/.*"bindAddr": *"\([^"]*\)".*/\1/p' "$cfg")
port=${addr##*:}

# Refuse to start on a taken port rather than losing the bind quietly. Something
# else answering this URL with its own password is indistinguishable from a
# wrong password, which has cost us an afternoon once already.
if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
	exec 3>&-
	echo "port $port is already in use, so this box would not be the one you reach." >&2
	echo "find it with: ss -ltnp | grep :$port" >&2
	exit 1
fi

exec .dev/m365-scan -config "$cfg" serve
