#!/usr/bin/env bash
# A Go change into the running VM: rebuild, push, restart. No full provision,
# so the seeded state, the password and the shares survive.
set -euo pipefail
cd "$(dirname "$0")" > /dev/null

./build.sh
vagrant rsync
vagrant ssh -c 'sudo install -m 0755 /repo/deploy/dev-vm/.build/m365-scan /usr/local/bin/m365-scan &&
                sudo systemctl restart m365-scan && sleep 2 && systemctl is-active m365-scan'
