#!/usr/bin/env bash
# Puts the Vagrant box back to how it looks out of the crate, so a take starts
# from nothing: no shares, no destinations, no routes and no tenant. Re-onboarding
# the tenant is the first thing the video shows, which is why tenant.json goes too.
#
#   ./reset.sh --yes
#
# This destroys a working box. There is no undo and no backup.
set -euo pipefail
unset CDPATH  # with CDPATH set, cd echoes its target and $(cd .. && pwd) returns it twice

[ "${1:-}" = "--yes" ] || {
	cat >&2 <<'USAGE'
reset.sh wipes the box: shares, SMB accounts, scanned files, settings and the
tenant connection. Run it with --yes once you are sure.

  ./reset.sh --yes
USAGE
	exit 2
}

vm=$(cd -- "$(dirname -- "$0")/../deploy/dev-vm" && pwd)
command -v vagrant >/dev/null || { echo "vagrant is not on PATH" >&2; exit 1; }

# base64 rather than nested quoting: the remote script has quotes, globs and a
# loop in it, and `vagrant ssh -c` would have to survive two levels of shell.
payload=$(base64 -w0 <<'REMOTE'
set -eu
systemctl stop m365-scan || true

# The registry is the only record of what the box created, so nothing here is
# hardcoded to the shares the demo happens to use.
for s in $(net conf listshares 2>/dev/null | tr -d '\r' | grep -v '^global$' || true); do
	users=$(net conf getparm "$s" "valid users" 2>/dev/null | tr -d '\r' || true)
	net conf delshare "$s" || true
	for u in $users; do
		# These names go to userdel as root. The box mints them from a narrow
		# alphabet, and a `valid users` line can hold anything; a word starting
		# with a dash would reach userdel as an option rather than a name.
		case "$u" in
		"" | root | [!a-z]* | *[!a-z0-9-]*) continue ;;
		esac
		smbpasswd -x "$u" >/dev/null 2>&1 || true
		userdel "$u" || true
	done
done
systemctl restart smbd nmbd || true

rm -f /var/lib/m365-scan/state.json /var/lib/m365-scan/settings.json /var/lib/m365-scan/tenant.json
# Leftovers here would show up as stale queue and quarantine rows on a box that
# is meant to look new.
rm -rf /var/lib/m365-scan/quarantine/* /var/lib/m365-scan/progress/*
rm -rf /srv/m365-scan/*

systemctl start m365-scan
sleep 2
systemctl is-active m365-scan
echo "shares left: $(net conf listshares 2>/dev/null | tr -d '\r' | grep -v '^global$' | wc -l)"
REMOTE
)

(cd "$vm" && vagrant ssh -c "echo $payload | base64 -d | sudo bash")
echo "box reset. The admin password is unchanged; the tenant is gone and has to be connected again."
