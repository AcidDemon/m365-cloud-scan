#!/usr/bin/env bash
# First-boot provisioning for an M365 Cloud Scan box.
#
# Builds a local ansible inventory + extra-vars from what the box can see about
# itself, and runs the existing deploy/ansible/site.yml against localhost
# (connection: local) — no control node, no SSH, no vault, and nothing
# tenant-specific. The image is generic: an admin connects the Microsoft 365
# tenant afterwards from the box's own web UI. On success it disables itself.
#
# Everything it needs was baked into the installer ISO under this dir:
#   deploy/ansible/   the playbook + m365_scan role + prebuilt binary
#   collections/      pre-vendored base_debian + hardening_debian + galaxy deps
set -euo pipefail

B=/opt/m365-scan-firstboot
# The admin account d-i created, written here by build-box-iso.sh --admin-user.
ADMIN=$(cat "$B/admin_user" 2>/dev/null || echo dkadmin)
LOG=/var/log/m365-scan-firstboot.log
STATUS=/var/log/m365-scan-firstboot.status
# Where the initial admin password ends up. The MOTD points at this file rather
# than printing the password, because /etc/motd is world readable and every
# local account — including the scan-* service accounts Samba gets — would
# otherwise be able to read the credential for the admin UI.
PWFILE=/root/m365-scan-initial-password

# 022, deliberately, and not 077: apt verifies repository signatures as the _apt
# user, so a keyring this script or the converge downloads has to stay readable
# by it. Tightening this once already broke the Tailscale install with an
# unsigned-repository error that names a permission problem three layers down.
# Everything secret here sets its own mode instead, right where it is created.
umask 022
# The ansible run echoes the generated admin password once and this log captures
# it, so the log is private regardless of the umask above.
install -m 0600 /dev/null "$LOG"
install -m 0600 /dev/null "$STATUS"

exec > >(tee -a "$LOG") 2>&1
echo "=== m365-scan firstboot $(date -u +%FT%TZ) ==="

IP=""  # set early so the failure trap can print it

# Install Tailscale from its official Debian repo and bring the box onto the
# tailnet with the baked auth key. Best-effort: called from an `if`, so a failure
# here does not abort firstboot (the box is still a working scan box on the LAN).
# --ssh turns on Tailscale SSH so the box is reachable over the tailnet for
# management even though hardening locks down the host sshd. curl + ca-certificates
# are already present by here (base_packages + preseed), installed by the converge.
join_tailnet() {
	local key codename tags
	key=$(head -1 "$1")
	tags=$(head -1 "$B/tailscale-tags" 2>/dev/null || true)
	# An OAuth client secret is used in place of an auth key, but it belongs to no
	# user, so Tailscale will only take it with the tags named here. It also mints
	# an ephemeral node by default, which is wrong for an appliance that is
	# supposed to stay in the tailnet while it is switched off overnight.
	case $key in
		tskey-client-*) case $key in *\?*) :;; *) key="$key?ephemeral=false&preauthorized=true";; esac;;
	esac
	codename=$(. /etc/os-release && echo "$VERSION_CODENAME")
	curl -fsSL "https://pkgs.tailscale.com/stable/debian/${codename}.noarmor.gpg" \
		-o /usr/share/keyrings/tailscale-archive-keyring.gpg
	curl -fsSL "https://pkgs.tailscale.com/stable/debian/${codename}.tailscale-keyring.list" \
		-o /etc/apt/sources.list.d/tailscale.list
	apt-get update -q
	DEBIAN_FRONTEND=noninteractive apt-get install -y -q tailscale
	systemctl enable --now tailscaled
	tailscale up --authkey "$key" --ssh ${tags:+--advertise-tags="$tags"}
}

fail() {
	echo "FAILED: ${1:-provisioning failed}" >&2
	echo "FAILED: ${1:-provisioning failed}" > "$STATUS"
	printf '\nM365 SCAN BOX PROVISIONING FAILED\n  see %s\n  box IP: %s (SSH as %s)\n\n' "$LOG" "${IP:-unknown}" "$ADMIN" | tee /etc/motd
	wall "M365 scan box provisioning FAILED — see $LOG (IP ${IP:-unknown})" 2>/dev/null || true
	# Leave the unit enabled so a reboot retries.
	exit 1
}
trap 'fail "unexpected error on line $LINENO"' ERR

# --- wait for real connectivity (route + working DNS), not just link ---
# network-online.target is unreliable with ifupdown and DHCP can be slow, so poll
# until the mirror actually resolves (that's what the online apt run needs).
# Up to ~5 min.
echo "waiting for network + DNS…"
n=0
while [ "$n" -lt 150 ]; do
	if getent hosts deb.debian.org >/dev/null 2>&1; then break; fi
	n=$((n + 1)); sleep 2
done

# --- network facts (best-effort; a failed probe must NOT abort under set -e) ---
IFACE=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1);exit}}') || true
IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}') || true
CIDR=$(ip -o -4 addr show dev "${IFACE:-lo}" 2>/dev/null | awk '{print $4;exit}') || true
ARCH=$(dpkg --print-architecture)
echo "iface=$IFACE ip=$IP cidr=$CIDR arch=$ARCH"

# --- local inventory: localhost in all three groups the playbook targets ---
# Written INTO the repo's inventory dir so ansible loads its group_vars/all/*
# (target_users, admin_user, base_packages, firewall_*, …) — else those are undefined.
INV="$B/deploy/ansible/inventory/firstboot.yml"
cat > "$INV" <<'YAML'
all:
  vars:
    ansible_connection: local
    ansible_python_interpreter: /usr/bin/python3
  children:
    base_hosts:
      hosts: {m365-scan-box: null}
    hardened_hosts:
      hosts: {m365-scan-box: null}
    m365_scan_boxes:
      hosts: {m365-scan-box: null}
YAML

# --- extra-vars the box worked out about itself ---
# render-vars.py emits JSON (valid YAML) so this stays pure-stdlib. extra-vars
# outrank the shipped group_vars/host_vars.
python3 "$B/render-vars.py" "$ARCH" "$B/extra.json"

# --- seed the daemon's own network-access list with this box's LAN ---
# Written before the converge, because the converge starts the daemon and the
# daemon applies this list to the firewall on start. ansible now opens management
# to the tailnet only, and join_tailnet is called from an `if` that merely warns
# on failure — so without this seed a box whose tailnet join failed would come up
# reachable from nowhere but its own console. Two ordinary entries, visible and
# removable in the UI like any other, so a customer can rename or replace them.
NET=$(python3 -c 'import ipaddress,sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "${CIDR:-10.0.0.0/8}" 2>/dev/null || echo 10.0.0.0/8)
install -d -m 0750 /var/lib/m365-scan
# Never on a retry: firstboot reruns after a failure, and by then the entries may
# already have been edited from the UI.
[ -s /var/lib/m365-scan/firewall.json ] || { cat > /var/lib/m365-scan/firewall.json <<JSON
{"version":1,"entries":[
{"id":"seed1","tier":"admin","label":"This box's LAN","cidr":"$NET","addedAt":"$(date -u +%FT%TZ)"},
{"id":"seed2","tier":"copier","label":"This box's LAN","cidr":"$NET","addedAt":"$(date -u +%FT%TZ)"}]}
JSON
	chmod 0640 /var/lib/m365-scan/firewall.json; }

# --- run the existing deploy locally, offline collections ---
echo "running ansible-playbook (local)…"
cd "$B/deploy/ansible"
ANSIBLE_CONFIG="$B/deploy/ansible/ansible.cfg" \
ANSIBLE_COLLECTIONS_PATH="$B/collections" \
	ansible-playbook -i "$INV" site.yml -e admin_user="$ADMIN" -e @"$B/extra.json"

# --- success: disable self and announce ---
trap - ERR
systemctl disable m365-scan-firstboot.service || true
echo OK > "$STATUS"
rm -f "$B/extra.json"

# --- optional: join the tailnet (only if a key was baked into the ISO) ---
# Runs AFTER the converge so hardening's firewall (which already admits
# 100.64.0.0/10, see render-vars.py) is in place first. The key is shredded either
# way — a used auth key must not linger on disk.
TS_STATUS=""
if [ -s "$B/tailscale-authkey" ]; then
	echo "joining tailnet…"
	if join_tailnet "$B/tailscale-authkey"; then
		TS_STATUS="tailnet: joined as $(tailscale ip -4 2>/dev/null | head -1)"
	else
		TS_STATUS="tailnet: JOIN FAILED — see $LOG (box still usable on the LAN)"
		echo "WARN: tailscale join failed" >&2
	fi
	shred -u "$B/tailscale-authkey" 2>/dev/null || rm -f "$B/tailscale-authkey"
fi

# The initial admin password is minted by the m365_scan role and stored only as a
# bcrypt hash (reset-password) — the plaintext exists just once, in the role's
# "shown once" debug task, which we captured in $LOG above. Lift it from there so
# the console banner can show it; if the box was already provisioned (retry), the
# role skips minting and there is nothing to lift — point at the log instead.
# The name the box answers to on the network. It is the one the converge just
# rendered rather than a guess, because the admin can rename the box later and
# the MOTD used to print a literal <name> placeholder that was never filled.
NBNAME=$(sed -n 's/.*"netbiosName": *"\([^"]*\)".*/\1/p' /etc/m365-scan/config.json 2>/dev/null | head -1)
NBNAME=${NBNAME:-m365scan}
NBLOWER=$(printf '%s' "$NBNAME" | tr '[:upper:]' '[:lower:]')

PW=$(grep -oiE 'password[[:space:]]+[0-9a-f]{16}' "$LOG" | tail -1 | grep -oE '[0-9a-f]{16}$' || true)
if [ -n "$PW" ]; then
	# Root-only, and scrubbed from the log afterwards so the plaintext lives in
	# exactly one place the operator can delete once they have used it.
	install -m 0600 /dev/null "$PWFILE"
	printf '%s\n' "$PW" > "$PWFILE"
	sed -i -E 's/([Pp]assword[[:space:]]+)[0-9a-f]{16}/\1<redacted>/g' "$LOG"
fi

{
	printf '\nM365 SCAN BOX READY\n  admin UI: https://%s:8444\n' "${IP:-<box-ip>}"
	if [ -n "$PW" ]; then
		printf '  admin password: sudo cat %s\n' "$PWFILE"
	else
		printf '  admin password: see %s\n' "$LOG"
	fi
	printf '  SMB name:   \\\\%s  (also %s.local via mDNS)\n' "$NBNAME" "$NBLOWER"
	printf '  SMB shares: none yet — create the first one in the admin UI\n'
	[ -n "$TS_STATUS" ] && printf '  %s\n' "$TS_STATUS"
	printf '  Sign in to the admin UI and connect your Microsoft 365 tenant under Settings.\n'
	# English only: the MOTD is written before anyone has picked a UI language.
	printf '  Locked out after a network change? Run on the console:\n'
	printf '    sudo m365-scan -config /etc/m365-scan/config.json fw-reset\n'
	printf '  It restores the network rules this installer set up.\n\n'
} | tee /etc/motd
wall "M365 scan box ready — admin UI https://${IP:-<box-ip>}:8444" 2>/dev/null || true
echo "=== firstboot done $(date -u +%FT%TZ) ==="
