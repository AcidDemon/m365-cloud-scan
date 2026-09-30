#!/usr/bin/env bash
# Build the GENERIC, reusable on-prem box installer ISO (owner, one-time).
#
# Output: a Debian 13 installer ISO that installs unattended on arbitrary
# hardware and, on first boot, runs deploy/ansible/site.yml locally to turn the
# machine into an M365 Cloud Scan box. It carries NO customer secrets: the image
# is generic — no tenant, no keys but the ones you pass — and is onboarded from
# its own web UI after install. One ISO works for every customer.
#
# The owner: (1) runs this once, (2) flashes N USB sticks with Ventoy and its
# data partition forced to FAT32, (3) copies this ISO onto each stick. See README.
#
# Needs on the build host: xorriso, cpio, gzip, git, openssl, ansible-galaxy,
# and the GitHub SSH deploy key loaded in ssh-agent (only used here, to vendor
# the acidnetworks.* collections — the box never sees it).
set -euo pipefail

cd "$(dirname "$0")/.."   # repo root

DVD=""
OUT="dist/m365-scan-installer.iso"
KEYS=""
PW=""
ADMIN="dkadmin"   # local admin account d-i creates and ansible then manages
WORK=""
COLLDIR=""   # pre-vendored collections dir; skips the git+ssh fetch (testing)
TSKEY="${TS_AUTHKEY:-}"   # optional tailscale auth key; baked in -> box joins the tailnet on first boot
TSTAGS="${TS_TAGS:-}"     # tags to advertise; REQUIRED with an OAuth client secret

usage() { sed -n '2,21p' "$0"; echo; echo "Usage: $0 --dvd debian-13-DVD-1.iso --authorized-keys FILE [--out OUT.iso] [--password PW] [--admin-user NAME] [--collections-dir DIR] [--tailscale-authkey KEY] [--tailscale-tags TAGS]"; echo; echo "  --tailscale-authkey KEY  bake a Tailscale auth key; the box joins the tailnet on first boot and the key is shredded. Also read from \$TS_AUTHKEY. Omit for a generic, secret-free ISO. From a vault: --tailscale-authkey \"\$(ansible-vault view deploy/ansible/inventory/group_vars/all/vault.yml | sed -n 's/^tailscale_authkey: *//p')\""; exit "${1:-0}"; }

ARGS=("$@")   # kept for the nix-shell re-exec (the loop below shifts $@ away)
while [ $# -gt 0 ]; do
	case "$1" in
		-d|--dvd)             DVD=$2; shift 2;;
		-o|--out)             OUT=$2; shift 2;;
		-k|--authorized-keys) KEYS=$2; shift 2;;
		-w|--work)            WORK=$2; shift 2;;
		--collections-dir)    COLLDIR=$2; shift 2;;
		--password)           PW=$2; shift 2;;
		--admin-user)         ADMIN=$2; shift 2;;
		--tailscale-authkey)  TSKEY=$2; shift 2;;
		--tailscale-tags)     TSTAGS=$2; shift 2;;
		-h|--help)            usage 0;;
		*) echo "unknown arg: $1" >&2; usage 1;;
	esac
done

[ -n "$DVD" ] && [ -f "$DVD" ] || { echo "error: --dvd <Debian 13 DVD-1 iso> is required" >&2; exit 1; }
# hardening_debian disables password SSH and restricts logins to the sshusers
# group, and nothing else installs a key — no key here means a console-only box.
[ -n "$KEYS" ] && [ -f "$KEYS" ] || { echo "error: --authorized-keys FILE is required (hardening disables password SSH; without a key the box is console-only)" >&2; exit 1; }

# The admin name lands in the preseed, in home paths, and in an ansible extra-var,
# so reject anything useradd would refuse or that collides with an account the
# playbooks already own (ansible = deploy_user; the daemon runs as root).
printf '%s' "$ADMIN" | grep -qE '^[a-z_][a-z0-9_-]{0,31}$' || { echo "error: --admin-user '$ADMIN' is not a valid Linux username" >&2; exit 1; }
case $ADMIN in root|ansible) echo "error: --admin-user '$ADMIN' collides with an account the playbooks create" >&2; exit 1;; esac

# xorriso ships in libisoburn. On NixOS it isn't on PATH by default — re-exec
# under nix-shell so the owner doesn't have to remember the wrapper.
if ! command -v xorriso >/dev/null 2>&1 && command -v nix-shell >/dev/null 2>&1; then
	echo ">> xorriso not on PATH — re-exec under nix-shell -p libisoburn"
	# invoke via bash: NixOS has no /usr/bin/env for the script's shebang
	exec nix-shell -p libisoburn --run "bash $(printf '%q ' "$0" "${ARGS[@]}")"
fi
# ansible-galaxy is only needed when we have to fetch the collections ourselves.
TOOLS=(xorriso cpio gzip git openssl)
[ -n "$COLLDIR" ] || TOOLS+=(ansible-galaxy)
for t in "${TOOLS[@]}"; do
	command -v "$t" >/dev/null || { echo "error: missing tool: $t (xorriso: run inside 'nix-shell -p libisoburn')" >&2; exit 1; }
done

WORK=${WORK:-$(mktemp -d)}
ISO=$WORK/iso
PAY=$WORK/payload/m365-scan
mkdir -p "$ISO" "$PAY" "$(dirname "$OUT")"
echo ">> work dir: $WORK"

# --- 1. payload: clean ansible tree + binary + vendored collections + installer files
echo ">> staging payload"
# Worktree content minus gitignored files. gitignore is the secret list here
# (vault.yml, .vault-pass, the binaries), same guarantee `git archive HEAD` gave,
# except this ships what was actually tested instead of what was last committed.
git ls-files -z -c -o --exclude-standard deploy/ansible | tar --null -T - -c | tar -x -C "$PAY"
# The daemon binary is gitignored, so it does not ride in via the ls-files tar
# above — build it if absent, then copy it in explicitly.
[ -f deploy/ansible/roles/m365_scan/files/m365-scan-amd64 ] || deploy/build.sh amd64
cp deploy/ansible/roles/m365_scan/files/m365-scan-amd64 "$PAY/deploy/ansible/roles/m365_scan/files/"
# The role reaches outside deploy/ansible for a couple of files with
# {{ playbook_dir }}/../, and the tar above carries deploy/ansible alone, so they
# have to be placed at the layout the role expects. Derived from the role rather
# than listed here: a third file added to that pattern later fails this build
# instead of failing the converge on a box someone has already driven to.
for f in $(grep -rhoE '\{\{ playbook_dir \}\}/\.\./[A-Za-z0-9._-]+' deploy/ansible | sed 's#.*/##' | sort -u); do
	[ -f "deploy/$f" ] || { echo "error: the playbook references deploy/$f, which is not in the repo" >&2; exit 1; }
	install -m 0644 "deploy/$f" "$PAY/deploy/$f"
	echo "   payload <- deploy/$f"
done

# This ISO gets handed to colleagues — a gitignore slip must not ride along.
[ ! -e "$PAY/deploy/ansible/inventory/group_vars/all/vault.yml" ] && [ ! -e "$PAY/deploy/ansible/.vault-pass" ] \
	|| { echo "error: secret leaked into the ISO payload" >&2; exit 1; }
install -m 0755 deploy/installer/firstboot.sh "$PAY/firstboot.sh"
install -m 0755 deploy/installer/render-vars.py "$PAY/render-vars.py"
install -m 0644 deploy/installer/m365-scan-firstboot.service "$PAY/m365-scan-firstboot.service"
install -m 0644 "$KEYS" "$PAY/authorized_keys"
# firstboot reads this and passes it to ansible, so d-i's account and base_users'
# admin_user stay the same person (else the playbook creates a second admin).
printf '%s\n' "$ADMIN" > "$PAY/admin_user"

# Optional Tailscale auth key. Decrypted on THIS workstation (e.g. ansible-vault
# view) and injected as plaintext here — never the vault or its password, which
# firstboot has no way to unlock on a headless local run. Present -> firstboot
# installs tailscale, `tailscale up`s with it, then shreds it. This makes the ISO
# carry a secret: use an ephemeral, tagged, short-lived key so a lost stick expires.
# An auth key (tskey-auth-…) expires in 90 days at most, so a stack of sticks
# goes stale. An OAuth client secret (tskey-client-…) does not expire, but it
# carries no user identity, so Tailscale requires the tags to be named on the
# command line. Catch that here rather than on a box at a customer site.
case $TSKEY in
	tskey-client-*)
		[ -n "$TSTAGS" ] || { echo "error: an OAuth client secret needs --tailscale-tags (e.g. tag:m365-box), which must be a tag the client is allowed to use" >&2; exit 1; };;
esac
if [ -n "$TSKEY" ]; then
	( umask 077; printf '%s\n' "$TSKEY" > "$PAY/tailscale-authkey" )
	[ -n "$TSTAGS" ] && printf '%s\n' "$TSTAGS" > "$PAY/tailscale-tags"
	echo ">> tailscale auth key baked in — THIS ISO IS NO LONGER GENERIC (it carries a secret)"
fi

if [ -n "$COLLDIR" ]; then
	echo ">> using pre-vendored collections from $COLLDIR"
	[ -d "$COLLDIR/ansible_collections" ] || { echo "error: $COLLDIR has no ansible_collections/" >&2; exit 1; }
	mkdir -p "$PAY/collections"
	cp -a "$COLLDIR/ansible_collections" "$PAY/collections/"
else
	echo ">> vendoring collections (uses your GitHub SSH key)"
	# --force: without it galaxy skips anything already present in the ambient
	# collection paths (the `ansible` bundle ships community.general and
	# ansible.posix), silently leaving them out of the payload.
	ansible-galaxy collection install -r deploy/ansible/requirements.yml -p "$PAY/collections" --force
fi

# The box installs ansible-core, which bundles no collections at all, so anything
# the layers reference by FQCN has to be here or the converge dies mid-install.
for c in acidnetworks/base_debian acidnetworks/hardening_debian ansible/posix community/general; do
	[ -d "$PAY/collections/ansible_collections/$c" ] || {
		echo "error: collection $c missing from the payload." >&2
		echo "       re-vendor with: ansible-galaxy collection install -r deploy/ansible/requirements.yml -p DIR --force" >&2
		exit 1
	}
done

# --- 2. preseed: fill the admin password crypt (SSH is key-based; this is a fallback)
PW=${PW:-$(openssl rand -base64 12)}
CRYPT=$(openssl passwd -6 "$PW")
mkdir -p "$WORK/preseed"
sed -e "s#@@USER_PWD_CRYPT@@#${CRYPT//#/\\#}#" -e "s#@@ADMIN_USER@@#$ADMIN#g" \
	deploy/installer/preseed.cfg > "$WORK/preseed/preseed.cfg"
if grep -q '@@' "$WORK/preseed/preseed.cfg"; then
	echo "error: unsubstituted @@PLACEHOLDER@@ left in the preseed" >&2
	exit 1
fi

# --- 3. extract the base ISO
echo ">> extracting base ISO"
xorriso -osirrox on -indev "$DVD" -extract / "$ISO" 2>/dev/null
chmod -R u+w "$ISO"

# bake the payload into the ISO filesystem — reachable at /cdrom/payload/m365-scan
# during install (the preseed late_command copies it into the target).
mkdir -p "$ISO/payload"
cp -a "$PAY" "$ISO/payload/m365-scan"

# --- 4. embed preseed.cfg into every installer initrd (read before any prompt)
embed_preseed() {
	local gz=$1 dir; [ -f "$gz" ] || return 0
	dir=$(dirname "$gz")
	echo "   preseed -> $gz"
	( cd "$dir" && gunzip -f "$(basename "$gz")" )
	cp "$WORK/preseed/preseed.cfg" "$dir/preseed.cfg"
	( cd "$dir" && echo preseed.cfg | cpio -H newc -o -A -F "${gz%.gz}" 2>/dev/null && rm -f preseed.cfg && gzip -f "$(basename "${gz%.gz}")" )
}
embed_preseed "$ISO/install.amd/initrd.gz"
embed_preseed "$ISO/install.amd/gtk/initrd.gz"

# --- 5. auto-boot the automated install (append cmdline, shrink the menu wait)
echo ">> patching boot menus"
for cfg in "$ISO"/boot/grub/grub.cfg "$ISO"/isolinux/*.cfg; do
	[ -f "$cfg" ] || continue
	sed -i -E 's#(vmlinuz[^\n]*)#\1 auto=true priority=critical#' "$cfg" 2>/dev/null || true
done
# GRUB (UEFI): Debian's grub.cfg ships NO timeout, so the menu waits forever —
# insert one and default to entry 1 (the text "Install", lighter than graphical).
G="$ISO/boot/grub/grub.cfg"
if [ -f "$G" ]; then
	grep -qE '^set +timeout=' "$G" && sed -i -E 's/^set +timeout=.*/set timeout=3/' "$G" || sed -i '1i set timeout=3' "$G"
	grep -qE '^set +default=' "$G" && sed -i -E 's/^set +default=.*/set default=1/' "$G" || sed -i '1i set default=1' "$G"
fi
# ISOLINUX (BIOS): short timeout so it doesn't wait at the prompt.
I="$ISO/isolinux/isolinux.cfg"
[ -f "$I" ] && { grep -qE '^timeout' "$I" && sed -i -E 's/^timeout.*/timeout 30/' "$I" || printf 'timeout 30\n' >> "$I"; }

# --- 6. remaster a hybrid BIOS+UEFI ISO
# Boot args mirror what the source ISO used (from `xorriso -report_el_torito
# as_mkisofs`). Debian 13 takes the isohybrid MBR from the source ISO's first
# sectors via --interval:local_fs, not from an isohdpfx.bin file.
echo ">> remastering $OUT"
xorriso -as mkisofs \
	-r -V 'M365SCAN' -o "$OUT" \
	-J -joliet-long \
	-isohybrid-mbr --interval:local_fs:0s-15s:zero_mbrpt,zero_gpt,zero_apm:"$DVD" \
	-partition_cyl_align off \
	-partition_offset 0 \
	--mbr-force-bootable \
	-apm-block-size 2048 \
	-iso_mbr_part_type 0x00 \
	-c isolinux/boot.cat \
	-b isolinux/isolinux.bin \
	-no-emul-boot -boot-load-size 4 -boot-info-table \
	-eltorito-alt-boot \
	-e boot/grub/efi.img \
	-no-emul-boot \
	-isohybrid-gpt-basdat \
	-isohybrid-apm-hfsplus \
	"$ISO"

# The password is baked into the preseed as a crypt hash, so it is fixed for this
# ISO and shared by every box installed from it. Terminal scrollback is a bad place
# for the only copy — drop it next to the image too (dist/ is gitignored).
umask 077
printf '%s\n' "$PW" > "$OUT.password"

echo
echo "built: $OUT ($(du -h "$OUT" | cut -f1))"
[ -n "$TSKEY" ] && echo "tailscale: box will join the tailnet on first boot (key baked in, then shredded) — keep this ISO private" \
                || echo "tailscale: not baked in (generic ISO) — pass --tailscale-authkey to join a tailnet on first boot"
echo "box admin fallback password (console login + sudo as $ADMIN): $PW"
echo "  also saved to $OUT.password — same for EVERY box built from this ISO."
echo "  Not the admin UI password: the box mints that itself and prints it on first boot."
echo
echo "Next: install Ventoy on each USB (force the data partition to FAT32),"
echo "copy $OUT onto it, hand it out. The colleague just boots it, then signs in"
echo "to the box admin UI on :8444 and connects the Microsoft 365 tenant under Settings."
echo
echo "If UEFI/BIOS boot fails, the boot-image paths in step 6 may differ for your"
echo "Debian build — inspect them with:  xorriso -indev '$DVD' -report_el_torito as_mkisofs"
