#!/usr/bin/env bash
# End-to-end test of the WHOLE box install under QEMU/OVMF (UEFI): it exercises
# debian-installer + preseed + first boot from bare metal — the only way to test
# the unattended installer, because it boots the built ISO on a blank target disk.
# Nothing else is needed: the image carries no tenant and no secrets.
#
# Runs entirely on the SERIAL console: the installer kernel is booted directly with
# console=ttyS0 so d-i, and then firstboot, are plain text on stdout. No graphical
# console, no VNC client, and the whole run is one greppable log. Two phases,
# because -kernel would otherwise re-run the installer on every guest reboot:
#   1. install  (-kernel/-initrd from the ISO, -no-reboot, exits when d-i reboots)
#   2. boot the installed disk, where firstboot runs the ansible converge
# The ISO itself is untouched; only how QEMU boots it differs. On real hardware the
# console stays tty0 (the attached monitor), which is what the READY banner needs.
#
# On NixOS the tools come from libisoburn; this script re-execs under nix-shell if
# they're missing. OVMF paths are auto-detected; override with OVMF_CODE/OVMF_VARS.
#
# Usage: run-qemu.sh path/to/m365-scan-installer.iso
#   The box comes up unonboarded: the admin UI answers on :8444 and the poller
#   idles until a tenant is connected there. Both are expected.
set -euo pipefail

ISO=${1:?usage: run-qemu.sh installer.iso}

if ! command -v xorriso >/dev/null 2>&1 && command -v nix-shell >/dev/null 2>&1; then
	# invoke via bash: NixOS has no /usr/bin/env for the script's shebang
	exec nix-shell -p qemu libisoburn --run "bash $(printf '%q ' "$0" "$@")"
fi
for t in qemu-system-x86_64 xorriso; do
	command -v "$t" >/dev/null || { echo "missing: $t (try: nix-shell -p qemu libisoburn)" >&2; exit 1; }
done

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

# --- blank target disk ---
TARGET=$WORK/target.qcow2
qemu-img create -f qcow2 "$TARGET" 20G >/dev/null

# --- OVMF firmware (auto-detect; override via env) ---
# `return 0` at the end matters: without it a no-match makes the $(...) assignment
# below fail, and `set -e` then kills the script with no message at all.
find_fw() { for p in "$@"; do [ -f "$p" ] && { echo "$p"; return 0; }; done; return 0; }
OVMF_CODE=${OVMF_CODE:-$(find_fw /run/libvirt/nix-ovmf/OVMF_CODE.fd /usr/share/OVMF/OVMF_CODE.fd /usr/share/edk2/x64/OVMF_CODE.4m.fd)}
OVMF_VARS_SRC=${OVMF_VARS:-$(find_fw /run/libvirt/nix-ovmf/OVMF_VARS.fd /usr/share/OVMF/OVMF_VARS.fd /usr/share/edk2/x64/OVMF_VARS.4m.fd)}
# Nothing on the usual paths (a NixOS host without libvirt running) — pull it from
# nixpkgs. Cached after the first fetch.
if { [ -z "$OVMF_CODE" ] || [ -z "$OVMF_VARS_SRC" ]; } && command -v nix-build >/dev/null 2>&1; then
	echo ">> OVMF not on the usual paths — fetching it from nixpkgs"
	FV=$(nix-build '<nixpkgs>' -A OVMF.fd --no-out-link 2>/dev/null)/FV
	OVMF_CODE=${OVMF_CODE:-$(find_fw "$FV/OVMF_CODE.fd")}
	OVMF_VARS_SRC=${OVMF_VARS_SRC:-$(find_fw "$FV/OVMF_VARS.fd")}
fi
[ -n "$OVMF_CODE" ] && [ -n "$OVMF_VARS_SRC" ] || { echo "OVMF not found — set OVMF_CODE=/path OVMF_VARS=/path" >&2; exit 1; }
echo ">> firmware: $OVMF_CODE"
cp "$OVMF_VARS_SRC" "$WORK/OVMF_VARS.fd"
chmod u+w "$WORK/OVMF_VARS.fd"

# KVM, or a deliberate opt-in to TCG. Silent TCG fallback turns a 40-minute run
# into a multi-hour one, so make it a stop rather than a warning.
if [ -w /dev/kvm ]; then
	ACCEL=(-machine q35,accel=kvm -cpu host)
elif [ -n "${ALLOW_TCG:-}" ]; then
	echo ">> no /dev/kvm — TCG software emulation, expect hours"; ACCEL=(-machine q35 -cpu max)
else
	echo "error: /dev/kvm not writable. Run from a shell with KVM access, or set ALLOW_TCG=1 to accept a multi-hour run." >&2
	exit 1
fi

# --- installer kernel + initrd, straight out of the ISO ---
# Booting these directly is the only way to put console= on d-i's cmdline; the
# preseed rides inside initrd.gz exactly as it does on a real boot.
xorriso -osirrox on -indev "$ISO" \
	-extract /install.amd/vmlinuz "$WORK/vmlinuz" \
	-extract /install.amd/initrd.gz "$WORK/initrd.gz" 2>/dev/null
chmod u+w "$WORK/vmlinuz" "$WORK/initrd.gz"

COMMON=(
	"${ACCEL[@]}" -m 4096 -smp 2
	-drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE"
	-drive if=pflash,format=raw,file="$WORK/OVMF_VARS.fd"
	-drive file="$TARGET",if=virtio,format=qcow2
	-netdev user,id=n0,hostfwd=tcp::8444-:8444,hostfwd=tcp::2222-:22 -device virtio-net,netdev=n0
	-display none -serial mon:stdio
)

echo ">> phase 1/2: unattended install (serial console below is the whole show)"
qemu-system-x86_64 "${COMMON[@]}" \
	-kernel "$WORK/vmlinuz" -initrd "$WORK/initrd.gz" \
	-append "auto=true priority=critical console=ttyS0,115200n8" \
	-cdrom "$ISO" \
	-no-reboot

echo
echo ">> phase 2/2: booting the installed system — firstboot runs the ansible converge."
echo "   Expect 20-45 min (AIDE dominates), then: M365 SCAN BOX READY  admin UI: https://<ip>:8444"
echo "   From the host meanwhile:"
echo "     curl -ks https://localhost:8444/ | grep 'M365 CLOUD SCAN'       # the pass criterion"
echo "     ssh -p 2222 -i ~/.ssh/box_admin acid@127.0.0.1 tail -f /var/log/m365-scan-firstboot.log"
echo "     ssh -p 2222 -i ~/.ssh/box_admin acid@127.0.0.1 \\"
echo "       'cat /var/log/m365-scan-firstboot.status; systemctl is-enabled m365-scan-firstboot; ls /opt/m365-scan-firstboot/'"
exec qemu-system-x86_64 "${COMMON[@]}"
