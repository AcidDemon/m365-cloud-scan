# Testing the box installer

The installer has two independent halves; test them with different tools.

| Half | What it covers | Tool | Why |
|------|----------------|------|-----|
| **ISO install** | preseed, hardware detect, disk wipe/partition, grub, **first boot** | `run-qemu.sh` (QEMU/OVMF) | boots the ISO through `debian-installer` on bare metal |
| **Ansible convergence** | `site.yml` runs clean, units up, UI answers | `../../dev-vm` (vagrant-libvirt) | fast; no ISO rebuild per iteration |

**Vagrant cannot replace the QEMU test.** The dev-vm boots a *prebuilt* Debian box
and skips `debian-installer` entirely — so it never exercises the preseed, the
wrong-disk-wipe guard, partitioning, or the boot path. Use it only for the app
inner loop; use QEMU for the real end-to-end acceptance.

## Full end-to-end (QEMU) — the acceptance test

```bash
deploy/build.sh amd64                                             # binary into the role's files/
scripts/build-box-iso.sh --dvd debian-13.x.0-amd64-DVD-1.iso \
  --authorized-keys ~/.ssh/box_admin.pub                          # -> dist/m365-scan-installer.iso
deploy/installer/test/run-qemu.sh dist/m365-scan-installer.iso
```

To also join a tailnet on first boot, add `--tailscale-authkey KEY` (use an
ephemeral, tagged, short-lived key; the ISO then carries a secret — keep it
private). The key is decrypted on your workstation, injected as plaintext, and
shredded on the box after `tailscale up`. From a vault:

```bash
scripts/build-box-iso.sh --dvd debian-13.x.0-amd64-DVD-1.iso \
  --authorized-keys ~/.ssh/box_admin.pub \
  --tailscale-authkey "$(ansible-vault view deploy/ansible/inventory/group_vars/all/vault.yml \
                          | sed -n 's/^tailscale_authkey: *//p')"
```

Run it from a shell with write access to `/dev/kvm`. Without acceleration the same
run takes hours, so the script stops rather than falling back silently (`ALLOW_TCG=1`
overrides).

It wipes the virtual disk, installs (pulling `ansible-core` and the samba/avahi
stack from `deb.debian.org`), reboots, and runs firstboot. Then from the host:

```bash
curl -k https://localhost:8444/        # expect the "M365 CLOUD SCAN" sign-in page
```

The box comes up unonboarded, which is the shipping state: the UI answers and the
poller idles until a tenant is connected under Settings.

## Also verified without a VM

- `bash deploy/installer/selftest.sh` — `render-vars.py` (extra-vars + firewall CIDRs).
- `go test ./...` — the daemon itself.
