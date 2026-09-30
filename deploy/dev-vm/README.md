# Dev VM

A throwaway Debian 13 box for the parts of the daemon that need a real machine. Creating a share runs
`useradd`, `smbpasswd` and `net conf`. On a NixOS workstation that fails with `useradd: Permission
denied`, and it should: those are system accounts, and `useradd` is not how NixOS makes them.

The VM matches the production box: Debian 13, Samba from apt with `config backend = registry`, the
daemon at the production paths as a root systemd unit.

## What is in here

```
Vagrantfile        the box, the network and the provisioning
build.sh           cross-builds m365-scan and devsetup for linux/amd64
reload.sh          rebuild, push, restart the unit after a Go change
smb.conf           the static Samba config the shipped box will have
m365-scan.service  the unit, running as root
```

The VM has no Go toolchain. Both binaries are built on the host by a Vagrant trigger before `up` and
travel in through the rsync'd `/repo`.

## Bring it up

Needs `vagrant`, `vagrant-libvirt`, `qemu` and `rsync` on the host. The first `up` downloads the
`debian/trixie64` box.

```
cd deploy/dev-vm
vagrant up
```

Provisioning ends by printing the admin password, the UI address and the SMB address. To see them
again:

```
vagrant ssh -c 'sudo m365-scan reset-password <new password> && sudo systemctl restart m365-scan'
```

That writes the hash to `/var/lib/m365-scan/ui-password`, which the config loader prefers over the
hash in `config.json`. The restart is what makes the running process pick it up: it reads the hash
once at start.

## Addresses

| What | Where | Why |
|---|---|---|
| Admin UI | https://127.0.0.1:8444 | forwarded port, vagrant-libvirt tunnels it over SSH |
| | | `scripts/dev.sh` deliberately uses 8445, so 8444 is always this VM |
| Admin UI | https://192.168.121.10:8444 | vagrant's management network, same thing without the tunnel |
| SMB | `//192.168.121.10/<share>` | 445 cannot be forwarded to an unprivileged host port |

The certificate is self-signed by the daemon on first start, so the browser warns.

## Make a share and scan into it

The share is created in the UI, which is the path that fails on the workstation. Shares, then Add,
then a name like `test-mfp`. The UI mints the SMB user and shows the generated password once.

```
smbclient //192.168.121.10/test-mfp -U scan-test-mfp
smb: \> put some.pdf
```

NixOS hosts usually have `mount.cifs` but not `smbclient`. Either works:

```
# no install, mounts over the private network
sudo mkdir -p /mnt/scan
sudo mount -t cifs //192.168.121.10/test-mfp /mnt/scan \
  -o username=scan-test-mfp,vers=3.0,uid=$(id -u),gid=$(id -g)
cp some.pdf /mnt/scan/

# or borrow smbclient for one command
nix-shell -p samba --run 'smbclient //192.168.121.10/test-mfp -U scan-test-mfp'
```

The file only moves if the share has a route. A share with no enabled route is
left alone on purpose, and the watcher says so:
`scan not queued: no enabled route accepts it`. The default rules also accept
only pdf, tif, tiff and jpg, and wait 5 seconds for the file to stop changing.

Watch the file arrive:

```
vagrant ssh -c 'sudo journalctl -fu m365-scan'
```

The watcher waits for the file to stop changing (5 seconds by default), then queues it. There is no
tenant in the VM, so every upload leg stays pending and the engine logs that the box is not connected.
The local file is never deleted, because deletion waits for every route to confirm.

## After a Go change

```
./reload.sh
```

Rebuild on the host, `vagrant rsync`, install the binary, restart the unit. The state, the shares and
the password survive. Use `vagrant provision` only when the unit, `smb.conf` or the config changed.

## Demo data

Provisioning seeds three shares, four destinations, five routes and four queued scans, the same set
`scripts/dev.sh` uses. It runs `devsetup -config /etc/m365-scan/config.json`, which seeds the state
file and share root that config names, and skips the whole thing if `state.json` already exists.

The seeded shares are directories and state entries only. They have no SMB user and no registry entry,
because the seed does not go through the Samba manager. Make a share in the UI for anything involving
a real SMB session.

## Throw it away

```
vagrant destroy -f
```

## What was verified here, and what was not

The VM has never booted on this machine. There is no `/dev/kvm` in the environment this was written
in, so `vagrant up` could not run.

Verified:

- `vagrant validate` passes.
- The inline provisioning script parses under `bash -n`, extracted from the Vagrantfile exactly as
  Ruby hands it to the shell.
- `build.sh` produces static linux/amd64 binaries with `CGO_ENABLED=0`.
- The cross-built `m365-scan` serves the UI with the same `config.json` the Vagrantfile writes, on the
  same production-shaped paths. `GET /` returns 200 and `POST /api/login` with the password set by
  `reset-password` returns 200.
- `devsetup -config` seeds into the paths the config names, and a second run keeps the existing state.

Not verified, because it needs the VM:

- `vagrant up` end to end, the box download, the rsync folder, the port forward and the private
  network.
- Everything Samba: the `smb.conf` above under `testparm`, the `net conf setparm` calls in
  provisioning, and whether smbd starts clean with an empty registry. Samba is not installed on the
  host either.
- Creating a share through the UI, so `useradd` and `smbpasswd` under systemd as root.
- `smbclient` against the box.
- `reload.sh`, which needs a running VM for `vagrant rsync` and `vagrant ssh`.

One thing to watch on the first boot: with `config backend = registry`, smbd takes its configuration
from the registry and not from `smb.conf`. Provisioning writes the same globals into the registry with
`net conf setparm`. If smbd complains anyway, `sudo net conf list` shows what it actually has.
