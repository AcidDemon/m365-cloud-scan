# Deploying a box

One Debian 13 box, one playbook, three layers. `acidnetworks.base_debian` owns
the users, the firewall, the hostname and unattended upgrades.
`acidnetworks.hardening_debian` then hardens SSH and adds auditd, AIDE, CrowdSec,
fail2ban and the rootkit scanners. The `m365_scan` role owns Samba, the daemon
and its config.

Read the SSH section below before the first run. The hardening layer turns off
password authentication, so the run that hardens the box is also the run that can
lock you out of it.

## First run

```
ansible-galaxy collection install -r requirements.yml
../build.sh                                    # binary into roles/m365_scan/files/
cp inventory/host_vars/m365-scan-box.yml.example inventory/host_vars/m365-scan-box.yml
$EDITOR inventory/host_vars/m365-scan-box.yml  # address, LAN, server name
ansible-playbook site.yml
ansible-playbook verify.yml
```

`site.yml` prints the admin URL and the generated password. It prints them once,
on the run that created them, so keep the output. If you lose it before signing
in, `m365-scan reset-password <new password>` on the box sets a new one.

The first run records the box's SSH host key. If you later re-image the same
address, clear the old key with `ssh-keygen -R <address>` or the run stops with
`Host key verification failed`, which is the check doing its job.

`inventory/host_vars/*.yml` is gitignored. That file and the binary under
`roles/m365_scan/files/` are the only per-box things; everything else in here is the
same on every box.

## Redeploying

```
ansible-playbook site.yml --tags scan
ansible-playbook verify.yml
```

That skips the baseline and touches only the app. Use it after a new binary or a
config change. Run `verify.yml` afterwards: the play reports success as soon as
systemd accepts the unit, which it does even when the daemon is crash-looping on
a bad config.

Re-running is safe by design, and the guards are the reason to use Ansible here
rather than a shell script:

- The session secret is read back out of the existing `config.json`. Minting a
  new one would sign out every browser.
- The admin password is only generated when `/var/lib/m365-scan/ui-password` is
  absent. A password the admin changed in the UI is never overwritten.
- Samba registry globals are only seeded where the registry has no value. The
  Settings page owns the server name, the workgroup and the protocol floor once
  the box is live.

## What the playbook does not do

It leaves a box that serves its admin UI and nothing else. Three things still
need a person:

1. **Connect the tenant.** Sign in to the UI and run the wizard under Settings.
   It needs a Microsoft 365 admin who can consent to an app registration, and it
   uses the device-code flow, so a Conditional Access policy that blocks device
   code will block onboarding.
2. **Create the shares.** Each share is made in the UI, which creates the system
   account and the Samba registry entry. The share password is shown once. Type
   it into the copier's scan-to-folder settings.
3. **Pick the destinations and routes.** Also UI only.

For a second box in the same tenant, copy `tenant.json` and `scan.pem` off the
first one instead of running the wizard again. The wizard replaces the app's key
credential every time it runs, which would cut the first box off.

## SSH, and not locking yourself out

`ssh_hardening` disables password authentication and admits only members of
`sshusers`, which the baseline creates and adds the admin and deploy users to. It
does not give them keys. Put yours in `files/ssh/` before the first run, or make
sure the Debian installer already left one in `authorized_keys` for the account
you connect as. Set `ansible_user` in the host_vars file too: `ssh_hardening`
checks that this account survives the cutover and skips the check when the
variable is missing.

If it goes wrong anyway, `harden_safe_rollback` arms a systemd timer before the
cutover that strips the sshd drop-ins again after `harden_rollback_minutes`,
twenty by default. It disarms as soon as the run finishes, so it only fires when
the run does not. This is the reason the box does not need a hypervisor console.

## What the hardening layer is set to do differently here

Most of it runs stock. Four things do not, and all four are in
`inventory/group_vars/all/main.yml` with the reasoning next to them:

- Its `os_base` role is off. It would set the hostname from `inventory_hostname`
  and rewrite `/etc/hosts`, while the baseline sets it from the NetBIOS name and
  the daemon re-asserts that on every start. The hostname is this box's SMB and
  mDNS identity, so it gets one owner.
- Its `auto_updates` role is off, because the baseline already writes the same
  two apt files and hardening's copy drops the package hold-list.
- msmtp and the reporting timer are off. There is no vault on this box and the
  mail templates reference vault variables that do not exist, which aborts the
  run before the daemon is installed.
- The CrowdSec and fail2ban whitelists are widened to the copier subnet. Both
  ban whole IPs from their own nftables tables, and those tables hook the input
  chain ahead of the baseline firewall, so a ban outranks the rule that lets a
  copier reach port 445.

TOTP and FIDO2 are off: an unattended appliance has nobody to answer a prompt.

AIDE watches `/etc/passwd`, `/etc/shadow` and `/etc/samba`, all of which this
daemon rewrites whenever someone adds a share in the web UI. That churn is
expected and is not excluded, because excluding it would remove most of the
reason to run AIDE. The share roots and the daemon's own state are excluded, and
the role refreshes the database itself after it installs a new binary.

## Backups

Losing `/var/lib/m365-scan` means losing the queue and the tenant link. Losing
the Samba passdb or `/etc/shadow` is worse: the share accounts are gone, the
shares still appear in the UI, and every copier has to be re-credentialed. Back
up together:

```
/etc/m365-scan/            config.json, scan.pem, the UI cert
/var/lib/m365-scan/        state.json, settings.json, tenant.json, ui-password
/var/lib/samba/            registry.tdb and the passdb
/etc/passwd /etc/shadow    the share accounts
```
