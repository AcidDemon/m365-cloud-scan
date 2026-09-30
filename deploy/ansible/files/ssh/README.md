# Operator SSH keys

Drop the public keys that should reach this box here, one `.pub` per operator.
The baseline installs every one of them for both the admin and the deploy user,
and adds rather than replaces, so a key the Debian installer already put in
`authorized_keys` survives.

An empty directory is not an error and the task simply skips, which matters
because the hardening layer turns off password authentication. If nothing here
matches a key you hold and the installer did not leave one on the box, the run
that hardens SSH is also the run that locks you out. The rollback timer in
`harden_safe_rollback` is what buys the box back, twenty minutes later.

The keys themselves are gitignored. This file is what keeps the directory.
