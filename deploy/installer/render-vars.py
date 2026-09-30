#!/usr/bin/env python3
"""Emit ansible extra-vars for a local site.yml run on a freshly installed box.

Everything tenant-specific now arrives through the box's own web UI, so this
carries only what the box can learn about itself at install time. Emitted as
JSON (valid YAML) so it stays pure-stdlib, no PyYAML: see selftest.sh.

Usage: render-vars.py <arch> <out.json>
"""
import json
import sys


def build(arch: str) -> dict:
    return {
        "m365_scan_arch": arch,
        # The tailnet only. Everything ansible writes here is invisible to the
        # admin UI and cannot be taken back once the box is at a customer, so
        # nothing customer-shaped belongs in it: baking the box's own LAN in used
        # to mean a customer sitting on 10.0.0.0/8 got their whole corporate
        # network permanent, unremovable access to SSH and the admin UI. The
        # box's own LAN is seeded by firstboot.sh into the daemon's own list
        # instead, where the UI can show it, name it and let a customer replace
        # it. These two are a belt for the window before tailscaled is up — once
        # it is, firewall_trust_iifnames pins the tailnet by interface instead,
        # which is what actually keeps a CGNAT neighbour out.
        "management_cidrs": ["100.64.0.0/10", "fd7a:115c:a1e0::/48"],
        # The copier subnet is a customer decision, so it starts empty here too
        # and is seeded into the daemon's list by firstboot.sh.
        "m365_scan_client_cidrs": [],
        # No SSH session to protect on a `-c local` run; disable the revert deadman.
        "harden_safe_rollback": False,
    }


def main() -> None:
    arch, out = sys.argv[1:3]
    with open(out, "w") as f:
        json.dump(build(arch), f, indent=2)


if __name__ == "__main__":
    main()
