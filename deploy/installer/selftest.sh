#!/usr/bin/env bash
# Self-check for render-vars.py — it wires the management_cidrs + client_cidrs
# firewall overrides, which decide who can reach the box after hardening.
# Pure stdlib, no ansible/PyYAML needed.
# Run: deploy/installer/selftest.sh
set -euo pipefail
cd "$(dirname "$0")"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

python3 render-vars.py amd64 "$tmp/extra.json"

python3 - "$tmp/extra.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for k in ["m365_scan_arch", "management_cidrs", "harden_safe_rollback"]:
    assert d.get(k) not in (None, ""), f"missing/empty: {k}"
# Nothing tenant-specific may reach the box at install time: the image is generic
# and the admin connects the tenant from the box UI.
for k in d:
    assert not k.startswith("vault_"), f"a secret leaked back into extra-vars: {k}"
assert "m365_tenant_id" not in d and "m365_client_id" not in d, "tenant identity must come from the box UI"
# The tailnet, and nothing else. Anything ansible puts here the admin UI can
# never remove, so a customer LAN in this list would be permanent access to SSH
# and the admin UI; the box's own LAN is seeded by firstboot.sh into the daemon's
# editable list instead.
assert d["management_cidrs"] == ["100.64.0.0/10", "fd7a:115c:a1e0::/48"], d["management_cidrs"]
assert d["m365_scan_client_cidrs"] == [], d["m365_scan_client_cidrs"]
# base_firewall asserts on both of these before it will apply a ruleset, and an
# empty management list aborts the whole converge.
assert len(d["management_cidrs"]) > 0, "base_firewall refuses to apply with no management CIDRs"
assert d["harden_safe_rollback"] is False, "revert deadman must be off for a local run"
PY

echo "render-vars selftest OK"
