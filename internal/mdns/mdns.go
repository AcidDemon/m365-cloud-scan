// Package mdns advertises the box on the local network, so an MFP panel and an
// admin can both reach it as <name>.local instead of an address that moves with
// the DHCP lease. Samba's nmbd answers NetBIOS, which covers Windows, but macOS
// and anything modern asks over mDNS.
package mdns

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AcidDemon/m365-cloud-scan/internal/config"
	"github.com/AcidDemon/m365-cloud-scan/internal/smb"
)

// ServicePath is where avahi picks up statically advertised services. It is a
// variable so the tests can write somewhere harmless.
var ServicePath = "/etc/avahi/services/m365-scan.service"

const tmpl = `<?xml version="1.0" standalone='no'?><!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<!-- Written by m365-scan. Edits are overwritten when the server name changes. -->
<service-group>
  <name replace-wildcards="yes">%s on %%h</name>
  <service>
    <type>_smb._tcp</type>
    <port>445</port>
  </service>
  <service>
    <type>_https._tcp</type>
    <port>%d</port>
    <txt-record>path=/</txt-record>
  </service>
</service-group>
`

// Publish advertises the box under name and returns once avahi has reloaded.
//
// It also sets the system hostname, because avahi derives <host>.local from the
// hostname rather than from this file, and a box answering to a name in the
// admin UI that does not resolve is worse than not advertising at all.
func Publish(ctx context.Context, r smb.Runner, name string, uiPort int) error {
	if !config.ValidNetBIOSName(name) {
		return fmt.Errorf("bad server name %q", name)
	}
	if uiPort <= 0 || uiPort > 65535 {
		return fmt.Errorf("bad ui port %d", uiPort)
	}
	if err := os.MkdirAll(filepath.Dir(ServicePath), 0o755); err != nil {
		return err
	}
	body := fmt.Sprintf(tmpl, name, uiPort)
	if err := os.WriteFile(ServicePath, []byte(body), 0o644); err != nil {
		return err
	}
	host := strings.ToLower(name)
	if cur, _, err := r.Run(ctx, "hostname", nil, nil); err == nil && strings.TrimSpace(string(cur)) != host {
		if _, stderr, err := r.Run(ctx, "hostnamectl", []string{"set-hostname", host}, nil); err != nil {
			return fmt.Errorf("set hostname: %w: %s", err, strings.TrimSpace(string(stderr)))
		}
	}
	if _, stderr, err := r.Run(ctx, "systemctl", []string{"reload-or-restart", "avahi-daemon"}, nil); err != nil {
		return fmt.Errorf("reload avahi: %w: %s", err, strings.TrimSpace(string(stderr)))
	}
	return nil
}
