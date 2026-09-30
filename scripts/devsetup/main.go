// Command devsetup prepares a throwaway box under ./.dev so the admin UI can be
// run and clicked through on a workstation: a config, a fresh admin password and
// a few shares, destinations, routes and queued files that look like a real site.
//
// With -config it seeds only, into the state file and the share root that
// config names. The dev VM in deploy/dev-vm uses that to get the same demo data
// on the production paths, where the box itself owns the config and the password.
//
// Nothing here ships. There is no Samba and no tenant, so the shares are plain
// directories and the upload engine parks everything as pending.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/AcidDemon/m365-cloud-scan/internal/config"
	"github.com/AcidDemon/m365-cloud-scan/internal/model"
	"github.com/AcidDemon/m365-cloud-scan/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "devsetup:", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", "", "seed the box this config describes instead of building ./.dev")
	flag.Parse()
	if *cfgPath != "" {
		c, err := config.LoadConfig(*cfgPath)
		if err != nil {
			return err
		}
		return seedOnce(c.StatePath, c.ShareRoot, c.QuarantineDir)
	}

	root, err := filepath.Abs(".dev")
	if err != nil {
		return err
	}
	for _, d := range []string{"etc", "state", "srv"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o750); err != nil {
			return err
		}
	}

	pw := randomPassword()
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	if err != nil {
		return err
	}
	secret := make([]byte, 24)
	rand.Read(secret)

	cfg := map[string]any{
		"statePath":     filepath.Join(root, "state", "state.json"),
		"shareRoot":     filepath.Join(root, "srv"),
		"quarantineDir": filepath.Join(root, "state", "quarantine"),
		"progressDir":   filepath.Join(root, "state", "progress"),
		"ui": map[string]any{
			// 8445, not the box's 8444: the Vagrant VM forwards host 8444, and
			// two things answering the same URL is how you end up typing one
			// box's password into the other.
			"bindAddr":      "127.0.0.1:8445",
			"certPath":      filepath.Join(root, "etc", "ui-cert.pem"),
			"keyPath":       filepath.Join(root, "etc", "ui-key.pem"),
			"passwordHash":  string(hash),
			"passwordFile":  filepath.Join(root, "state", "ui-password"),
			"sessionSecret": hex.EncodeToString(secret),
		},
		"netbiosName": "m365scan",
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(filepath.Join(root, "etc", "config.json"), b, 0o600); err != nil {
		return err
	}
	// A password file left by reset-password outranks the hash written above, so
	// the password printed below would not be the one that works.
	if err := os.Remove(filepath.Join(root, "state", "ui-password")); err != nil && !os.IsNotExist(err) {
		return err
	}

	if err := seedOnce(cfg["statePath"].(string), filepath.Join(root, "srv"), cfg["quarantineDir"].(string)); err != nil {
		return err
	}

	fmt.Printf("\n  admin UI   https://127.0.0.1:8445\n  password   %s\n\n", pw)
	return nil
}

// seedOnce leaves a box that already has state alone. Seeding a second time
// would add a second set of demo shares, which is what a re-provision would do.
func seedOnce(statePath, shareRoot, quarantineDir string) error {
	if _, err := os.Stat(statePath); err == nil {
		fmt.Printf("kept the existing state at %s\n", statePath)
		return nil
	}
	if err := os.MkdirAll(shareRoot, 0o750); err != nil {
		return err
	}
	return seed(statePath, shareRoot, quarantineDir)
}

func randomPassword() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyz23456789"
	b := make([]byte, 16)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func seed(statePath, shareRoot, quarantineDir string) error {
	st, err := store.Open(statePath)
	if err != nil {
		return err
	}

	rules := model.ShareRules{
		Extensions:        []string{"pdf", "tif", "tiff", "jpg"},
		MaxSizeBytes:      100 << 20,
		StabilityDelay:    model.Duration(5 * time.Second),
		DeleteAfterUpload: true,
	}
	shares := map[string]model.Share{}
	for _, n := range []string{"scans-hr", "scans-buchhaltung", "mfp-eg-flur"} {
		sh, err := st.AddShare(model.Share{Name: n, SMBUser: "scan-" + n, Enabled: true, Rules: rules})
		if err != nil {
			return err
		}
		shares[n] = sh
		if err := os.MkdirAll(filepath.Join(shareRoot, n), 0o750); err != nil {
			return err
		}
	}

	dests := map[string]model.Destination{}
	for _, d := range []model.Destination{
		{Name: "Eingangsrechnungen", SiteName: "Finanzen", SiteID: "site-fin", DriveName: "Dokumente", DriveID: "drv-fin", FolderPath: "Eingangsrechnungen"},
		{Name: "Archiv 2026", SiteName: "Geschaeftsfuehrung", SiteID: "site-gf", DriveName: "Dokumente", DriveID: "drv-gf", FolderPath: "Archiv/2026"},
		{Name: "Bewerbungen", SiteName: "Personal", SiteID: "site-hr", DriveName: "Dokumente", DriveID: "drv-hr", FolderPath: "Bewerbungen"},
		{Name: "Allgemein", SiteName: "Personal", SiteID: "site-hr", DriveName: "Dokumente", DriveID: "drv-hr"},
	} {
		saved, err := st.PutDestination(d)
		if err != nil {
			return err
		}
		dests[d.Name] = saved
	}

	routes := map[string]model.Route{}
	for _, r := range []struct {
		share, dest, tmpl string
		enabled           bool
	}{
		{"scans-hr", "Bewerbungen", "{yyyy}/{MM}", true},
		{"scans-buchhaltung", "Eingangsrechnungen", "{yyyy}/{MM}", true},
		{"scans-buchhaltung", "Archiv 2026", "{yyyy}", true},
		{"mfp-eg-flur", "Allgemein", "{yyyy}/{MM}/{share}", true},
		{"mfp-eg-flur", "Bewerbungen", "", false},
	} {
		saved, err := st.PutRoute(model.Route{
			ShareID: shares[r.share].ID, DestinationID: dests[r.dest].ID,
			Enabled: r.enabled, SubfolderTemplate: r.tmpl,
			Conflict: model.ConflictRename, MaxAttempts: 5,
		})
		if err != nil {
			return err
		}
		routes[r.share+"|"+r.dest] = saved
	}

	now := time.Now()
	type demo struct {
		share, file string
		states      []model.LegState
		err         string
	}
	for _, d := range []demo{
		{"scans-buchhaltung", "Rechnung_2026-08-19.pdf", []model.LegState{model.LegUploading, model.LegPending}, ""},
		{"scans-buchhaltung", "Lieferschein_4471.pdf", []model.LegState{model.LegConfirmed, model.LegRetrying}, "503 Service Unavailable"},
		{"scans-hr", "Vertrag_Mueller_scan.pdf", []model.LegState{model.LegPending}, ""},
		{"mfp-eg-flur", "Protokoll_Betriebsrat.pdf", []model.LegState{model.LegQuarantined}, "404 the destination folder was removed"},
	} {
		p := filepath.Join(shareRoot, d.share, d.file)
		body := make([]byte, 256<<10)
		rand.Read(body)
		if err := os.WriteFile(p, body, 0o640); err != nil {
			return err
		}
		var legs []model.Leg
		i := 0
		for k, rt := range routes {
			if len(k) < len(d.share) || k[:len(d.share)] != d.share || !rt.Enabled {
				continue
			}
			if i >= len(d.states) {
				break
			}
			leg := model.Leg{RouteID: rt.ID, State: d.states[i]}
			switch leg.State {
			case model.LegUploading:
				leg.Sent = int64(len(body)) / 3
			case model.LegConfirmed:
				leg.UploadedAt = now.Add(-42 * time.Minute)
				leg.DriveItemID = "01DEMO" + rt.ID
			case model.LegRetrying:
				leg.Attempts, leg.LastError, leg.NextAttempt = 2, d.err, now.Add(90*time.Second)
			case model.LegQuarantined:
				leg.Attempts, leg.LastError = 5, d.err
			}
			legs = append(legs, leg)
			i++
		}
		// The watcher treats a file whose mtime is newer than the item as a
		// re-scan, so backdate the file to match its pretend discovery time.
		found := now.Add(-time.Duration(i+1) * 7 * time.Minute)
		if err := os.Chtimes(p, found, found); err != nil {
			return err
		}
		saved, err := st.PutItem(model.Item{
			ShareID: shares[d.share].ID, Path: p, Name: d.file, Size: int64(len(body)),
			Discovered: found, Legs: legs,
			Quarantined: d.states[0] == model.LegQuarantined,
		})
		if err != nil {
			return err
		}
		if saved.Quarantined {
			// Item.Path keeps naming the share copy, but the bytes live in
			// quarantine. Leaving them in the share is a state production never
			// produces, and the watcher would queue the file again on every sweep.
			q := filepath.Join(quarantineDir, d.share, saved.ID+"-"+d.file)
			if err := os.MkdirAll(filepath.Dir(q), 0o750); err != nil {
				return err
			}
			if err := os.Rename(p, q); err != nil {
				return err
			}
		}
	}
	fmt.Println("seeded 3 shares, 4 destinations, 5 routes and 4 queued scans")
	return nil
}
