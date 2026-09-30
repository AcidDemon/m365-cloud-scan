// Command m365-scan runs the box: it watches the SMB shares, uploads what lands
// in them to SharePoint, and serves the admin UI.
//
// The watcher, the upload engine and the UI share one process because they
// share one state file, and splitting them would mean inventing a protocol
// between three things that live on the same disk.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/AcidDemon/m365-cloud-scan/internal/auth"
	"github.com/AcidDemon/m365-cloud-scan/internal/config"
	"github.com/AcidDemon/m365-cloud-scan/internal/engine"
	"github.com/AcidDemon/m365-cloud-scan/internal/graphref"
	"github.com/AcidDemon/m365-cloud-scan/internal/mdns"
	"github.com/AcidDemon/m365-cloud-scan/internal/scanui"
	"github.com/AcidDemon/m365-cloud-scan/internal/smb"
	"github.com/AcidDemon/m365-cloud-scan/internal/store"
	"github.com/AcidDemon/m365-cloud-scan/internal/watch"
	"github.com/AcidDemon/m365-cloud-scan/pkg/graph"
)

const defaultConfigPath = "/etc/m365-scan/config.json"

func main() {
	cfgPath := flag.String("config", defaultConfigPath, "path to config.json")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	var err error
	switch flag.Arg(0) {
	case "", "serve":
		err = serve(*cfgPath, log)
	case "reset-password":
		err = resetPassword(*cfgPath, flag.Arg(1))
	case "fw-reset":
		err = fwReset(*cfgPath)
	case "version":
		fmt.Println(version)
	default:
		err = fmt.Errorf("unknown command %q: use serve, reset-password, fw-reset or version", flag.Arg(0))
	}
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

func serve(cfgPath string, log *slog.Logger) error {
	ctx0 := context.Background()
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	// Refusing to start on a bad config beats discovering the missing field
	// hours later, when a scan fails and nobody is watching the journal.
	if err := cfg.Validate(); err != nil {
		return err
	}

	st, err := store.Open(cfg.StatePath)
	if err != nil {
		return err
	}

	// The Graph client is built even when the tenant details are missing: the
	// admin UI has to come up so someone can see *why* it is not connected.
	// Every Graph call then fails with that same error rather than a nil panic.
	gc, gcErr := graphClient(cfg)
	if gcErr != nil {
		log.Warn("no Graph connection; uploads will fail until the box is onboarded", "err", gcErr)
	}
	// Shared, because connecting the tenant from the admin UI has to reach the
	// upload engine without a restart.
	gref := graphref.New(gc)

	runner := smb.NewExecRunner()
	sm := smb.New(runner, cfg.ShareRoot)

	// Advertising is best effort. A box with no avahi still takes scans, it is
	// just reached by address until someone installs it.
	if _, port, err := net.SplitHostPort(cfg.UIBindAddr); err == nil {
		if p, err := strconv.Atoi(port); err == nil {
			if err := mdns.Publish(ctx0, runner, cfg.NetBIOSName, p); err != nil {
				log.Warn("could not advertise the box over mDNS", "err", err)
			}
		}
	}

	// The admin UI offers an upload-log retention; honour it here, where the
	// records are written.
	keep := 180 * 24 * time.Hour
	if d := scanui.HistoryRetention(cfg, log); d > 0 {
		keep = d
	}
	eng := engine.New(st, gref, engine.Options{
		KeepHistory:   keep,
		ProgressDir:   cfg.ProgressDir,
		QuarantineDir: cfg.QuarantineDir,
		Retry:         cfg.RetryPolicy,
	}, log.With("component", "engine"))

	w := watch.New(st, cfg.ShareRoot, log.With("component", "watch"))
	if cfg.RescanInterval > 0 {
		w.SetRescanInterval(cfg.RescanInterval)
	}

	secret, err := hex.DecodeString(cfg.UISessionSecret)
	if err != nil || len(secret) < 16 {
		return errors.New("uiSessionSecret must be at least 32 hex characters")
	}
	ui := scanui.NewServer(cfg, scanui.NewAuth(cfg.UIPasswordHash, secret, 12*time.Hour),
		st, sm, eng, gref, scanui.IndexHTML, log.With("component", "ui"))

	ui.SetRescan(w.Kick)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 3)
	go func() { errc <- named("watcher", w.Run(ctx)) }()
	go func() { errc <- named("engine", eng.Run(ctx)) }()
	go func() {
		err := ui.Serve()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- named("ui", err)
	}()

	log.Info("started", "ui", cfg.UIBindAddr, "shareRoot", cfg.ShareRoot, "version", version)

	// Any of the three exiting takes the process down. A box that is watching
	// but not uploading looks healthy to systemd while scans pile up, so it is
	// better to die and let the unit restart everything together.
	select {
	case <-ctx.Done():
		log.Info("shutting down")
		return nil
	case err := <-errc:
		return err
	}
}

func named(what string, err error) error {
	if err == nil {
		return fmt.Errorf("%s stopped unexpectedly", what)
	}
	return fmt.Errorf("%s: %w", what, err)
}

func graphClient(cfg config.Config) (*graph.Client, error) {
	if err := cfg.TenantReady(); err != nil {
		return nil, err
	}
	ts, err := auth.NewCertTokenSource(cfg.TenantID, cfg.ClientID, cfg.CertPath)
	if err != nil {
		return nil, err
	}
	base := cfg.GraphBaseURL
	if base == "" {
		base = "https://graph.microsoft.com/v1.0"
	}
	return graph.NewClient(&http.Client{Timeout: 5 * time.Minute}, base, ts), nil
}

// resetPassword writes a new bcrypt hash to the password file, which the config
// loader prefers over the hash in config.json. That is what makes a password
// change survive Ansible rewriting config.json underneath the running box.
func resetPassword(cfgPath, newPassword string) error {
	if len(newPassword) < 8 {
		return errors.New("usage: m365-scan reset-password <new password of at least 8 characters>")
	}
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
	if err != nil {
		return err
	}
	// The password file lives under /var/lib, not next to the config that was
	// just loaded, so on a fresh box its directory need not exist yet.
	if err := os.MkdirAll(filepath.Dir(cfg.UIPasswordFile), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(cfg.UIPasswordFile, hash, 0o600); err != nil {
		return err
	}
	fmt.Println("admin password changed. A running box picks it up on the next sign-in.")
	return nil
}

// fwReset is the console floor for a box locked out of its own admin UI by the
// networks someone typed into it: it throws away what the UI added and reloads
// the installer's own ruleset. Whoever runs this is already in trouble, so a
// missing file is not a failure and running it twice is safe.
func fwReset(cfgPath string) error {
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	saved := filepath.Join(filepath.Dir(cfg.StatePath), "firewall.json")
	if err := os.Rename(saved, saved+".bak"); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove("/etc/nftables.d/zz-m365-scan.nft"); err != nil && !os.IsNotExist(err) {
		return err
	}
	if out, err := exec.Command("nft", "-f", "/etc/nftables.conf").CombinedOutput(); err != nil {
		return fmt.Errorf("could not reload the firewall: %w: %s", err, bytes.TrimSpace(out))
	}
	fmt.Println("the networks added in the web UI are cleared and the installer's own rules are back, so the box is reachable again from the network it is plugged into.")
	return nil
}
