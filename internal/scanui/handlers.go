package scanui

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/internal/config"
	"github.com/AcidDemon/m365-cloud-scan/internal/mdns"
	"github.com/AcidDemon/m365-cloud-scan/internal/model"
	"github.com/AcidDemon/m365-cloud-scan/internal/smb"
	"github.com/AcidDemon/m365-cloud-scan/internal/store"
	"github.com/AcidDemon/m365-cloud-scan/pkg/graph"
)

// --- shares ---

func (s *Server) handleShareAdd(rw http.ResponseWriter, r *http.Request) {
	var b struct{ Name, SMBUser, Password string }
	if !decode(rw, r, &b) {
		return
	}
	// Held for the whole of this handler: the uniqueness check below and the
	// store write at the end are a check-then-act with useradd, smbpasswd and
	// net conf in between. Two requests inside that window both passed, and the
	// second one's rollback removed the share the first had just created.
	s.shareMu.Lock()
	defer s.shareMu.Unlock()
	sm, err := s.samba()
	if err != nil {
		fail(rw, err)
		return
	}
	name := strings.ToLower(strings.TrimSpace(b.Name))
	if err := store.ValidShareName(name); err != nil {
		fail(rw, err)
		return
	}
	user := strings.ToLower(strings.TrimSpace(b.SMBUser))
	if user == "" {
		user = defaultSMBUser(name)
	}
	// One account per share keeps the rollback below safe: removing the account
	// of a failed share can never cut off a share that already works.
	for _, sh := range s.st.Shares() {
		// The name has to be checked here too: store.AddShare refuses a duplicate
		// only after EnsureShare has already written the registry, and the
		// rollback then removes the share that was there first.
		if sh.Name == name {
			failText(rw, "the share "+name+" already exists")
			return
		}
		if sh.SMBUser == user {
			failText(rw, "the account "+user+" already belongs to the share "+sh.Name)
			return
		}
	}

	password, err := sharePassword(b.Password)
	if err != nil {
		fail(rw, err)
		return
	}

	// A client that hangs up mid-request must not leave the rollback half done.
	ctx := context.WithoutCancel(r.Context())
	if err := sm.EnsureUser(ctx, user, password); err != nil {
		// useradd may have succeeded before smbpasswd failed.
		s.undoShare(ctx, "", user)
		fail(rw, err)
		return
	}
	if err := sm.EnsureShare(ctx, name, user); err != nil {
		s.undoShare(ctx, name, user)
		fail(rw, err)
		return
	}
	sh, err := s.st.AddShare(model.Share{
		Name:    name,
		SMBUser: user,
		Enabled: true,
		Rules:   s.currentSettings().DefaultRules,
	})
	if err != nil {
		s.undoShare(ctx, name, user)
		fail(rw, err)
		return
	}
	s.log.Info("share created", "share", sh.Name, "user", user, "dir", sm.ShareDir(sh.Name))
	// The password is shown once and never stored: the box has no reason to
	// know it after Samba has it.
	// Watch it now. Otherwise the first scan into a brand new share waits for
	// the rescan tick, which looks exactly like a share that does not work.
	s.kickWatcher()
	writeJSON(rw, map[string]any{"share": sh, "password": password})
}

func (s *Server) handleShareUpdate(rw http.ResponseWriter, r *http.Request) {
	var b struct {
		Share model.Share `json:"share"`
	}
	if !decode(rw, r, &b) {
		return
	}
	cur, ok := s.st.Share(b.Share.ID)
	if !ok {
		failText(rw, "that share no longer exists")
		return
	}
	// The name is the directory, the Samba share and the {share} token at once,
	// so a rename is a new share, not an edit.
	if b.Share.Name != "" && b.Share.Name != cur.Name {
		failText(rw, "the share name cannot be changed, create a new share instead")
		return
	}
	if b.Share.SMBUser != "" && b.Share.SMBUser != cur.SMBUser {
		failText(rw, "the account cannot be changed, create a new share instead")
		return
	}
	next := cur
	next.Enabled = b.Share.Enabled
	next.Rules = b.Share.Rules
	if next.Enabled != cur.Enabled {
		if err := s.applyEnabled(context.WithoutCancel(r.Context()), next, next.Enabled); err != nil {
			fail(rw, err)
			return
		}
	}
	if err := s.st.PutShare(next); err != nil {
		fail(rw, err)
		return
	}
	writeJSON(rw, map[string]any{"share": next})
}

func (s *Server) handleShareRemove(rw http.ResponseWriter, r *http.Request) {
	var b struct{ ID string }
	if !decode(rw, r, &b) {
		return
	}
	sm, err := s.samba()
	if err != nil {
		fail(rw, err)
		return
	}
	sh, ok := s.st.Share(b.ID)
	if !ok {
		failText(rw, "that share no longer exists")
		return
	}
	ctx := context.WithoutCancel(r.Context())
	if err := sm.RemoveShare(ctx, sh.Name); err != nil {
		fail(rw, err)
		return
	}
	// The share is already gone; a leftover account can reach nothing, so it is
	// worth a log line rather than a failed request the admin cannot retry.
	if err := sm.RemoveUser(ctx, sh.SMBUser); err != nil {
		s.log.Error("removing the share account failed", "share", sh.Name, "user", sh.SMBUser, "err", err)
	}
	if err := s.st.DeleteShare(sh.ID); err != nil {
		fail(rw, err)
		return
	}
	dir := sm.ShareDir(sh.Name)
	s.log.Info("share removed", "share", sh.Name, "dir", dir)
	writeJSON(rw, map[string]any{
		"ok":   true,
		"dir":  dir,
		"note": "the scans were kept in " + dir,
	})
}

func (s *Server) handleShareRotatePW(rw http.ResponseWriter, r *http.Request) {
	var b struct{ ID, Password string }
	if !decode(rw, r, &b) {
		return
	}
	sm, err := s.samba()
	if err != nil {
		fail(rw, err)
		return
	}
	sh, ok := s.st.Share(b.ID)
	if !ok {
		failText(rw, "that share no longer exists")
		return
	}
	password, err := sharePassword(b.Password)
	if err != nil {
		fail(rw, err)
		return
	}
	if err := sm.SetPassword(context.WithoutCancel(r.Context()), sh.SMBUser, password); err != nil {
		fail(rw, err)
		return
	}
	s.log.Info("share password rotated", "share", sh.Name, "user", sh.SMBUser)
	writeJSON(rw, map[string]any{"password": password})
}

func (s *Server) handleShareSetEnabled(rw http.ResponseWriter, r *http.Request) {
	var b struct {
		ID      string
		Enabled bool
	}
	if !decode(rw, r, &b) {
		return
	}
	sh, ok := s.st.Share(b.ID)
	if !ok {
		failText(rw, "that share no longer exists")
		return
	}
	if err := s.applyEnabled(context.WithoutCancel(r.Context()), sh, b.Enabled); err != nil {
		fail(rw, err)
		return
	}
	sh.Enabled = b.Enabled
	if err := s.st.PutShare(sh); err != nil {
		fail(rw, err)
		return
	}
	s.kickWatcher()
	writeJSON(rw, map[string]any{"share": sh})
}

// applyEnabled makes Samba match the record. A disabled share keeps its files
// and its account but stops answering, which is what "off" means to an admin.
func (s *Server) applyEnabled(ctx context.Context, sh model.Share, on bool) error {
	sm, err := s.samba()
	if err != nil {
		return err
	}
	if on {
		return sm.EnsureShare(ctx, sh.Name, sh.SMBUser)
	}
	return sm.RemoveShare(ctx, sh.Name)
}

// undoShare rolls back a half-created share. What it cannot remove it logs:
// Samba serving a share the UI does not list is the outcome worth shouting
// about.
func (s *Server) undoShare(ctx context.Context, name, user string) {
	if name != "" {
		if err := s.sm.RemoveShare(ctx, name); err != nil {
			s.log.Error("rollback: removing the share failed", "share", name, "err", err)
		}
	}
	if user != "" {
		if err := s.sm.RemoveUser(ctx, user); err != nil {
			s.log.Error("rollback: removing the account failed", "user", user, "err", err)
		}
	}
}

func (s *Server) samba() (*smb.Manager, error) {
	if s.sm == nil {
		return nil, errors.New("Samba is not available on this box")
	}
	return s.sm, nil
}

// sharePassword takes what the admin typed, or mints one when they typed
// nothing. It is not trimmed: a password is what it is.
func sharePassword(given string) (string, error) {
	if given == "" {
		return smb.GeneratePassword(), nil
	}
	if err := smb.ValidPassword(given); err != nil {
		return "", err
	}
	return given, nil
}

// defaultSMBUser mints the account name for a share the admin did not name one
// for. useradd tops out at 32 characters.
func defaultSMBUser(share string) string {
	u := "scan-" + share
	if len(u) > 31 {
		u = u[:31]
	}
	return strings.TrimRight(u, "-")
}

// --- destinations ---

func (s *Server) handleDestinationSave(rw http.ResponseWriter, r *http.Request) {
	var b struct {
		Destination model.Destination `json:"destination"`
	}
	if !decode(rw, r, &b) {
		return
	}
	d := b.Destination
	d.Name = strings.TrimSpace(d.Name)
	d.FolderPath = strings.Trim(strings.TrimSpace(d.FolderPath), "/")
	switch {
	case d.Name == "":
		failText(rw, "give the destination a name")
		return
	case d.SiteID == "":
		failText(rw, "pick a SharePoint site")
		return
	case d.DriveID == "":
		failText(rw, "pick a document library")
		return
	}
	saved, err := s.st.PutDestination(d)
	if err != nil {
		fail(rw, err)
		return
	}
	writeJSON(rw, map[string]any{"destination": saved})
}

func (s *Server) handleDestinationRemove(rw http.ResponseWriter, r *http.Request) {
	var b struct{ ID string }
	if !decode(rw, r, &b) {
		return
	}
	// The store refuses while routes point at it, which is what keeps a delete
	// from silently stopping a scan folder from being delivered.
	if err := s.st.DeleteDestination(b.ID); err != nil {
		fail(rw, err)
		return
	}
	writeJSON(rw, map[string]any{"ok": true})
}

// --- routes ---

func (s *Server) handleRouteSave(rw http.ResponseWriter, r *http.Request) {
	var b struct {
		Route model.Route `json:"route"`
	}
	if !decode(rw, r, &b) {
		return
	}
	rt := b.Route
	if _, ok := s.st.Share(rt.ShareID); !ok {
		failText(rw, "pick a share")
		return
	}
	if _, ok := s.st.Destination(rt.DestinationID); !ok {
		failText(rw, "pick a destination")
		return
	}
	if rt.Conflict == "" {
		rt.Conflict = model.ConflictRename
	}
	if rt.Conflict != model.ConflictRename && rt.Conflict != model.ConflictOverwrite {
		failText(rw, "the conflict policy must be rename or overwrite")
		return
	}
	if rt.MaxAttempts < 0 {
		failText(rw, "the retry count cannot be negative")
		return
	}
	rt.SubfolderTemplate = strings.Trim(strings.TrimSpace(rt.SubfolderTemplate), "/")
	if err := model.ValidateTemplate(rt.SubfolderTemplate); err != nil {
		failText(rw, err.Error())
		return
	}
	saved, err := s.st.PutRoute(rt)
	if err != nil {
		fail(rw, err)
		return
	}
	writeJSON(rw, map[string]any{"route": saved})
}

func (s *Server) handleRouteRemove(rw http.ResponseWriter, r *http.Request) {
	var b struct{ ID string }
	if !decode(rw, r, &b) {
		return
	}
	if err := s.st.DeleteRoute(b.ID); err != nil {
		fail(rw, err)
		return
	}
	writeJSON(rw, map[string]any{"ok": true})
}

func (s *Server) handleRouteSetEnabled(rw http.ResponseWriter, r *http.Request) {
	var b struct {
		ID      string
		Enabled bool
	}
	if !decode(rw, r, &b) {
		return
	}
	rt, ok := s.st.Route(b.ID)
	if !ok {
		failText(rw, "that route no longer exists")
		return
	}
	rt.Enabled = b.Enabled
	saved, err := s.st.PutRoute(rt)
	if err != nil {
		fail(rw, err)
		return
	}
	writeJSON(rw, map[string]any{"route": saved})
}

func (s *Server) handleRouteTest(rw http.ResponseWriter, r *http.Request) {
	var b struct{ ID string }
	if !decode(rw, r, &b) {
		return
	}
	if s.eng == nil {
		failText(rw, "the upload engine is not running")
		return
	}
	if err := s.eng.TestRoute(r.Context(), b.ID); err != nil {
		s.noteGraph(err)
		fail(rw, err)
		return
	}
	s.noteGraph(nil)
	writeJSON(rw, map[string]any{"ok": true})
}

// --- SharePoint browsing ---

// handleSPSites answers from the sites onboarding was granted, never from Graph.
// An app-only token with Sites.Selected may use the sites it was given and
// nothing else: asking Graph to search returns HTTP 401 generalException, which
// reads like a broken connection when it is really the permission working as
// designed. The query filters that list locally.
func (s *Server) handleSPSites(rw http.ResponseWriter, r *http.Request) {
	granted := s.grantedSites()
	if len(granted) == 0 {
		failText(rw, "no SharePoint site has been granted to this box yet. Connect the tenant under Settings and choose the sites it may write to")
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	out := []map[string]string{}
	for _, si := range granted {
		if q != "" && !strings.Contains(strings.ToLower(si.Name), q) && !strings.Contains(strings.ToLower(si.URL), q) {
			continue
		}
		out = append(out, map[string]string{"id": si.ID, "name": si.Name, "webUrl": si.URL})
	}
	writeJSON(rw, map[string]any{"sites": out, "granted": true})
}

func (s *Server) handleSPDrives(rw http.ResponseWriter, r *http.Request) {
	gc, err := s.graphClient()
	if err != nil {
		fail(rw, err)
		return
	}
	site := r.URL.Query().Get("site")
	if site == "" {
		failText(rw, "no site was given")
		return
	}
	drives, err := gc.Drives(r.Context(), site)
	s.noteGraph(err)
	if err != nil {
		fail(rw, err)
		return
	}
	writeJSON(rw, map[string]any{"drives": drives})
}

func (s *Server) handleSPChildren(rw http.ResponseWriter, r *http.Request) {
	gc, err := s.graphClient()
	if err != nil {
		fail(rw, err)
		return
	}
	drive := r.URL.Query().Get("drive")
	if drive == "" {
		failText(rw, "no library was given")
		return
	}
	folders, err := gc.Children(r.Context(), drive, r.URL.Query().Get("path"))
	s.noteGraph(err)
	if err != nil {
		fail(rw, err)
		return
	}
	writeJSON(rw, map[string]any{"folders": folderList(folders)})
}

// folderJSON carries the library-relative path the picker navigates by.
// graph.Folder keeps it out of its own JSON because Graph does not send it.
type folderJSON struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
}

func folderList(in []graph.Folder) []folderJSON {
	out := make([]folderJSON, 0, len(in))
	for _, f := range in {
		out = append(out, folderJSON{f.ID, f.Name, f.Path})
	}
	return out
}

func (s *Server) handleSPMkdir(rw http.ResponseWriter, r *http.Request) {
	var b struct{ Drive, Path, Name string }
	if !decode(rw, r, &b) {
		return
	}
	gc, err := s.graphClient()
	if err != nil {
		fail(rw, err)
		return
	}
	if b.Drive == "" {
		failText(rw, "no library was given")
		return
	}
	if strings.TrimSpace(b.Name) == "" {
		failText(rw, "give the folder a name")
		return
	}
	f, err := gc.CreateFolder(r.Context(), b.Drive, b.Path, strings.TrimSpace(b.Name))
	s.noteGraph(err)
	if err != nil {
		fail(rw, err)
		return
	}
	writeJSON(rw, map[string]any{"folder": folderJSON{f.ID, f.Name, f.Path}})
}

// --- queue ---

func (s *Server) handleQueueRetry(rw http.ResponseWriter, r *http.Request) {
	var b struct{ ID string }
	if !decode(rw, r, &b) {
		return
	}
	if s.eng == nil {
		failText(rw, "the upload engine is not running")
		return
	}
	if err := s.eng.Retry(b.ID); err != nil {
		fail(rw, err)
		return
	}
	writeJSON(rw, map[string]any{"ok": true})
}

// handleQueueRemove takes a file out of the queue without ever unlinking it: a
// scan that is still in its share is renamed to a dotted sibling, which the
// watcher skips, so dropping the record cannot make it come back on the next
// sweep. A quarantined file is already out of the share and stays put.
func (s *Server) handleQueueRemove(rw http.ResponseWriter, r *http.Request) {
	var b struct{ ID string }
	if !decode(rw, r, &b) {
		return
	}
	it, ok := s.st.Item(b.ID)
	if !ok {
		failText(rw, "that file is no longer in the queue")
		return
	}
	kept := it.Path
	if !it.Quarantined {
		kept = filepath.Join(filepath.Dir(it.Path), "."+it.Name+".removed")
		if err := os.Rename(it.Path, kept); err != nil && !errors.Is(err, os.ErrNotExist) {
			failText(rw, "the file could not be moved aside: "+err.Error())
			return
		}
	}
	if err := s.st.DeleteItem(b.ID); err != nil {
		fail(rw, err)
		return
	}
	s.log.Info("item removed from the queue", "item", b.ID, "file", kept)
	writeJSON(rw, map[string]any{"ok": true, "file": kept})
}

// --- settings ---

// Settings are the box-wide knobs the daemon and the share defaults read. They
// live beside the state file rather than in it, so config management can drop
// in a state file without clobbering what an admin set here.
type Settings struct {
	SMBMinProtocol string           `json:"smbMinProtocol"`
	ServerName     string           `json:"serverName"`
	Workgroup      string           `json:"workgroup"`
	DefaultRules   model.ShareRules `json:"defaultRules"`
	QuarantineDir  string           `json:"quarantineDir"`
	RetentionDays  int              `json:"retentionDays"`
}

func defaultSettings(cfg config.Config) Settings {
	return Settings{
		SMBMinProtocol: "SMB2",
		ServerName:     cfg.NetBIOSName,
		Workgroup:      "WORKGROUP",
		DefaultRules: model.ShareRules{
			StabilityDelay:    model.Duration(5 * time.Second),
			DeleteAfterUpload: true,
		},
		QuarantineDir: cfg.QuarantineDir,
		RetentionDays: 30,
	}
}

func settingsPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "settings.json")
}

// loadSettings overlays the file on the defaults, so a file written by an older
// build keeps working.
func loadSettings(path string, def Settings, log *slog.Logger) Settings {
	raw, err := os.ReadFile(path)
	if err != nil {
		return def
	}
	out := def
	if err := json.Unmarshal(raw, &out); err != nil {
		log.Error("settings file unreadable, using the defaults", "path", path, "err", err)
		return def
	}
	return out
}

func (s *Server) currentSettings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings
}

func (s *Server) handleGetSettings(rw http.ResponseWriter, r *http.Request) {
	writeJSON(rw, map[string]any{"settings": s.currentSettings()})
}

func (s *Server) handleSetSettings(rw http.ResponseWriter, r *http.Request) {
	var b struct {
		Settings Settings `json:"settings"`
	}
	if !decode(rw, r, &b) {
		return
	}
	cur := s.currentSettings()
	next := b.Settings
	next.SMBMinProtocol = strings.ToUpper(strings.TrimSpace(next.SMBMinProtocol))
	if next.SMBMinProtocol == "" {
		next.SMBMinProtocol = "SMB2"
	}
	if !smb.ValidMinProtocol(next.SMBMinProtocol) {
		failText(rw, "the minimum SMB protocol must be SMB1, SMB2 or SMB3")
		return
	}
	// An older page, or one that never loaded the settings, sends these empty.
	// Keeping what is set beats renaming the box to "".
	next.ServerName = strings.TrimSpace(next.ServerName)
	if next.ServerName == "" {
		next.ServerName = cur.ServerName
	}
	next.Workgroup = strings.TrimSpace(next.Workgroup)
	if next.Workgroup == "" {
		next.Workgroup = cur.Workgroup
	}
	if !config.ValidNetBIOSName(next.ServerName) {
		failText(rw, "the server name must be up to 15 letters, digits or hyphens")
		return
	}
	if !config.ValidNetBIOSName(next.Workgroup) {
		failText(rw, "the workgroup must be up to 15 letters, digits or hyphens")
		return
	}
	if next.RetentionDays < 0 {
		failText(rw, "the retention period cannot be negative")
		return
	}
	if !filepath.IsAbs(next.QuarantineDir) {
		failText(rw, "the quarantine path must be absolute")
		return
	}
	if next.DefaultRules.MaxSizeBytes < 0 {
		failText(rw, "the maximum file size cannot be negative")
		return
	}
	// Samba first: a settings file that promises a floor or a name Samba never
	// took would be a lie the admin cannot see.
	if next.SMBMinProtocol != cur.SMBMinProtocol || next.ServerName != cur.ServerName || next.Workgroup != cur.Workgroup {
		sm, err := s.samba()
		if err != nil {
			fail(rw, err)
			return
		}
		if err := sm.SetGlobal(context.WithoutCancel(r.Context()), next.SMBMinProtocol, next.ServerName, next.Workgroup); err != nil {
			fail(rw, err)
			return
		}
		// The advertised name follows the SMB name, or the box answers to one
		// name on the network and a different one in mDNS. Advertising is not
		// worth failing the save over: the settings are already applied.
		if next.ServerName != cur.ServerName {
			if _, port, err := net.SplitHostPort(s.cfg.UIBindAddr); err == nil {
				if p, err := strconv.Atoi(port); err == nil {
					if err := mdns.Publish(context.WithoutCancel(r.Context()), sm.Runner(), next.ServerName, p); err != nil {
						s.log.Warn("could not advertise the new server name over mDNS", "err", err)
					}
				}
			}
		}
	}
	raw, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		fail(rw, err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.settingsPath), 0o750); err != nil {
		fail(rw, err)
		return
	}
	if err := os.WriteFile(s.settingsPath, raw, 0o640); err != nil {
		failText(rw, "the settings could not be saved: "+err.Error())
		return
	}
	s.mu.Lock()
	s.settings = next
	s.mu.Unlock()
	// /api/state keeps reporting what Samba answers, which is the floor smbd has
	// actually picked up, not the one that was asked for here.
	writeJSON(rw, map[string]any{"settings": next})
}

// HistoryRetention is how long finished uploads stay listed. It lives with the
// settings file rather than the daemon config, which Ansible owns.
func HistoryRetention(cfg config.Config, log *slog.Logger) time.Duration {
	st := loadSettings(settingsPath(cfg.StatePath), defaultSettings(cfg), log)
	if st.RetentionDays <= 0 {
		return 0
	}
	return time.Duration(st.RetentionDays) * 24 * time.Hour
}
