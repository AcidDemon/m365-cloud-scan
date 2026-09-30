package scanui

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AcidDemon/m365-cloud-scan/internal/model"
)

// addShare drives the happy path and returns the share id and the one-time
// password.
func addShare(t *testing.T, s *Server, tok, name string) (id, password string) {
	t.Helper()
	out := post(t, s, "/api/shares/add", `{"name":"`+name+`"}`, tok)
	if e, ok := out["error"]; ok {
		t.Fatalf("add share %s: %v", name, e)
	}
	sh, ok := out["share"].(map[string]any)
	if !ok {
		t.Fatalf("add share %s: no share in %v", name, out)
	}
	pw, _ := out["password"].(string)
	if len(pw) != 16 {
		t.Fatalf("password %q: want 16 characters", pw)
	}
	return sh["id"].(string), pw
}

func TestAddShareCreatesUserShareAndRecord(t *testing.T) {
	s, run, _ := newTestServer(t)
	tok := session(t, s)
	id, _ := addShare(t, s, tok, "scans-hr")

	sh, ok := s.st.Share(id)
	if !ok {
		t.Fatal("the share was not stored")
	}
	if sh.SMBUser != "scan-scans-hr" || !sh.Enabled {
		t.Errorf("stored %+v", sh)
	}
	for _, want := range []string{"useradd", "smbpasswd -a -s scan-scans-hr", "net conf addshare scans-hr"} {
		if !run.ran(want) {
			t.Errorf("missing command %q in %v", want, run.calls)
		}
	}
	if _, err := os.Stat(filepath.Join(s.cfg.ShareRoot, "scans-hr")); err != nil {
		t.Errorf("share directory: %v", err)
	}
	// A second share must not reuse the account, or removing one would break
	// the other.
	if out := post(t, s, "/api/shares/add", `{"name":"scans-hr2","smbUser":"scan-scans-hr"}`, tok); out["error"] == nil {
		t.Error("reusing another share's account should be refused")
	}
}

// An MFP panel may already hold a password, so the admin has to be able to
// type that one instead of taking a generated one.
func TestSharePasswordCanBeChosen(t *testing.T) {
	s, run, _ := newTestServer(t)
	tok := session(t, s)
	const chosen = "Kopierer-2026"

	out := post(t, s, "/api/shares/add", `{"name":"scans-hr","password":"`+chosen+`"}`, tok)
	if out["password"] != chosen {
		t.Fatalf("add: password = %v, want the one that was supplied", out["password"])
	}
	if !run.gotStdin(chosen + "\n" + chosen + "\n") {
		t.Errorf("smbpasswd did not get the chosen password: %v", run.calls)
	}
	id := out["share"].(map[string]any)["id"].(string)

	const rotated = "Kopierer-2027"
	if got := post(t, s, "/api/shares/rotatepw", `{"id":"`+id+`","password":"`+rotated+`"}`, tok); got["password"] != rotated {
		t.Errorf("rotate: password = %v", got["password"])
	}
	// No password means one is generated, which is still the default path.
	if got := post(t, s, "/api/shares/rotatepw", `{"id":"`+id+`"}`, tok); len(got["password"].(string)) != 16 {
		t.Errorf("rotate without a password = %v, want a generated one", got["password"])
	}
}

// smbpasswd reads the password from stdin as one line, so anything that could
// end that line early has to be refused before it gets there.
func TestSharePasswordRefusesUnusableOnes(t *testing.T) {
	s, run, _ := newTestServer(t)
	tok := session(t, s)
	id, _ := addShare(t, s, tok, "scans-hr")

	for _, tc := range []struct{ name, pw string }{
		{"too short", "kurz123"},
		{"a newline", `abcdefgh\nxyz`},
		{"a carriage return", `abcdefgh\rxyz`},
		{"a null byte", `abcdefgh\u0000xyz`},
	} {
		add := post(t, s, "/api/shares/add", `{"name":"scans-neu","password":"`+tc.pw+`"}`, tok)
		if add["error"] == nil {
			t.Errorf("add with %s should be refused: %v", tc.name, add)
		}
		if add["password"] != nil {
			t.Errorf("add with %s handed out a password", tc.name)
		}
		rot := post(t, s, "/api/shares/rotatepw", `{"id":"`+id+`","password":"`+tc.pw+`"}`, tok)
		if rot["error"] == nil {
			t.Errorf("rotate with %s should be refused: %v", tc.name, rot)
		}
	}
	// A refused password must not have created or touched anything.
	if len(s.st.Shares()) != 1 {
		t.Errorf("shares = %v", s.st.Shares())
	}
	if run.ran("useradd --system --no-create-home --shell /usr/sbin/nologin scan-scans-neu") {
		t.Errorf("a refused password still reached the OS: %v", run.calls)
	}
}

func TestAddShareRollsBackWhenSambaFails(t *testing.T) {
	s, run, _ := newTestServer(t)
	tok := session(t, s)
	run.failPrefix = "net conf addshare"

	out := post(t, s, "/api/shares/add", `{"name":"scans-hr"}`, tok)
	if out["error"] == nil {
		t.Fatalf("expected an error, got %v", out)
	}
	if out["password"] != nil {
		t.Error("a failed add must not hand out a password")
	}
	if got := s.st.Shares(); len(got) != 0 {
		t.Errorf("the store kept %d share(s) after a failed add", len(got))
	}
	// The account created before the failing step has to go, or Samba keeps an
	// account for a share the UI does not list.
	if !run.ran("userdel scan-scans-hr") {
		t.Errorf("no rollback of the unix account: %v", run.calls)
	}
	if !run.ran("smbpasswd -x scan-scans-hr") {
		t.Errorf("no rollback of the samba account: %v", run.calls)
	}
}

func TestAddShareRefusesADuplicateNameBeforeTouchingSamba(t *testing.T) {
	s, run, _ := newTestServer(t)
	tok := session(t, s)
	addShare(t, s, tok, "scans-hr")
	before := len(run.calls)

	// Same name, different account. This has to be caught before Samba is
	// touched: the registry entry would be the existing share's, and the
	// rollback would then delete the share that was already working.
	out := post(t, s, "/api/shares/add", `{"name":"scans-hr","smbUser":"scan-other"}`, tok)
	if out["error"] == nil {
		t.Fatalf("a duplicate name should be refused, got %v", out)
	}
	if len(run.calls) != before {
		t.Errorf("a duplicate name still reached the OS: %v", run.calls[before:])
	}
	if len(s.st.Shares()) != 1 {
		t.Errorf("the first share did not survive: %v", s.st.Shares())
	}
	// The share the admin already had still answers.
	if !run.shares["scans-hr"] {
		t.Error("the existing share was removed from the registry")
	}
}

func TestRemoveShareKeepsTheFiles(t *testing.T) {
	s, run, _ := newTestServer(t)
	tok := session(t, s)
	id, _ := addShare(t, s, tok, "scans-hr")

	out := post(t, s, "/api/shares/remove", `{"id":"`+id+`"}`, tok)
	if out["ok"] != true {
		t.Fatalf("remove: %v", out)
	}
	dir := filepath.Join(s.cfg.ShareRoot, "scans-hr")
	if out["dir"] != dir || !strings.Contains(out["note"].(string), dir) {
		t.Errorf("the response must say where the scans are: %v", out)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("the directory must survive: %v", err)
	}
	if !run.ran("net conf delshare scans-hr") || !run.ran("userdel scan-scans-hr") {
		t.Errorf("samba was not cleaned up: %v", run.calls)
	}
	if len(s.st.Shares()) != 0 {
		t.Error("the record survived the removal")
	}
}

func TestSetEnabledTogglesTheSambaShare(t *testing.T) {
	s, run, _ := newTestServer(t)
	tok := session(t, s)
	id, _ := addShare(t, s, tok, "scans-hr")

	post(t, s, "/api/shares/setenabled", `{"id":"`+id+`","enabled":false}`, tok)
	if sh, _ := s.st.Share(id); sh.Enabled {
		t.Error("the share is still enabled")
	}
	if !run.ran("net conf delshare scans-hr") {
		t.Errorf("disabling did not stop the samba share: %v", run.calls)
	}
	post(t, s, "/api/shares/setenabled", `{"id":"`+id+`","enabled":true}`, tok)
	if sh, _ := s.st.Share(id); !sh.Enabled {
		t.Error("the share was not re-enabled")
	}
}

func TestRotatePasswordDoesNotStoreIt(t *testing.T) {
	s, _, _ := newTestServer(t)
	tok := session(t, s)
	id, first := addShare(t, s, tok, "scans-hr")

	out := post(t, s, "/api/shares/rotatepw", `{"id":"`+id+`"}`, tok)
	second, _ := out["password"].(string)
	if len(second) != 16 || second == first {
		t.Fatalf("rotate returned %q", second)
	}
	raw, err := os.ReadFile(s.cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, pw := range []string{first, second} {
		if strings.Contains(string(raw), pw) {
			t.Error("a share password reached the state file")
		}
	}
}

func TestDestinationInUseIsNotDeleted(t *testing.T) {
	s, _, _ := newTestServer(t)
	tok := session(t, s)
	shareID, _ := addShare(t, s, tok, "scans-hr")

	dest := post(t, s, "/api/destinations/save",
		`{"destination":{"name":"Eingang","siteId":"s1","siteName":"Finanzen","driveId":"d1","folderPath":"/Eingang/"}}`, tok)
	d := dest["destination"].(map[string]any)
	if d["folderPath"] != "Eingang" {
		t.Errorf("folderPath was not normalised: %v", d)
	}
	destID := d["id"].(string)

	post(t, s, "/api/routes/save",
		`{"route":{"shareId":"`+shareID+`","destinationId":"`+destID+`","enabled":true}}`, tok)

	out := post(t, s, "/api/destinations/remove", `{"id":"`+destID+`"}`, tok)
	if got, _ := out["error"].(string); got != "1 route(s) still use this destination" {
		t.Fatalf("delete refusal = %v", out)
	}
	if len(s.st.Destinations()) != 1 {
		t.Error("the destination was deleted anyway")
	}
	// Once the route is gone the destination may go.
	rt := s.st.Routes()[0]
	post(t, s, "/api/routes/remove", `{"id":"`+rt.ID+`"}`, tok)
	if out := post(t, s, "/api/destinations/remove", `{"id":"`+destID+`"}`, tok); out["ok"] != true {
		t.Errorf("delete after the route went: %v", out)
	}
}

func TestRouteSaveValidates(t *testing.T) {
	s, _, _ := newTestServer(t)
	tok := session(t, s)
	shareID, _ := addShare(t, s, tok, "scans-hr")
	destID := post(t, s, "/api/destinations/save",
		`{"destination":{"name":"Eingang","siteId":"s1","driveId":"d1"}}`, tok)["destination"].(map[string]any)["id"].(string)

	tests := []struct {
		name, body string
		wantErr    bool
	}{
		{"unknown share", `{"route":{"shareId":"nope","destinationId":"` + destID + `"}}`, true},
		{"unknown destination", `{"route":{"shareId":"` + shareID + `","destinationId":"nope"}}`, true},
		{"bad conflict", `{"route":{"shareId":"` + shareID + `","destinationId":"` + destID + `","conflict":"explode"}}`, true},
		{"ok", `{"route":{"shareId":"` + shareID + `","destinationId":"` + destID + `","subfolderTemplate":"/{yyyy}/{MM}/"}}`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := post(t, s, "/api/routes/save", tc.body, tok)
			if gotErr := out["error"] != nil; gotErr != tc.wantErr {
				t.Fatalf("error = %v, want error: %v", out["error"], tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			rt := out["route"].(map[string]any)
			if rt["conflict"] != string(model.ConflictRename) {
				t.Errorf("conflict default = %v", rt["conflict"])
			}
			if rt["subfolderTemplate"] != "{yyyy}/{MM}" {
				t.Errorf("template was not normalised: %v", rt["subfolderTemplate"])
			}
		})
	}
}

func TestQueueRetryAndRemove(t *testing.T) {
	s, _, eng := newTestServer(t)
	tok := session(t, s)
	shareID, _ := addShare(t, s, tok, "scans-hr")

	path := filepath.Join(s.cfg.ShareRoot, "scans-hr", "Rechnung.pdf")
	if err := os.WriteFile(path, []byte("scan"), 0o600); err != nil {
		t.Fatal(err)
	}
	it, err := s.st.PutItem(model.Item{ShareID: shareID, Path: path, Name: "Rechnung.pdf", Size: 4,
		Legs: []model.Leg{{RouteID: "rte-1", State: model.LegPending}}})
	if err != nil {
		t.Fatal(err)
	}

	post(t, s, "/api/queue/retry", `{"id":"`+it.ID+`"}`, tok)
	if len(eng.retried) != 1 || eng.retried[0] != it.ID {
		t.Errorf("retry did not reach the engine: %v", eng.retried)
	}

	out := post(t, s, "/api/queue/remove", `{"id":"`+it.ID+`"}`, tok)
	if out["ok"] != true {
		t.Fatalf("remove: %v", out)
	}
	if _, ok := s.st.Item(it.ID); ok {
		t.Error("the item survived the removal")
	}
	// Never unlinked: the bytes stay, out of the watcher's way.
	kept, _ := out["file"].(string)
	if _, err := os.Stat(kept); err != nil {
		t.Errorf("the file was not kept: %v", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("the file is still where the watcher would queue it again")
	}
}

// stateOf reads /api/state the way the page polls it.
func stateOf(t *testing.T, s *Server, tok string) stateResp {
	t.Helper()
	rw := call(s, http.MethodGet, "/api/state", "", tok, "")
	if rw.Code != http.StatusOK {
		t.Fatalf("state: HTTP %d", rw.Code)
	}
	var st stateResp
	if err := json.Unmarshal(rw.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestStateNeverCarriesAPassword(t *testing.T) {
	s, _, _ := newTestServer(t)
	tok := session(t, s)
	_, pw := addShare(t, s, tok, "scans-hr")
	_, pw2 := addShare(t, s, tok, "scans-buchhaltung")

	rw := call(s, http.MethodGet, "/api/state", "", tok, "")
	if rw.Code != http.StatusOK {
		t.Fatalf("HTTP %d", rw.Code)
	}
	body := rw.Body.String()
	for _, secret := range []string{pw, pw2, testPassword} {
		if strings.Contains(body, secret) {
			t.Fatalf("a password reached /api/state")
		}
	}
	var st stateResp
	if err := json.Unmarshal(rw.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Shares) != 2 {
		t.Fatalf("shares = %d", len(st.Shares))
	}
	info := st.ShareInfo[st.Shares[0].ID]
	if info.UNC != `\\m365scan\scans-buchhaltung` || !info.Watching {
		t.Errorf("shareInfo = %+v", info)
	}
	if info.LocalPath != filepath.Join(s.cfg.ShareRoot, "scans-buchhaltung") {
		t.Errorf("localPath = %q", info.LocalPath)
	}
	if !st.SMB.Running || st.SMB.Version != "4.21.4" || st.SMB.MinProtocol != "SMB2" {
		t.Errorf("smb = %+v", st.SMB)
	}
	if st.Tenant.AppID != "app-0001" || st.Tenant.Domain != "contoso.onmicrosoft.com" {
		t.Errorf("tenant = %+v", st.Tenant)
	}
	if st.Tenant.Connected {
		t.Error("a box without a Graph client is not connected")
	}
}

func TestStateStats(t *testing.T) {
	s, _, _ := newTestServer(t)
	tok := session(t, s)
	shareID, _ := addShare(t, s, tok, "scans-hr")
	destID := post(t, s, "/api/destinations/save",
		`{"destination":{"name":"Eingang","siteId":"s1","siteName":"Finanzen","driveId":"d1"}}`, tok)["destination"].(map[string]any)["id"].(string)
	route := post(t, s, "/api/routes/save",
		`{"route":{"shareId":"`+shareID+`","destinationId":"`+destID+`","enabled":true}}`, tok)["route"].(map[string]any)
	routeID := route["id"].(string)

	now := s.now()
	mustPut(t, s, model.Item{ShareID: shareID, Name: "a.pdf", Path: "/a.pdf", Size: 100, Discovered: now,
		Legs: []model.Leg{{RouteID: routeID, State: model.LegConfirmed, UploadedAt: now}}})
	mustPut(t, s, model.Item{ShareID: shareID, Name: "b.pdf", Path: "/b.pdf", Size: 200, Discovered: now,
		Legs: []model.Leg{{RouteID: routeID, State: model.LegRetrying}}})
	mustPut(t, s, model.Item{ShareID: shareID, Name: "c.pdf", Path: "/c.pdf", Size: 300, Discovered: now,
		Legs: []model.Leg{{RouteID: routeID, State: model.LegQuarantined}}})

	rw := call(s, http.MethodGet, "/api/state", "", tok, "")
	var st stateResp
	if err := json.Unmarshal(rw.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	want := statsInfo{UploadedToday: 1, Pending: 2, Failed: 1, TotalFiles: 3, BytesMonth: 100}
	got := st.Stats
	if got.UploadedToday != want.UploadedToday || got.Pending != want.Pending ||
		got.Failed != want.Failed || got.TotalFiles != want.TotalFiles || got.BytesMonth != want.BytesMonth {
		t.Errorf("stats = %+v, want %+v", got, want)
	}
	if len(got.PerShare) != 1 || got.PerShare[0].Label != "scans-hr" || got.PerShare[0].N != 3 {
		t.Errorf("perShare = %+v", got.PerShare)
	}
	if len(got.Recent) != 3 || got.Recent[0].Dest != "Finanzen · Eingang" || got.Recent[0].Device != "scan-scans-hr" {
		t.Errorf("recent = %+v", got.Recent)
	}
	ri := st.RouteInfo[routeID]
	if ri.FilesToday != 1 || ri.Pending != 1 || ri.LastSuccess.IsZero() {
		t.Errorf("routeInfo = %+v", ri)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	s, run, _ := newTestServer(t)
	tok := session(t, s)

	rw := call(s, http.MethodGet, "/api/settings", "", tok, "")
	var first struct{ Settings Settings }
	if err := json.Unmarshal(rw.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.Settings.SMBMinProtocol != "SMB2" || first.Settings.RetentionDays != 30 ||
		first.Settings.ServerName != "m365scan" || first.Settings.Workgroup != "WORKGROUP" {
		t.Fatalf("defaults = %+v", first.Settings)
	}

	if out := post(t, s, "/api/settings", `{"settings":{"smbMinProtocol":"SMB4","quarantineDir":"/var/q","retentionDays":7,"defaultRules":{"stabilityDelay":"5s"}}}`, tok); out["error"] == nil {
		t.Error("SMB4 should be refused")
	}
	if out := post(t, s, "/api/settings", `{"settings":{"smbMinProtocol":"SMB3","quarantineDir":"relative","retentionDays":7,"defaultRules":{"stabilityDelay":"5s"}}}`, tok); out["error"] == nil {
		t.Error("a relative quarantine path should be refused")
	}
	post(t, s, "/api/settings", `{"settings":{"smbMinProtocol":"SMB3","serverName":"scanbox","workgroup":"ACIDNET","quarantineDir":"/var/q","retentionDays":7,"defaultRules":{"stabilityDelay":"9s","deleteAfterUpload":true}}}`, tok)

	for _, want := range []string{
		"net conf setparm global server min protocol SMB3",
		"net conf setparm global netbios name scanbox",
		"net conf setparm global workgroup ACIDNET",
	} {
		if !run.ran(want) {
			t.Errorf("missing command %q in %v", want, run.calls)
		}
	}

	// Survives a restart, and a new share inherits the rules.
	reloaded := loadSettings(s.settingsPath, defaultSettings(s.cfg), s.log)
	if reloaded.SMBMinProtocol != "SMB3" || reloaded.RetentionDays != 7 || reloaded.DefaultRules.StabilityDelay.Std().String() != "9s" ||
		reloaded.ServerName != "scanbox" || reloaded.Workgroup != "ACIDNET" {
		t.Fatalf("reloaded = %+v", reloaded)
	}
	id, _ := addShare(t, s, tok, "scans-hr")
	sh, _ := s.st.Share(id)
	if sh.Rules.StabilityDelay.Std().String() != "9s" || !sh.Rules.DeleteAfterUpload {
		t.Errorf("the new share did not inherit the default rules: %+v", sh.Rules)
	}
	// The UNC follows the name Samba now answers to.
	if unc := stateOf(t, s, tok).ShareInfo[id].UNC; unc != `\\scanbox\scans-hr` {
		t.Errorf("unc = %q", unc)
	}
}

func TestSettingsRejectBadServerNames(t *testing.T) {
	s, run, _ := newTestServer(t)
	tok := session(t, s)
	const tail = `,"quarantineDir":"/var/q","retentionDays":7}}`

	for _, tc := range []struct{ name, body string }{
		{"a dot", `{"settings":{"smbMinProtocol":"SMB3","serverName":"scan.box"` + tail},
		{"16 characters", `{"settings":{"smbMinProtocol":"SMB3","serverName":"abcdefghijklmnop"` + tail},
		{"a leading hyphen", `{"settings":{"smbMinProtocol":"SMB3","serverName":"-scanbox"` + tail},
		{"a space", `{"settings":{"smbMinProtocol":"SMB3","serverName":"scan box"` + tail},
		{"a semicolon in the workgroup", `{"settings":{"smbMinProtocol":"SMB3","workgroup":"WG;reboot"` + tail},
	} {
		if out := post(t, s, "/api/settings", tc.body, tok); out["error"] == nil {
			t.Errorf("%s should be refused: %v", tc.name, out)
		}
	}
	if run.ran("net conf setparm global") {
		t.Errorf("a refused name reached Samba: %v", run.calls)
	}
	// An empty field keeps what is set rather than clearing the box name.
	post(t, s, "/api/settings", `{"settings":{"smbMinProtocol":"SMB1","quarantineDir":"/var/q","retentionDays":7}}`, tok)
	if got := s.currentSettings(); got.ServerName != "m365scan" || got.Workgroup != "WORKGROUP" || got.SMBMinProtocol != "SMB1" {
		t.Errorf("settings = %+v", got)
	}
	if !run.ran("net conf setparm global server min protocol NT1") {
		t.Errorf("SMB1 did not reach Samba as NT1: %v", run.calls)
	}
}

func TestStateReportsTheRetrySchedule(t *testing.T) {
	s, _, _ := newTestServer(t)
	tok := session(t, s)

	got := stateOf(t, s, tok).Retry
	want := retryInfo{MaxAttempts: 8, BaseDelay: "2s", MaxDelay: "5m", Jitter: 0.2}
	if got != want {
		t.Errorf("retry = %+v, want %+v", got, want)
	}
}

func TestSharePointNeedsAGraphClient(t *testing.T) {
	s, _, _ := newTestServer(t)
	tok := session(t, s)
	for _, path := range []string{"/api/sp/sites?q=fin", "/api/sp/drives?site=s1", "/api/sp/children?drive=d1&path=x"} {
		rw := call(s, http.MethodGet, path, "", tok, "")
		var out map[string]any
		if err := json.Unmarshal(rw.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if out["error"] == nil {
			t.Errorf("%s: want an error when Microsoft 365 is not configured", path)
		}
	}
}

func mustPut(t *testing.T, s *Server, it model.Item) {
	t.Helper()
	if _, err := s.st.PutItem(it); err != nil {
		t.Fatal(err)
	}
}

// A template naming a token the box does not have used to reach SharePoint as a
// folder literally called "{device}".
func TestRouteSaveRefusesAnUnknownToken(t *testing.T) {
	s, _, _ := newTestServer(t)
	tok := session(t, s)
	sh, _ := addShare(t, s, tok, "scans-hr")
	dout := post(t, s, "/api/destinations/save",
		`{"destination":{"name":"Finanzen","siteId":"s1","driveId":"d1"}}`, tok)
	d := dout["destination"].(map[string]any)["id"].(string)
	out := post(t, s, "/api/routes/save",
		`{"route":{"shareId":"`+sh+`","destinationId":"`+d+`","enabled":true,"subfolderTemplate":"{yyyy}/{device}"}}`, tok)
	msg, _ := out["error"].(string)
	if msg == "" {
		t.Fatal("an unknown token should be refused")
	}
	if !strings.Contains(msg, "{device}") {
		t.Errorf("the message should name the token, got %q", msg)
	}
	if out := post(t, s, "/api/routes/save",
		`{"route":{"shareId":"`+sh+`","destinationId":"`+d+`","enabled":true,"subfolderTemplate":"{yyyy}/{MM}/{share}"}}`, tok); out["error"] != nil {
		t.Errorf("a valid template should be accepted, got %v", out["error"])
	}
}
