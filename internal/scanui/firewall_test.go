package scanui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const fwHeader = "#!/usr/sbin/nft -f\n" +
	"# Managed by m365-scan (admin UI -> Network access). Do not edit by hand.\n"

// fwServer is the ordinary server with the drop-in redirected into a temporary
// directory, so the tests never go near /etc.
func fwServer(t *testing.T) (*Server, *fakeRunner, string, string) {
	t.Helper()
	s, run, _ := newTestServer(t)
	s.nftDir = t.TempDir()
	return s, run, session(t, s), filepath.Join(s.nftDir, nftDropIn)
}

// fwCall drives a request from a chosen address, which is what the lockout
// guard decides on.
func fwCall(t *testing.T, s *Server, method, body, tok, remote string) map[string]any {
	t.Helper()
	r := httptest.NewRequest(method, "/api/firewall", strings.NewReader(body))
	r.RemoteAddr = remote
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	r.Header.Set("X-CSRF", tok)
	rw := httptest.NewRecorder()
	s.Handler().ServeHTTP(rw, r)
	if rw.Code != http.StatusOK {
		t.Fatalf("%s /api/firewall: HTTP %d: %s", method, rw.Code, rw.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s /api/firewall: %v: %s", method, err, rw.Body.String())
	}
	return out
}

func TestFirewallRender(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []FWEntry
		want    string
	}{
		{"nothing allowed", nil, fwHeader},
		{
			"a mixed list",
			[]FWEntry{
				{Tier: "copier", Label: "Copiers", CIDR: "192.168.31.0/24"},
				{Tier: "admin", Label: "Office v6", CIDR: "2001:db8:1::/48"},
				{Tier: "admin", Label: "Office", CIDR: "192.168.30.0/24"},
			},
			fwHeader +
				"add rule inet base_filter input ip  saddr 192.168.30.0/24 tcp dport { 22, 8444 } accept\n" +
				"add rule inet base_filter input ip6 saddr 2001:db8:1::/48 tcp dport { 22, 8444 } accept\n" +
				"add rule inet base_filter input ip  saddr 192.168.31.0/24 tcp dport { 139, 445 } accept\n" +
				"add rule inet base_filter input ip  saddr 192.168.31.0/24 udp dport { 137, 138, 5353 } accept\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := renderFirewall(tc.entries); got != tc.want {
				t.Errorf("rendered\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
}

// The file has to come out the same however the page ordered the list, or every
// save churns a file that nobody changed.
func TestFirewallRenderIsStable(t *testing.T) {
	a := []FWEntry{{Tier: "admin", CIDR: "10.0.0.0/8"}, {Tier: "copier", CIDR: "10.1.0.0/16"}}
	b := []FWEntry{a[1], a[0]}
	if renderFirewall(a) != renderFirewall(b) {
		t.Errorf("the order of the list changed the file:\n%s\n%s", renderFirewall(a), renderFirewall(b))
	}
}

func TestFirewallSaveNormalisesAddresses(t *testing.T) {
	for _, tc := range []struct{ name, given, want string }{
		{"host bits are masked", "192.168.1.44/24", "192.168.1.0/24"},
		{"a bare v4 address is that host", "192.168.1.44", "192.168.1.44/32"},
		{"a bare v6 address is that host", "2001:db8::5", "2001:db8::5/128"},
		{"a v6 prefix keeps its length", "2001:db8:1::/48", "2001:db8:1::/48"},
		{"surrounding spaces are ignored", "  10.0.0.0/8  ", "10.0.0.0/8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, tok, dropIn := fwServer(t)
			out := fwCall(t, s, http.MethodPost,
				`{"entries":[{"tier":"admin","label":"Office","cidr":"`+tc.given+`"}]}`, tok, "203.0.113.9:4000")
			if e, ok := out["error"]; ok {
				t.Fatalf("save %q: %v", tc.given, e)
			}
			got := s.currentFirewall()
			if len(got) != 1 || got[0].CIDR != tc.want {
				t.Fatalf("stored %+v, want %s", got, tc.want)
			}
			if got[0].ID == "" || got[0].AddedAt == "" {
				t.Errorf("the entry was saved without an id or a date: %+v", got[0])
			}
			raw, err := os.ReadFile(dropIn)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), "saddr "+tc.want+" ") {
				t.Errorf("drop-in does not carry %s:\n%s", tc.want, raw)
			}
		})
	}
}

func TestFirewallSaveRefusesBadLists(t *testing.T) {
	long := strings.Repeat("a", 41)
	many := make([]string, 0, 33)
	for i := range 33 {
		many = append(many, fmt.Sprintf(`{"tier":"copier","label":"n","cidr":"10.%d.0.0/16"}`, i))
	}
	for _, tc := range []struct{ name, body, want string }{
		{"an unknown tier", `{"entries":[{"tier":"guest","label":"x","cidr":"10.0.0.0/8"}]}`, "administration"},
		{"not an address at all", `{"entries":[{"tier":"admin","label":"x","cidr":"the office"}]}`, "is not a network"},
		{"no name", `{"entries":[{"tier":"admin","label":"  ","cidr":"10.0.0.0/8"}]}`, "a name"},
		{"a name that is too long", `{"entries":[{"tier":"admin","label":"` + long + `","cidr":"10.0.0.0/8"}]}`, "too long"},
		{
			"a prefix inside another one",
			`{"entries":[{"tier":"admin","label":"Office","cidr":"10.0.0.0/8"},{"tier":"admin","label":"Floor 2","cidr":"10.1.0.0/16"}]}`,
			"already covered by Office (10.0.0.0/8)",
		},
		{
			"a prefix swallowing another one",
			`{"entries":[{"tier":"admin","label":"Floor 2","cidr":"10.1.0.0/16"},{"tier":"admin","label":"Office","cidr":"10.0.0.0/8"}]}`,
			"already covered by Office (10.0.0.0/8)",
		},
		{
			"the same network twice",
			`{"entries":[{"tier":"admin","label":"Office","cidr":"10.0.0.0/8"},{"tier":"admin","label":"Again","cidr":"10.0.0.0/8"}]}`,
			"already covered",
		},
		{"more than 32 in a tier", `{"entries":[` + strings.Join(many, ",") + `]}`, "at most 32 networks"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, run, tok, dropIn := fwServer(t)
			out := fwCall(t, s, http.MethodPost, tc.body, tok, "203.0.113.9:4000")
			msg, _ := out["error"].(string)
			if !strings.Contains(msg, tc.want) {
				t.Fatalf("error = %q, want it to mention %q", msg, tc.want)
			}
			if run.ran("nft") {
				t.Errorf("a refused list still reached nft: %v", run.calls)
			}
			if _, err := os.Stat(dropIn); err == nil {
				t.Error("a refused list still wrote the drop-in")
			}
		})
	}
	// The same prefix in two tiers is not a duplicate: one network may be
	// allowed to administer the box and to scan to it.
	s, _, tok, _ := fwServer(t)
	out := fwCall(t, s, http.MethodPost,
		`{"entries":[{"tier":"admin","label":"Office","cidr":"10.0.0.0/8"},{"tier":"copier","label":"Office","cidr":"10.0.0.0/8"}]}`,
		tok, "203.0.113.9:4000")
	if e, ok := out["error"]; ok {
		t.Errorf("the same network in both tiers should be allowed: %v", e)
	}
}

func TestFirewallRefusesToCutOffTheOperator(t *testing.T) {
	const saved = `{"entries":[{"tier":"admin","label":"Office","cidr":"192.168.30.0/24"}]}`
	const without = `{"entries":[{"tier":"admin","label":"Elsewhere","cidr":"10.0.0.0/8"}]}`

	// From the office network itself, dropping the entry that carries the
	// request is a lockout and has to be refused.
	s, _, tok, _ := fwServer(t)
	fwCall(t, s, http.MethodPost, saved, tok, "192.168.30.55:5000")
	out := fwCall(t, s, http.MethodPost, without, tok, "192.168.30.55:5000")
	msg, _ := out["error"].(string)
	if !strings.Contains(msg, "Office (192.168.30.0/24)") || !strings.Contains(msg, "192.168.30.55") {
		t.Errorf("error = %q, want it to name the entry and the operator's address", msg)
	}
	if got := s.currentFirewall(); len(got) != 1 || got[0].CIDR != "192.168.30.0/24" {
		t.Errorf("the refused save changed the list: %+v", got)
	}

	// Over the tailnet there is always a way back in, so the same change goes
	// through.
	s2, _, tok2, _ := fwServer(t)
	fwCall(t, s2, http.MethodPost, saved, tok2, "100.101.102.103:5000")
	if out := fwCall(t, s2, http.MethodPost, without, tok2, "100.101.102.103:5000"); out["error"] != nil {
		t.Errorf("over the tailnet: %v", out["error"])
	}
	if got := s2.currentFirewall(); len(got) != 1 || got[0].CIDR != "10.0.0.0/8" {
		t.Errorf("stored %+v, want the new list", got)
	}
}

func TestFirewallKeepsTheDropInWhenNftRefuses(t *testing.T) {
	s, run, tok, dropIn := fwServer(t)
	const before = fwHeader + "add rule inet base_filter input ip  saddr 10.0.0.0/8 tcp dport { 22, 8444 } accept\n"
	if err := os.WriteFile(dropIn, []byte(before), 0o644); err != nil {
		t.Fatal(err)
	}
	run.failPrefix = "nft -c"

	out := fwCall(t, s, http.MethodPost,
		`{"entries":[{"tier":"admin","label":"Office","cidr":"192.168.30.0/24"}]}`, tok, "203.0.113.9:4000")
	msg, _ := out["error"].(string)
	if !strings.Contains(msg, "refused") || !strings.Contains(msg, "boom") {
		t.Errorf("error = %q, want the refusal and what nft said", msg)
	}
	raw, err := os.ReadFile(dropIn)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != before {
		t.Errorf("the drop-in was changed:\n%s", raw)
	}
	if _, err := os.Stat(filepath.Join(s.nftDir, nftTempFile)); err == nil {
		t.Error("the temporary file was left behind")
	}
	if run.ran("nft -f") {
		t.Errorf("a refused file was still loaded: %v", run.calls)
	}
	if len(s.currentFirewall()) != 0 {
		t.Errorf("a refused file was still saved: %+v", s.currentFirewall())
	}
	if _, err := os.Stat(s.firewallPath); err == nil {
		t.Error("a refused file still wrote firewall.json")
	}
}

func TestFirewallRoundTripsThroughTheFile(t *testing.T) {
	s, run, tok, _ := fwServer(t)
	const body = `{"entries":[` +
		`{"tier":"admin","label":"Office","cidr":"192.168.30.0/24"},` +
		`{"tier":"copier","label":"Copiers","cidr":"192.168.31.0/24"}]}`

	out := fwCall(t, s, http.MethodPost, body, tok, "192.168.30.55:5000")
	if e, ok := out["error"]; ok {
		t.Fatal(e)
	}
	// The check runs before the load, or a bad file would take the ruleset down.
	if !run.ran("nft -c -f ") || !run.ran("nft -f "+nftConfPath) {
		t.Errorf("nft calls = %v", run.calls)
	}

	fw := out["firewall"].(map[string]any)
	you := fw["you"].(map[string]any)
	if you["ip"] != "192.168.30.55" || you["viaTailnet"] != false || you["coveredBy"] == "" {
		t.Errorf("you = %+v, want the caller covered by the office entry", you)
	}

	saved := mustLoadFirewall(t, s.firewallPath)
	if len(saved) != 2 || saved[0].CIDR != "192.168.30.0/24" || saved[1].Tier != "copier" {
		t.Fatalf("firewall.json holds %+v", saved)
	}
	if saved[0].ID == "" {
		t.Error("the saved entry has no id")
	}

	// A GET answers with the same shape, and from the tailnet says so.
	got := fwCall(t, s, http.MethodGet, "", tok, "100.101.102.103:5000")
	gotFW := got["firewall"].(map[string]any)
	if len(gotFW["entries"].([]any)) != 2 {
		t.Errorf("GET returned %+v", gotFW["entries"])
	}
	if gotFW["you"].(map[string]any)["viaTailnet"] != true {
		t.Errorf("you = %+v, want viaTailnet", gotFW["you"])
	}
}

// The reload is the step that can leave a box unreachable: if it fails, the
// drop-in that was there before has to come back and be loaded again.
func TestFirewallPutsTheDropInBackWhenTheReloadFails(t *testing.T) {
	s, run, tok, dropIn := fwServer(t)
	const before = fwHeader + "add rule inet base_filter input ip  saddr 10.0.0.0/8 tcp dport { 22, 8444 } accept\n"
	if err := os.WriteFile(dropIn, []byte(before), 0o644); err != nil {
		t.Fatal(err)
	}
	// Only the whole-conf reload fails; the check on the temporary file passes.
	run.failPrefix = "nft -f " + nftConfPath

	out := fwCall(t, s, http.MethodPost,
		`{"entries":[{"tier":"admin","label":"Office","cidr":"192.168.30.0/24"}]}`, tok, "203.0.113.9:4000")
	msg, _ := out["error"].(string)
	if !strings.Contains(msg, "reloaded") || !strings.Contains(msg, "boom") {
		t.Errorf("error = %q, want the reload failure and what nft said", msg)
	}
	raw, err := os.ReadFile(dropIn)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != before {
		t.Errorf("the drop-in was not put back:\n%s", raw)
	}
	var reloads int
	for _, c := range run.calls {
		if c == "nft -f "+nftConfPath {
			reloads++
		}
	}
	if reloads != 2 {
		t.Errorf("the restored drop-in was not loaded again: %v", run.calls)
	}
	if len(s.currentFirewall()) != 0 {
		t.Errorf("a list that never loaded was still kept: %+v", s.currentFirewall())
	}
	if _, err := os.Stat(s.firewallPath); err == nil {
		t.Error("a list that never loaded still wrote firewall.json")
	}
}

// fwConfirm drives the confirm route, which is the only one that takes a body
// other than the list.
func fwConfirm(t *testing.T, s *Server, body, tok, remote string) map[string]any {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/firewall/confirm", strings.NewReader(body))
	r.RemoteAddr = remote
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	r.Header.Set("X-CSRF", tok)
	rw := httptest.NewRecorder()
	s.Handler().ServeHTTP(rw, r)
	if rw.Code != http.StatusOK {
		t.Fatalf("confirm: HTTP %d: %s", rw.Code, rw.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rw.Body.Bytes(), &out); err != nil {
		t.Fatalf("confirm: %v: %s", err, rw.Body.String())
	}
	return out
}

const fwOffice = `{"entries":[{"tier":"admin","label":"Office","cidr":"192.168.30.0/24"}],"revertAfter":0}`
const fwArmed = `{"entries":[{"tier":"admin","label":"Office","cidr":"192.168.30.0/24"},` +
	`{"tier":"copier","label":"Copiers","cidr":"192.168.31.0/24"}],"revertAfter":300}`

// An armed change is in the kernel but not in the file, so a crash inside the
// window comes back on the list somebody actually confirmed.
func TestFirewallArmedChangeIsNotSavedUntilConfirmed(t *testing.T) {
	s, _, tok, dropIn := fwServer(t)
	if out := fwCall(t, s, http.MethodPost, fwOffice, tok, "100.64.0.9:5000"); out["error"] != nil {
		t.Fatal(out["error"])
	}

	out := fwCall(t, s, http.MethodPost, fwArmed, tok, "100.64.0.9:5000")
	if out["error"] != nil {
		t.Fatal(out["error"])
	}
	if _, ok := out["firewall"].(map[string]any)["armed"]; !ok {
		t.Fatalf("no countdown reported: %+v", out["firewall"])
	}
	raw, err := os.ReadFile(dropIn)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "192.168.31.0/24") {
		t.Errorf("the new rules never reached the drop-in:\n%s", raw)
	}
	if saved := mustLoadFirewall(t, s.firewallPath); len(saved) != 1 {
		t.Errorf("firewall.json holds %d entries, want the 1 that was confirmed", len(saved))
	}

	fwConfirm(t, s, `{}`, tok, "100.64.0.9:5000")
	if saved := mustLoadFirewall(t, s.firewallPath); len(saved) != 2 {
		t.Errorf("after confirming, firewall.json holds %+v", saved)
	}
}

// Nobody confirms: the previous list goes back into the kernel by itself.
func TestFirewallRevertsWhenNobodyConfirms(t *testing.T) {
	s, _, tok, dropIn := fwServer(t)
	fwCall(t, s, http.MethodPost, fwOffice, tok, "100.64.0.9:5000")
	fwCall(t, s, http.MethodPost, fwArmed, tok, "100.64.0.9:5000")

	fireRevert(s) // what the timer calls

	raw, err := os.ReadFile(dropIn)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "192.168.31.0/24") {
		t.Errorf("the unconfirmed rule is still loaded:\n%s", raw)
	}
	if got := s.currentFirewall(); len(got) != 1 || got[0].CIDR != "192.168.30.0/24" {
		t.Errorf("after the revert the box holds %+v", got)
	}
	// The timer is spent, so a late confirm must not put anything back.
	fwConfirm(t, s, `{}`, tok, "100.64.0.9:5000")
	if got := s.currentFirewall(); len(got) != 1 {
		t.Errorf("a late confirm changed the list: %+v", got)
	}
}

// Undo is the same path the timer takes, asked for early.
func TestFirewallUndoRestoresThePreviousList(t *testing.T) {
	s, _, tok, _ := fwServer(t)
	fwCall(t, s, http.MethodPost, fwOffice, tok, "100.64.0.9:5000")
	fwCall(t, s, http.MethodPost, fwArmed, tok, "100.64.0.9:5000")

	out := fwConfirm(t, s, `{"undo":true}`, tok, "100.64.0.9:5000")
	if n := len(out["firewall"].(map[string]any)["entries"].([]any)); n != 1 {
		t.Errorf("undo answered with %d entries, want 1", n)
	}
	if got := s.currentFirewall(); len(got) != 1 || got[0].CIDR != "192.168.30.0/24" {
		t.Errorf("after undo the box holds %+v", got)
	}
}

// A second armed change keeps falling back to the last CONFIRMED list, not to
// the one that is itself still waiting.
func TestFirewallSecondArmedChangeKeepsTheConfirmedFallback(t *testing.T) {
	s, _, tok, _ := fwServer(t)
	fwCall(t, s, http.MethodPost, fwOffice, tok, "100.64.0.9:5000")
	fwCall(t, s, http.MethodPost, fwArmed, tok, "100.64.0.9:5000")
	fwCall(t, s, http.MethodPost, `{"entries":[{"tier":"admin","label":"Elsewhere","cidr":"10.9.0.0/16"}],"revertAfter":300}`, tok, "100.64.0.9:5000")

	fireRevert(s)
	if got := s.currentFirewall(); len(got) != 1 || got[0].CIDR != "192.168.30.0/24" {
		t.Errorf("the revert landed on %+v, want the confirmed office list", got)
	}
}

// Saving without a window supersedes a pending one, or its timer would later
// restore a list two changes old.
func TestFirewallUnarmedSaveCancelsAPendingRevert(t *testing.T) {
	s, _, tok, _ := fwServer(t)
	fwCall(t, s, http.MethodPost, fwOffice, tok, "100.64.0.9:5000")
	fwCall(t, s, http.MethodPost, fwArmed, tok, "100.64.0.9:5000")
	fwCall(t, s, http.MethodPost, `{"entries":[{"tier":"admin","label":"Final","cidr":"10.9.0.0/16"}],"revertAfter":0}`, tok, "100.64.0.9:5000")

	fireRevert(s) // must be a no-op now
	if got := s.currentFirewall(); len(got) != 1 || got[0].CIDR != "10.9.0.0/16" {
		t.Errorf("a stale timer undid a confirmed save: %+v", got)
	}
}

func mustLoadFirewall(t *testing.T, path string) []FWEntry {
	t.Helper()
	got, err := loadFirewall(path)
	if err != nil {
		t.Fatalf("loadFirewall(%s): %v", path, err)
	}
	return got
}

// Two saves at once used to share one temp path and one unlocked
// read-modify-write, leaving the kernel holding one list and firewall.json the
// other. The wizard reaches this from a single browser: step 2 posts the whole
// list on every checkbox, add and remove.
func TestConcurrentSavesAgreeWithTheDropIn(t *testing.T) {
	s, _, tok, dropIn := fwServer(t)
	body := func(cidr string) string {
		return `{"entries":[{"tier":"admin","label":"` + cidr + `","cidr":"` + cidr + `"}]}`
	}
	var wg sync.WaitGroup
	for _, cidr := range []string{"10.1.0.0/16", "10.2.0.0/16"} {
		wg.Add(1)
		go func(c string) {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodPost, "/api/firewall", strings.NewReader(body(c)))
			r.RemoteAddr = "100.64.0.9:5000"
			r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
			r.Header.Set("X-CSRF", tok)
			s.Handler().ServeHTTP(httptest.NewRecorder(), r)
		}(cidr)
	}
	wg.Wait()

	raw, err := os.ReadFile(dropIn)
	if err != nil {
		t.Fatal(err)
	}
	saved := mustLoadFirewall(t, s.firewallPath)
	if len(saved) != 1 {
		t.Fatalf("firewall.json holds %+v", saved)
	}
	if !strings.Contains(string(raw), saved[0].CIDR) {
		t.Errorf("the drop-in and firewall.json disagree:\nfile says %s\ndrop-in:\n%s", saved[0].CIDR, raw)
	}
	if left, _ := os.ReadDir(s.nftDir); len(left) != 1 {
		t.Errorf("a temporary file was left behind: %v", left)
	}
}

// An unreadable file must not be mistaken for "no networks": the startup
// re-apply would write that emptiness into the kernel and delete the rules it
// exists to restore.
func TestUnreadableFileLeavesTheKernelAlone(t *testing.T) {
	s, run, _, dropIn := fwServer(t)
	if err := os.WriteFile(dropIn, []byte("# the good rules\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(s.firewallPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.firewallPath, []byte("{not json"), 0o640); err != nil {
		t.Fatal(err)
	}

	s.reapplyFirewall()

	raw, err := os.ReadFile(dropIn)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "# the good rules\n" {
		t.Errorf("the drop-in was rewritten from an unreadable file:\n%s", raw)
	}
	if run.ran("nft -f") {
		t.Errorf("the ruleset was reloaded anyway: %v", run.calls)
	}
}

// fireRevert runs the revert the way its timer would, carrying the generation
// that is current now.
func fireRevert(s *Server) {
	s.mu.Lock()
	gen := s.fwGen
	s.mu.Unlock()
	s.revertFirewall(gen)
}

// A failed undo used to answer with an error AND throw the countdown away, so
// the box kept rules nobody had confirmed with nothing left to restore them.
func TestFailedUndoKeepsTheWindowArmed(t *testing.T) {
	s, run, tok, _ := fwServer(t)
	fwCall(t, s, http.MethodPost, fwOffice, tok, "100.64.0.9:5000")
	fwCall(t, s, http.MethodPost, fwArmed, tok, "100.64.0.9:5000")

	run.failPrefix = "nft -c -f " // the restore cannot be validated
	out := fwConfirm(t, s, `{"undo":true}`, tok, "100.64.0.9:5000")
	if out["error"] == nil {
		t.Fatal("a failed undo answered as if it had worked")
	}
	if _, armed := s.peek(); !armed {
		t.Fatal("the window was thrown away by a failed undo, so nothing can restore the old list")
	}

	// With the fault cleared the timer still has something to put back.
	run.failPrefix = ""
	fireRevert(s)
	if got := s.currentFirewall(); len(got) != 1 || got[0].CIDR != "192.168.30.0/24" {
		t.Errorf("after the revert the box holds %+v", got)
	}
}

// A timer that fires just as a newer change arms must not take the newer list
// down with the old one.
func TestSupersededTimerDoesNotRevert(t *testing.T) {
	s, _, tok, _ := fwServer(t)
	fwCall(t, s, http.MethodPost, fwOffice, tok, "100.64.0.9:5000")
	fwCall(t, s, http.MethodPost, fwArmed, tok, "100.64.0.9:5000")

	s.mu.Lock()
	stale := s.fwGen // the generation of the window armed above
	s.mu.Unlock()

	// A second armed change supersedes it.
	fwCall(t, s, http.MethodPost, `{"entries":[{"tier":"admin","label":"Newer","cidr":"10.9.0.0/16"}],"revertAfter":300}`, tok, "100.64.0.9:5000")

	s.revertFirewall(stale) // the old timer finally fires

	if got := s.currentFirewall(); len(got) != 1 || got[0].CIDR != "10.9.0.0/16" {
		t.Errorf("a superseded timer reverted the newer list: %+v", got)
	}
}
