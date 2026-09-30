package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/internal/model"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestShareNameRules(t *testing.T) {
	for _, bad := range []string{"", "ab", "-scans", "scans-", "Scans", "scan folder", "scan_hr"} {
		if err := ValidShareName(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	for _, ok := range []string{"scans-hr", "mfp-eg-flur", "abc"} {
		if err := ValidShareName(ok); err != nil {
			t.Errorf("%q should be accepted: %v", ok, err)
		}
	}
}

func TestAddShareRejectsDuplicateName(t *testing.T) {
	s := open(t)
	if _, err := s.AddShare(model.Share{Name: "scans-hr"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddShare(model.Share{Name: "scans-hr"}); err == nil {
		t.Fatal("duplicate share name was accepted")
	}
}

func TestDeleteShareDropsItsRoutes(t *testing.T) {
	s := open(t)
	sh, _ := s.AddShare(model.Share{Name: "scans-hr"})
	d, _ := s.PutDestination(model.Destination{Name: "Personal"})
	if _, err := s.PutRoute(model.Route{ShareID: sh.ID, DestinationID: d.ID, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteShare(sh.ID); err != nil {
		t.Fatal(err)
	}
	if got := len(s.Routes()); got != 0 {
		t.Fatalf("routes left after share delete: %d", got)
	}
}

func TestDeleteDestinationRefusesWhileRouted(t *testing.T) {
	s := open(t)
	sh, _ := s.AddShare(model.Share{Name: "scans-hr"})
	d, _ := s.PutDestination(model.Destination{Name: "Personal"})
	s.PutRoute(model.Route{ShareID: sh.ID, DestinationID: d.ID, Enabled: true})
	if err := s.DeleteDestination(d.ID); err == nil {
		t.Fatal("deleting a routed destination should fail")
	}
}

func TestRoutesForShareSkipsDisabled(t *testing.T) {
	s := open(t)
	sh, _ := s.AddShare(model.Share{Name: "scans-hr"})
	d1, _ := s.PutDestination(model.Destination{Name: "a"})
	d2, _ := s.PutDestination(model.Destination{Name: "b"})
	s.PutRoute(model.Route{ShareID: sh.ID, DestinationID: d1.ID, Enabled: true})
	s.PutRoute(model.Route{ShareID: sh.ID, DestinationID: d2.ID, Enabled: false})
	if got := len(s.RoutesForShare(sh.ID)); got != 1 {
		t.Fatalf("want 1 enabled route, got %d", got)
	}
}

func TestReopenKeepsState(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "state.json")
	s1, _ := Open(p)
	s1.AddShare(model.Share{Name: "scans-hr", Rules: model.ShareRules{StabilityDelay: model.Duration(5 * time.Second)}})
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	got := s2.Shares()
	if len(got) != 1 || got[0].Rules.StabilityDelay.Std() != 5*time.Second {
		t.Fatalf("state did not survive a reopen: %+v", got)
	}
}

func TestItemDoneOnlyWhenEveryLegConfirmed(t *testing.T) {
	it := model.Item{Legs: []model.Leg{{State: model.LegConfirmed}, {State: model.LegPending}}}
	if it.Done() {
		t.Fatal("item with a pending leg must not be Done: the file would be deleted early")
	}
	it.Legs[1].State = model.LegConfirmed
	if !it.Done() {
		t.Fatal("item with every leg confirmed should be Done")
	}
	if (model.Item{}).Done() {
		t.Fatal("an item with no legs must not be Done")
	}
}

func TestRenderTemplate(t *testing.T) {
	at := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	if got := model.RenderTemplate("{yyyy}/{MM}/{share}", at, "scans-hr"); got != "2026/08/scans-hr" {
		t.Fatalf("got %q", got)
	}
	if got := model.RenderTemplate("", at, "scans-hr"); got != "" {
		t.Fatalf("empty template should render empty, got %q", got)
	}
	if got := model.RenderTemplate("/{yyyy}//x/", at, "s"); got != "2026/x" {
		t.Fatalf("got %q", got)
	}
	// An unknown token survives so the mistake is visible in the preview.
	if got := model.RenderTemplate("{yyy}", at, "s"); got != "{yyy}" {
		t.Fatalf("got %q", got)
	}
}

func TestDestPathJoinsFolderAndTemplate(t *testing.T) {
	at := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	d := model.Destination{FolderPath: "Eingang/Scans"}
	r := model.Route{SubfolderTemplate: "{yyyy}/{MM}"}
	if got := model.DestPath(d, r, at, "scans-hr"); got != "Eingang/Scans/2026/08" {
		t.Fatalf("got %q", got)
	}
	if got := model.DestPath(model.Destination{}, model.Route{}, at, "s"); got != "" {
		t.Fatalf("library root should render empty, got %q", got)
	}
}

// A template that names a token the box does not have would otherwise reach
// SharePoint as a literal folder called "{device}".
func TestValidateTemplate(t *testing.T) {
	for _, ok := range []string{"", "{yyyy}/{MM}", "{yyyy}/{MM}/{dd}/{share}", "Eingang/{share}"} {
		if err := model.ValidateTemplate(ok); err != nil {
			t.Errorf("%q should be accepted: %v", ok, err)
		}
	}
	err := model.ValidateTemplate("{yyyy}/{device}")
	if err == nil {
		t.Fatal("an unknown token should be refused")
	}
	if !strings.Contains(err.Error(), "{device}") {
		t.Errorf("the message should name the offending token, got: %v", err)
	}
	if err := model.ValidateTemplate("{user}"); err == nil {
		t.Error("{user} was removed and should now be refused")
	}
}

// A delivered scan deletes its file and its queue entry, so without the history
// the dashboard would show no trace of the thing that just worked.
func TestUploadHistorySurvivesAndPrunes(t *testing.T) {
	s := open(t)
	if err := s.AppendUpload(model.Upload{
		Share: "scans-hr", File: "Rechnung.pdf", Size: 2048, Status: "uploaded",
		Targets: []model.UploadLeg{{Destination: "Finanzen", WebURL: "https://example.invalid/x"}},
	}, 0); err != nil {
		t.Fatal(err)
	}
	got := s.Uploads()
	if len(got) != 1 || got[0].ID == "" || got[0].At.IsZero() {
		t.Fatalf("want one stamped record, got %+v", got)
	}

	// Anything past the retention window goes on the next write.
	if err := s.AppendUpload(model.Upload{Share: "scans-hr", File: "old.pdf",
		At: time.Now().Add(-48 * time.Hour), Status: "uploaded"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, u := range s.Uploads() {
		if u.File == "old.pdf" {
			t.Error("a record older than the retention window should have been pruned")
		}
	}
	if len(s.Uploads()) != 1 {
		t.Fatalf("want the recent record kept, got %d", len(s.Uploads()))
	}
}
