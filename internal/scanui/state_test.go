package scanui

import (
	"testing"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/internal/model"
	"github.com/AcidDemon/m365-cloud-scan/pkg/graph"
)

// The Graph reference always exists; only the client inside it appears at
// onboarding. Reporting the reference as a connection made a box that had never
// seen a tenant claim it was connected.
func TestTenantPanelIsNotConnectedUntilAClientExists(t *testing.T) {
	s, _, _ := newTestServer(t)
	ti := s.tenantInfo(nil)
	if ti.Connected {
		t.Error("a box with no tenant must not report a connection")
	}
	if ti.Consent {
		t.Error("a box with no tenant must not report consent")
	}
	s.gc.Set(graph.NewClient(nil, "https://example.invalid", nil))
	if ti2 := s.tenantInfo(nil); !ti2.Connected {
		t.Error("once a client exists the panel should report the connection")
	}
}

// The sparkline reads Daily straight out, so a record that lands in the wrong
// bucket is a chart that lies. The last assertion ties the array back to the
// scalar the KPI shows, which is what keeps the two from drifting apart.
func TestStatsDailyBuckets(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.Local)
	hist := []model.Upload{
		{Status: "uploaded", At: now, Size: 100},
		{Status: "uploaded", At: now.AddDate(0, 0, -1), Size: 200},
		{Status: "uploaded", At: now.AddDate(0, 0, -13), Size: 400},
		{Status: "uploaded", At: now.AddDate(0, 0, -14), Size: 800}, // older than the window
		{Status: "quarantined", At: now, Size: 1600},                // never uploaded
	}

	st := stats(nil, nil, nil, nil, hist, now)

	if len(st.Daily) != histDays {
		t.Fatalf("Daily has %d entries, want %d", len(st.Daily), histDays)
	}
	for i, want := range map[int]int{histDays - 1: 1, histDays - 2: 1, 0: 1} {
		if st.Daily[i] != want {
			t.Errorf("Daily[%d] = %d, want %d", i, st.Daily[i], want)
		}
	}
	sum := 0
	for _, n := range st.Daily {
		sum += n
	}
	if sum != 3 {
		t.Errorf("Daily sums to %d, want 3 (the 15-day-old and the quarantined record do not count)", sum)
	}
	if st.Daily[histDays-1] != st.UploadedToday {
		t.Errorf("Daily[today] = %d but UploadedToday = %d", st.Daily[histDays-1], st.UploadedToday)
	}
	if len(st.DailyBytes) != histDays {
		t.Fatalf("DailyBytes has %d entries, want %d", len(st.DailyBytes), histDays)
	}
	for i, want := range map[int]int64{histDays - 1: 100, histDays - 2: 200, 0: 400} {
		if st.DailyBytes[i] != want {
			t.Errorf("DailyBytes[%d] = %d, want %d", i, st.DailyBytes[i], want)
		}
	}
}

// A delivered scan deletes its own file and its own queue entry, so the queue is
// empty precisely when a route has been working. Reading the per-route counters
// out of the queue alone therefore reported "0 today, last success never" on the
// routes that had just succeeded, which is the opposite of the truth.
func TestRouteInfoCountsDeliveredUploadsFromHistory(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.Local)
	routes := []model.Route{{ID: "r1"}, {ID: "r2"}}
	hist := []model.Upload{
		{Status: "uploaded", At: now, Size: 100, Targets: []model.UploadLeg{{RouteID: "r1"}}},
		{Status: "uploaded", At: now.Add(-2 * time.Hour), Size: 250, Targets: []model.UploadLeg{{RouteID: "r1"}}},
		{Status: "uploaded", At: now.AddDate(0, 0, -1), Size: 700, Targets: []model.UploadLeg{{RouteID: "r1"}}},
		{Status: "quarantined", At: now, Size: 900, Targets: []model.UploadLeg{{RouteID: "r1"}}},
	}

	ri := routeInfoOf(routes, nil, hist, now)

	r1 := ri["r1"]
	if r1.FilesToday != 2 {
		t.Errorf("FilesToday = %d, want 2 (yesterday's and the quarantined record do not count)", r1.FilesToday)
	}
	if r1.BytesToday != 350 {
		t.Errorf("BytesToday = %d, want 350", r1.BytesToday)
	}
	if !r1.LastSuccess.Equal(now) {
		t.Errorf("LastSuccess = %v, want %v", r1.LastSuccess, now)
	}
	if r2 := ri["r2"]; r2.FilesToday != 0 || !r2.LastSuccess.IsZero() {
		t.Errorf("a route with no history reported %+v", r2)
	}
}

// The queue and the history describe different halves of the same day: whatever
// is still in flight, and whatever already landed. Both have to be counted or a
// box that is mid-upload shows a number that drops when the upload succeeds.
func TestRouteInfoAddsQueueAndHistory(t *testing.T) {
	now := time.Date(2026, 8, 21, 10, 0, 0, 0, time.Local)
	routes := []model.Route{{ID: "r1"}}
	items := []model.Item{{
		ID: "i1", Size: 40,
		Legs: []model.Leg{
			{RouteID: "r1", State: model.LegConfirmed, UploadedAt: now.Add(-time.Minute)},
		},
	}, {
		ID: "i2", Size: 50,
		Legs: []model.Leg{{RouteID: "r1", State: model.LegPending}},
	}}
	hist := []model.Upload{
		{Status: "uploaded", At: now, Size: 60, Targets: []model.UploadLeg{{RouteID: "r1"}}},
	}

	ri := routeInfoOf(routes, items, hist, now)["r1"]

	if ri.FilesToday != 2 {
		t.Errorf("FilesToday = %d, want 2 (one still queued, one already in history)", ri.FilesToday)
	}
	if ri.BytesToday != 100 {
		t.Errorf("BytesToday = %d, want 100", ri.BytesToday)
	}
	if ri.Pending != 1 {
		t.Errorf("Pending = %d, want 1", ri.Pending)
	}
	if !ri.LastSuccess.Equal(now) {
		t.Errorf("LastSuccess = %v, want the history record at %v", ri.LastSuccess, now)
	}
}

// A quarantined scan is both a live item and a history line on purpose. Before
// this it was also two rows in the activity table, with two differently
// formatted destinations, and two entries in every total.
func TestQuarantinedScanIsCountedOnce(t *testing.T) {
	now := time.Now()
	shares := []model.Share{{ID: "shr1", Name: "scaninbox"}}
	dests := []model.Destination{{ID: "d1", Name: "Documents", SiteName: "Mark 8 Project Team"}}
	routes := []model.Route{{ID: "r1", ShareID: "shr1", DestinationID: "d1"}}
	items := []model.Item{{
		ID: "itm1", ShareID: "shr1", Name: "testfile.pdf", Discovered: now,
		Quarantined: true,
		Legs:        []model.Leg{{RouteID: "r1", State: model.LegQuarantined, LastError: "the file is empty, so there is nothing to upload"}},
	}}
	hist := []model.Upload{{
		ID: "up1", ItemID: "itm1", At: now, Share: "scaninbox", File: "testfile.pdf",
		Status: "quarantined", Targets: []model.UploadLeg{{RouteID: "r1", Destination: dests[0].Label()}},
	}}

	st := stats(shares, dests, routes, items, hist, now)

	if len(st.Recent) != 1 {
		t.Fatalf("the activity table has %d rows for one scan: %+v", len(st.Recent), st.Recent)
	}
	if st.TotalFiles != 1 {
		t.Errorf("TotalFiles = %d, want 1", st.TotalFiles)
	}
	if n := st.PerShare[0].N; n != 1 {
		t.Errorf("the share bar counts %d, want 1", n)
	}
	// Both sources have to name the destination the same way, or the same scan
	// reads differently depending on which one produced the row.
	if got := dests[0].Label(); got != "Mark 8 Project Team · Documents" {
		t.Errorf("Label() = %q", got)
	}
}

// Once the item is gone the history line is the only record, and it must show.
func TestHistoryShowsOnceTheItemIsGone(t *testing.T) {
	now := time.Now()
	shares := []model.Share{{ID: "shr1", Name: "scaninbox"}}
	hist := []model.Upload{{
		ID: "up1", ItemID: "itm1", At: now, Share: "scaninbox", File: "testfile.pdf", Status: "uploaded",
	}}

	st := stats(shares, nil, nil, nil, hist, now)

	if len(st.Recent) != 1 || st.TotalFiles != 1 {
		t.Fatalf("Recent=%d TotalFiles=%d, want 1 and 1", len(st.Recent), st.TotalFiles)
	}
}
