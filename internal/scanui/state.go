package scanui

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/internal/model"
	"github.com/AcidDemon/m365-cloud-scan/pkg/graph"
)

// smbStatusTTL keeps /api/state from shelling out to systemctl, smbd and
// testparm on every poll of a page that refreshes every few seconds.
const smbStatusTTL = 10 * time.Second

// recentRows is how much of the activity list the dashboard shows.
const recentRows = 10

// histDays is the span of the dashboard sparkline. A box whose history
// retention is shorter than this simply has empty bars at the old end.
const histDays = 14

type stateResp struct {
	Shares       []model.Share        `json:"shares"`
	Destinations []model.Destination  `json:"destinations"`
	Routes       []model.Route        `json:"routes"`
	Items        []model.Item         `json:"items"`
	ShareInfo    map[string]shareInfo `json:"shareInfo"`
	RouteInfo    map[string]routeInfo `json:"routeInfo"`
	Tenant       tenantInfo           `json:"tenant"`
	Stats        statsInfo            `json:"stats"`
	SMB          smbInfo              `json:"smb"`
	Retry        retryInfo            `json:"retry"`
}

// retryInfo is the delivery schedule the daemon actually runs, so the page can
// show it rather than describe one of its own.
type retryInfo struct {
	MaxAttempts int     `json:"maxAttempts"`
	BaseDelay   string  `json:"baseDelay"`
	MaxDelay    string  `json:"maxDelay"`
	Jitter      float64 `json:"jitter"`
}

type shareInfo struct {
	UNC       string `json:"unc"`
	LocalPath string `json:"localPath"`
	Pending   int    `json:"pending"`
	Watching  bool   `json:"watching"`
}

type routeInfo struct {
	FilesToday  int       `json:"filesToday"`
	BytesToday  int64     `json:"bytesToday"`
	Pending     int       `json:"pending"`
	LastSuccess time.Time `json:"lastSuccess,omitzero"`
}

type tenantInfo struct {
	Name       string    `json:"name"`
	Domain     string    `json:"domain"`
	AppID      string    `json:"appId"`
	Consent    bool      `json:"consent"`
	CertExpiry time.Time `json:"certExpiry,omitzero"`
	Sites      []siteRef `json:"sites"`
	Connected  bool      `json:"connected"`
}

type siteRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type labelN struct {
	Label string `json:"label"`
	N     int    `json:"n"`
}

type recentRow struct {
	File   string    `json:"file"`
	Share  string    `json:"share"`
	Device string    `json:"device"`
	Dest   string    `json:"dest"`
	Status string    `json:"status"`
	At     time.Time `json:"at"`
}

type statsInfo struct {
	UploadedToday int      `json:"uploadedToday"`
	Pending       int      `json:"pending"`
	Failed        int      `json:"failed"`
	TotalFiles    int      `json:"totalFiles"`
	BytesMonth    int64    `json:"bytesMonth"`
	PerShare      []labelN `json:"perShare"`
	// Daily is one confirmed-upload count per day, oldest first. The last entry
	// is today and always equals UploadedToday.
	Daily []int `json:"daily"`
	// DailyBytes is the same window by volume rather than by file count.
	DailyBytes []int64     `json:"dailyBytes"`
	Recent     []recentRow `json:"recent"`
}

type smbInfo struct {
	Running     bool   `json:"running"`
	Version     string `json:"version"`
	MinProtocol string `json:"minProtocol"`
}

// handleState is the one read the page polls. Everything in it is derived from
// the store, and no share password is part of any record it returns.
func (s *Server) handleState(rw http.ResponseWriter, r *http.Request) {
	shares := s.st.Shares()
	dests := s.st.Destinations()
	routes := s.st.Routes()
	items := s.st.Items()
	now := s.now()

	writeJSON(rw, stateResp{
		Shares:       shares,
		Destinations: dests,
		Routes:       routes,
		Items:        items,
		ShareInfo:    s.shareInfo(shares, items),
		RouteInfo:    routeInfoOf(routes, items, s.st.Uploads(), now),
		Tenant:       s.tenantInfo(dests),
		Stats:        stats(shares, dests, routes, items, s.st.Uploads(), now),
		SMB:          s.smbStatus(r.Context()),
		Retry: retryInfo{
			MaxAttempts: s.cfg.RetryPolicy.MaxAttempts,
			BaseDelay:   durText(s.cfg.RetryPolicy.BaseDelay),
			MaxDelay:    durText(s.cfg.RetryPolicy.MaxDelay),
			Jitter:      s.cfg.RetryPolicy.Jitter,
		},
	})
}

func (s *Server) shareInfo(shares []model.Share, items []model.Item) map[string]shareInfo {
	pending := map[string]int{}
	for _, it := range items {
		if !it.Done() {
			pending[it.ShareID]++
		}
	}
	// The name an admin set in the settings is the one Samba answers to, so the
	// UNC has to follow it rather than the name in the config file.
	server := s.currentSettings().ServerName
	if server == "" {
		server = s.cfg.NetBIOSName
	}
	out := make(map[string]shareInfo, len(shares))
	for _, sh := range shares {
		out[sh.ID] = shareInfo{
			UNC:       `\\` + server + `\` + sh.Name,
			LocalPath: s.shareDir(sh.Name),
			Pending:   pending[sh.ID],
			// The watcher only sweeps enabled shares, so this is the same bit.
			Watching: sh.Enabled,
		}
	}
	return out
}

func (s *Server) shareDir(name string) string {
	if s.sm != nil {
		return s.sm.ShareDir(name)
	}
	return filepath.Join(s.cfg.ShareRoot, name)
}

// routeInfoOf reads the queue and the history together, because between them
// they describe one day: what is still in flight and what already landed. The
// queue alone is not enough. A delivered scan deletes its own file and its own
// queue entry, so counting only the queue reports "nothing today, last success
// never" on exactly the routes that have just been working.
func routeInfoOf(routes []model.Route, items []model.Item, hist []model.Upload, now time.Time) map[string]routeInfo {
	out := make(map[string]routeInfo, len(routes))
	for _, rt := range routes {
		out[rt.ID] = routeInfo{}
	}
	confirm := func(routeID string, at time.Time, size int64) {
		ri, ok := out[routeID]
		if !ok {
			return // a leg of a route that has since been deleted
		}
		if sameDay(at, now) {
			ri.FilesToday++
			ri.BytesToday += size
		}
		if at.After(ri.LastSuccess) {
			ri.LastSuccess = at
		}
		out[routeID] = ri
	}
	for _, it := range items {
		for _, l := range it.Legs {
			switch l.State {
			case model.LegConfirmed:
				confirm(l.RouteID, l.UploadedAt, it.Size)
			case model.LegPending, model.LegUploading, model.LegRetrying:
				if ri, ok := out[l.RouteID]; ok {
					ri.Pending++
					out[l.RouteID] = ri
				}
			}
		}
	}
	for _, u := range hist {
		if u.Status != "uploaded" {
			continue
		}
		for _, tg := range u.Targets {
			confirm(tg.RouteID, u.At, u.Size)
		}
	}
	return out
}

// recentOfUpload turns a finished file into a row that reads the same as a live
// one, so the activity table does not visibly change shape when a scan lands.
func recentOfUpload(u model.Upload) recentRow {
	dest := ""
	for _, tg := range u.Targets {
		if tg.Destination == "" {
			continue
		}
		if dest != "" {
			dest += ", "
		}
		dest += tg.Destination
	}
	status := u.Status
	if status == "quarantined" {
		status = "failed"
	}
	return recentRow{File: u.File, Share: u.Share, Dest: dest, Status: status, At: u.At}
}

func stats(shares []model.Share, dests []model.Destination, routes []model.Route, items []model.Item, hist []model.Upload, now time.Time) statsInfo {
	shareByID := index(shares, func(sh model.Share) string { return sh.ID })
	destByID := index(dests, func(d model.Destination) string { return d.ID })
	routeByID := index(routes, func(rt model.Route) string { return rt.ID })

	st := statsInfo{TotalFiles: len(items), PerShare: []labelN{}, Recent: []recentRow{}}
	st.Daily = make([]int, histDays)
	st.DailyBytes = make([]int64, histDays)
	// Bucketing on the formatted local date rather than a duration keeps the
	// day boundaries right across a DST change.
	dayIndex := make(map[string]int, histDays)
	for i := 0; i < histDays; i++ {
		dayIndex[now.Local().AddDate(0, 0, -i).Format("2006-01-02")] = histDays - 1 - i
	}
	bump := func(t time.Time, size int64) {
		if i, ok := dayIndex[t.Local().Format("2006-01-02")]; ok {
			st.Daily[i]++
			st.DailyBytes[i] += size
		}
	}
	perShare := map[string]int{}
	for _, it := range items {
		perShare[it.ShareID]++
		if !it.Done() {
			st.Pending++
		}
		if it.Stuck() {
			st.Failed++
		}
		var uploadedThisMonth bool
		for _, l := range it.Legs {
			if l.State != model.LegConfirmed {
				continue
			}
			bump(l.UploadedAt, it.Size)
			if sameDay(l.UploadedAt, now) {
				st.UploadedToday++
			}
			if sameMonth(l.UploadedAt, now) {
				uploadedThisMonth = true
			}
		}
		if uploadedThisMonth {
			st.BytesMonth += it.Size
		}
		st.Recent = append(st.Recent, recentOf(it, shareByID, routeByID, destByID))
	}
	// The queue only holds what has not finished. Everything that worked is in
	// the history, which is the whole reason it exists: a delivered scan deletes
	// its own file and its own queue entry.
	byName := map[string]string{}
	for _, sh := range shares {
		byName[sh.Name] = sh.ID
	}
	// A quarantined scan is deliberately both: the item stays so an admin can
	// retry it, and the history line records why it stopped. Counting both puts
	// the same file in the activity table twice, once per source and with two
	// differently formatted destinations, and inflates the totals with it. The
	// item is the live truth while it exists, so its history line waits.
	live := make(map[string]bool, len(items))
	for _, it := range items {
		live[it.ID] = true
	}
	for _, u := range hist {
		if u.ItemID != "" && live[u.ItemID] {
			continue
		}
		st.TotalFiles++
		if id, ok := byName[u.Share]; ok {
			perShare[id]++
		}
		if u.Status == "uploaded" {
			bump(u.At, u.Size)
			if sameDay(u.At, now) {
				st.UploadedToday++
			}
			if sameMonth(u.At, now) {
				st.BytesMonth += u.Size
			}
		}
		st.Recent = append(st.Recent, recentOfUpload(u))
	}
	for _, sh := range shares {
		st.PerShare = append(st.PerShare, labelN{Label: sh.Name, N: perShare[sh.ID]})
	}
	sort.Slice(st.Recent, func(i, j int) bool { return st.Recent[i].At.After(st.Recent[j].At) })
	if len(st.Recent) > recentRows {
		st.Recent = st.Recent[:recentRows]
	}
	return st
}

func recentOf(it model.Item, shares map[string]model.Share, routes map[string]model.Route, dests map[string]model.Destination) recentRow {
	sh := shares[it.ShareID]
	row := recentRow{
		File:  it.Name,
		Share: sh.Name,
		// The MFP is not identified beyond the account it authenticated as.
		Device: sh.SMBUser,
		Status: itemStatus(it),
		At:     it.Discovered,
	}
	for _, l := range it.Legs {
		if l.UploadedAt.After(row.At) {
			row.At = l.UploadedAt
		}
	}
	if len(it.Legs) > 0 {
		row.Dest = destLabel(dests[routes[it.Legs[0].RouteID].DestinationID])
		if n := len(it.Legs) - 1; n > 0 {
			row.Dest += " +" + strconv.Itoa(n)
		}
	}
	return row
}

func destLabel(d model.Destination) string { return d.Label() }

func itemStatus(it model.Item) string {
	if it.Done() {
		return "uploaded"
	}
	if it.Stuck() {
		return "failed"
	}
	for _, l := range it.Legs {
		if l.State == model.LegUploading {
			return "uploading"
		}
	}
	for _, l := range it.Legs {
		if l.State == model.LegRetrying {
			return "retrying"
		}
	}
	return "pending"
}

func (s *Server) tenantInfo(dests []model.Destination) tenantInfo {
	s.mu.Lock()
	graphErr, certExp := s.graphErr, s.certExp
	s.mu.Unlock()

	// The granted list is the truth: a destination can only exist on a site the
	// box was granted, but a granted site may have no destination yet, and the
	// panel has to show it so an admin can tell onboarding worked.
	seen := map[string]bool{}
	sites := []siteRef{}
	for _, si := range s.grantedSites() {
		seen[si.ID] = true
		sites = append(sites, siteRef{ID: si.ID, Name: si.Name})
	}
	for _, d := range dests {
		if d.SiteID == "" || seen[d.SiteID] {
			continue
		}
		seen[d.SiteID] = true
		sites = append(sites, siteRef{ID: d.SiteID, Name: d.SiteName})
	}
	s.mu.Lock()
	tenant := s.tenant
	s.mu.Unlock()
	return tenantInfo{
		// A tenant id is a GUID and means nothing to a human, so show the domain
		// of the account that onboarded the box when there is one.
		Name:   firstNonEmpty(tenant.Domain(), tenantDomain(s.cfg.TenantID), s.cfg.TenantID),
		Domain: firstNonEmpty(tenant.Domain(), tenantDomain(s.cfg.TenantID)),
		AppID:  s.cfg.ClientID,
		// Consent drops only when Graph refused us on authorization grounds: a
		// network blip must not make the page claim the app registration broke.
		// s.gc is a shared reference that always exists; what matters is whether
		// it currently holds a client, which it does not until onboarding.
		Consent:    s.gc.Get() != nil && !refused(graphErr),
		CertExpiry: certExp,
		Sites:      sites,
		Connected:  s.gc.Get() != nil && graphErr == nil,
	}
}

// tenantDomain shows the tenant id only when it is a domain; a bare GUID in a
// field labelled "domain" reads as a bug.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func tenantDomain(tenantID string) string {
	if strings.Contains(tenantID, ".") {
		return tenantID
	}
	return ""
}

func refused(err error) bool {
	var ae *graph.APIError
	return errors.As(err, &ae) && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden)
}

func (s *Server) smbStatus(ctx context.Context) smbInfo {
	s.mu.Lock()
	if fresh := s.now().Sub(s.smbSeen) < smbStatusTTL; fresh {
		info := s.smbCache
		s.mu.Unlock()
		return info
	}
	s.mu.Unlock()

	if s.sm == nil {
		return smbInfo{}
	}
	running, version, minProtocol, err := s.sm.Status(ctx)
	if err != nil {
		s.log.Warn("reading the Samba status failed", "err", err)
	}
	info := smbInfo{Running: running, Version: version, MinProtocol: minProtocol}
	s.mu.Lock()
	s.smbCache, s.smbSeen = info, s.now()
	s.mu.Unlock()
	return info
}

// durText writes a duration the way the config file does. time.Duration.String
// spells five minutes "5m0s", which reads as a bug in a schedule.
func durText(d time.Duration) string {
	switch {
	case d <= 0:
		return "0s"
	case d%time.Hour == 0:
		return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
	case d%time.Minute == 0:
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m"
	case d%time.Second == 0:
		return strconv.FormatInt(int64(d/time.Second), 10) + "s"
	}
	return d.String()
}

func sameDay(t, now time.Time) bool {
	y1, m1, d1 := t.Local().Date()
	y2, m2, d2 := now.Local().Date()
	return y1 == y2 && m1 == m2 && d1 == d2
}

func sameMonth(t, now time.Time) bool {
	y1, m1, _ := t.Local().Date()
	y2, m2, _ := now.Local().Date()
	return y1 == y2 && m1 == m2
}

func index[T any](in []T, key func(T) string) map[string]T {
	out := make(map[string]T, len(in))
	for _, v := range in {
		out[key(v)] = v
	}
	return out
}
