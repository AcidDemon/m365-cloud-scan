package scanui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/internal/smb"
	"github.com/AcidDemon/m365-cloud-scan/internal/store"
)

// The ansible-owned /etc/nftables.d/base_filter.nft deletes and recreates
// 'table inet base_filter', whose input chain drops by default. A drop in a
// base chain is terminal, so a second table of our own could never let a packet
// through: the allowance has to be appended into that chain. The "zz-" prefix
// sorts after base_filter in the include glob, so a reload rebuilds the table
// and re-appends these rules in the same transaction, and applying the whole
// conf twice leaves the rule count unchanged.
const (
	nftConfPath = "/etc/nftables.conf"
	nftDropIn   = "zz-m365-scan.nft"
	// The leading dot and the .tmp suffix keep the half-written file out of the
	// *.nft glob, so a reload racing with a save cannot pick it up.
	nftTempFile = ".m365-scan.tmp"

	fwMaxPerTier = 32
	fwMaxLabel   = 40
)

// FWEntry is one customer network that may reach the box. Tier says what for:
// "admin" is SSH and this UI, "copier" is the SMB service the scanners use.
type FWEntry struct {
	ID      string `json:"id"`
	Tier    string `json:"tier"`
	Label   string `json:"label"`
	CIDR    string `json:"cidr"`
	AddedAt string `json:"addedAt"`
}

// fwPorts is what each tier opens. NetBIOS and mDNS ride along with SMB
// because a copier that cannot resolve the box cannot scan to it either.
var fwPorts = map[string][]struct{ proto, ports string }{
	"admin":  {{"tcp", "22, 8444"}},
	"copier": {{"tcp", "139, 445"}, {"udp", "137, 138, 5353"}},
}

// The Tailscale link is the way back into a box whose networks were mistyped.
// It is pinned by interface in ansible and never listed here, so a rule that
// only the tailnet reaches can always be corrected.
var tailnetNets = []*net.IPNet{
	mustCIDR("100.64.0.0/10"),
	mustCIDR("fd7a:115c:a1e0::/48"),
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

type firewallFile struct {
	Version int       `json:"version"`
	Entries []FWEntry `json:"entries"`
}

func firewallPath(statePath string) string {
	return filepath.Join(filepath.Dir(statePath), "firewall.json")
}

// loadFirewall reads the saved networks. A box that never had any has no file,
// which is an empty list and no error. Anything else IS an error, and the
// difference matters: an unreadable file used to read as "no networks", which
// the startup re-apply then wrote into the kernel, deleting the very rules it
// exists to restore.
func loadFirewall(path string) ([]FWEntry, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f firewallFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	return f.Entries, nil
}

func (s *Server) currentFirewall() []FWEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]FWEntry(nil), s.firewall...)
}

// renderFirewall writes the drop-in. The order is fixed so that saving the same
// list twice produces the same file and nothing churns.
func renderFirewall(entries []FWEntry) string {
	lines := []string{
		"#!/usr/sbin/nft -f",
		"# Managed by m365-scan (admin UI -> Network access). Do not edit by hand.",
	}
	sorted := append([]FWEntry(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Tier != sorted[j].Tier {
			return sorted[i].Tier < sorted[j].Tier
		}
		return sorted[i].CIDR < sorted[j].CIDR
	})
	for _, e := range sorted {
		// The padding lines the v4 rules up with the v6 ones in a file an admin
		// may well end up reading over someone's shoulder.
		fam := "ip "
		if strings.Contains(e.CIDR, ":") {
			fam = "ip6"
		}
		for _, p := range fwPorts[e.Tier] {
			lines = append(lines, "add rule inet base_filter input "+fam+" saddr "+e.CIDR+" "+p.proto+" dport { "+p.ports+" } accept")
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

// runner is the exec seam nft goes through. The box gets it with Samba, so a
// box without one cannot run nft either.
func (s *Server) runner() (smb.Runner, error) {
	if s.sm == nil {
		return nil, errors.New("this box cannot change its firewall")
	}
	return s.sm.Runner(), nil
}

// applyFirewall renders the drop-in and loads it. The order matters: the file is
// checked against the live kernel before it can be seen by a reload, and a
// reload that fails puts the previous drop-in back. Never `systemctl restart
// nftables`: Debian's unit stops with `nft flush ruleset`, which would take
// CrowdSec's and fail2ban's tables with it.
func (s *Server) applyFirewall(ctx context.Context, entries []FWEntry) error {
	run, err := s.runner()
	if err != nil {
		return err
	}
	dropIn := filepath.Join(s.nftDir, nftDropIn)
	tmp := filepath.Join(s.nftDir, nftTempFile)
	if err := os.WriteFile(tmp, []byte(renderFirewall(entries)), 0o644); err != nil {
		return fmt.Errorf("the firewall rules could not be written: %v", err)
	}
	// -c checks against the running ruleset, so this also catches a base_filter
	// that is not loaded at all, which is the state a bad file leaves at boot.
	if _, stderr, err := run.Run(ctx, "nft", []string{"-c", "-f", tmp}, nil); err != nil {
		os.Remove(tmp)
		return nftError("the firewall rules were refused", stderr, err)
	}
	backup, backupErr := os.ReadFile(dropIn)
	if err := os.Rename(tmp, dropIn); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("the firewall rules could not be saved: %v", err)
	}
	if _, stderr, err := run.Run(ctx, "nft", []string{"-f", nftConfPath}, nil); err != nil {
		// Put back whatever was there and reload again, so a failed save leaves
		// the box reachable exactly as it was.
		if backupErr == nil {
			_ = os.WriteFile(dropIn, backup, 0o644)
		} else {
			_ = os.Remove(dropIn)
		}
		_, _, _ = run.Run(ctx, "nft", []string{"-f", nftConfPath}, nil)
		return nftError("the firewall could not be reloaded", stderr, err)
	}
	return nil
}

// reapplyFirewall puts the saved networks back into the kernel at startup, so a
// drop-in that was deleted by hand repairs itself. It is not fatal: a box that
// cannot load its rules still has to serve the page that says so.
func (s *Server) reapplyFirewall() {
	s.fwMu.Lock()
	defer s.fwMu.Unlock()
	// Re-read rather than trust the list NewServer loaded: if the file cannot be
	// read, the rules already in the kernel are better than the empty list this
	// would otherwise apply.
	if _, err := loadFirewall(s.firewallPath); err != nil {
		s.log.Error("the allowed networks could not be read, the rules already in the kernel are left alone",
			"path", s.firewallPath, "err", err)
		return
	}
	entries := s.currentFirewall()
	if err := s.applyFirewall(context.Background(), entries); err != nil {
		s.log.Error("the allowed networks could not be applied", "err", err)
		return
	}
	s.log.Info("allowed networks applied", "networks", len(entries))
}

func nftError(what string, stderr []byte, err error) error {
	if msg := strings.TrimSpace(string(stderr)); msg != "" {
		return fmt.Errorf("%s: %s", what, msg)
	}
	return fmt.Errorf("%s: %v", what, err)
}

type fwYou struct {
	IP         string `json:"ip"`
	ViaTailnet bool   `json:"viaTailnet"`
	CoveredBy  string `json:"coveredBy"`
}

// firewallResp is what all three routes answer with, so the page never has to
// guess what the box kept.
func (s *Server) firewallResp(entries []FWEntry, r *http.Request) map[string]any {
	if entries == nil {
		entries = []FWEntry{}
	}
	ip := net.ParseIP(clientIP(r))
	you := fwYou{IP: clientIP(r), ViaTailnet: onTailnet(ip)}
	// Only the admin tier matters here: the question the page asks is whether
	// the person reading it would still get in.
	if e, ok := covering(entries, "admin", ip); ok {
		you.CoveredBy = e.ID
	}
	fw := map[string]any{"entries": entries, "you": you}
	s.mu.Lock()
	until := s.fwUntil
	s.mu.Unlock()
	if !until.IsZero() {
		fw["armed"] = map[string]any{"until": until.UTC().Format(time.RFC3339)}
	}
	return map[string]any{"firewall": fw}
}

func (s *Server) handleGetFirewall(rw http.ResponseWriter, r *http.Request) {
	writeJSON(rw, s.firewallResp(s.currentFirewall(), r))
}

// The confirm-or-revert window. It is NOT proof that whoever made the change
// can still reach the box: rule #1 of base_filter accepts established flows, so
// the page that made the change keeps working either way. It is here so a
// change that cut the copiers off comes back by itself when nobody is watching
// the other end of the wire.
const fwMaxRevert = 30 * time.Minute

func (s *Server) armRevert(prev []FWEntry, d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fwTimer != nil {
		// Already armed: a second change inside the window extends it, but what
		// it falls back to stays the last CONFIRMED list, which is the one the
		// file still holds. Overwriting it here would make "undo" restore
		// something nobody ever agreed to either.
		s.fwTimer.Stop()
	} else {
		s.fwPrev = prev
	}
	// The generation makes a timer that has already fired harmless. Without it,
	// a revert firing just as a new change arms could take the new list down
	// with the old one, and the box would silently hold rules nobody chose.
	s.fwGen++
	gen := s.fwGen
	s.fwUntil = s.now().Add(d)
	s.fwTimer = time.AfterFunc(d, func() { s.revertFirewall(gen) })
}

// peek reports the pending revert without consuming it, so a restore that fails
// leaves the window intact and the countdown still means something.
func (s *Server) peek() ([]FWEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fwPrev, s.fwTimer != nil
}

// disarm takes the pending revert away, if there is one. Whoever gets the
// entries back owns the decision.
func (s *Server) disarm() ([]FWEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fwTimer == nil {
		return nil, false
	}
	s.fwTimer.Stop()
	prev := s.fwPrev
	s.fwTimer, s.fwPrev, s.fwUntil = nil, nil, time.Time{}
	return prev, true
}

// staleGen reports whether this timer was superseded while it waited for the
// lock.
func (s *Server) staleGen(gen uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return gen != s.fwGen
}

func (s *Server) revertFirewall(gen uint64) {
	s.fwMu.Lock()
	defer s.fwMu.Unlock()
	if s.staleGen(gen) {
		return
	}
	// Peeked, not consumed: a restore that fails has to leave the window armed,
	// or the box keeps rules nobody confirmed and nothing will ever put them
	// back.
	prev, armed := s.peek()
	if !armed {
		return
	}
	if err := s.applyFirewall(context.Background(), prev); err != nil {
		s.log.Error("restoring the previous networks failed", "err", err)
		return
	}
	s.disarm()
	s.mu.Lock()
	s.firewall = prev
	s.mu.Unlock()
	s.log.Info("nobody confirmed the new networks, the previous ones are back", "networks", len(prev))
}

// handleConfirmFirewall keeps or undoes a change that is in the kernel but not
// yet on disk.
func (s *Server) handleConfirmFirewall(rw http.ResponseWriter, r *http.Request) {
	s.fwMu.Lock()
	defer s.fwMu.Unlock()
	var b struct {
		Undo bool `json:"undo"`
	}
	if !decode(rw, r, &b) {
		return
	}
	// Peeked, not consumed. Disarming first meant a failed undo answered with an
	// error AND threw the countdown away, leaving rules nobody confirmed with
	// nothing left to put them back.
	prev, armed := s.peek()
	if !armed {
		// Nothing pending: the timer already fired, or someone else confirmed.
		writeJSON(rw, s.firewallResp(s.currentFirewall(), r))
		return
	}
	if b.Undo {
		if err := s.applyFirewall(context.WithoutCancel(r.Context()), prev); err != nil {
			fail(rw, err)
			return
		}
		s.disarm()
		s.mu.Lock()
		s.firewall = prev
		s.mu.Unlock()
		writeJSON(rw, s.firewallResp(prev, r))
		return
	}
	cur := s.currentFirewall()
	if err := s.saveFirewall(cur); err != nil {
		fail(rw, err)
		return
	}
	s.disarm()
	s.log.Info("allowed networks confirmed", "networks", len(cur))
	writeJSON(rw, s.firewallResp(cur, r))
}

// saveFirewall writes the list that is already in the kernel.
func (s *Server) saveFirewall(entries []FWEntry) error {
	raw, err := json.MarshalIndent(firewallFile{Version: 1, Entries: entries}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.firewallPath), 0o750); err != nil {
		return err
	}
	// Temp then rename, like the drop-in: a power cut mid-write would otherwise
	// leave a truncated file, and an unreadable one is what the startup
	// re-apply has to be protected from in the first place.
	tmp := filepath.Join(filepath.Dir(s.firewallPath), ".firewall.json.tmp")
	if err := os.WriteFile(tmp, raw, 0o640); err != nil {
		return errors.New("the networks are in effect but could not be saved: " + err.Error())
	}
	if err := os.Rename(tmp, s.firewallPath); err != nil {
		os.Remove(tmp)
		return errors.New("the networks are in effect but could not be saved: " + err.Error())
	}
	return nil
}

// handleSetFirewall takes the whole list, not a single change: the page edits a
// table and one save is one ruleset.
func (s *Server) handleSetFirewall(rw http.ResponseWriter, r *http.Request) {
	s.fwMu.Lock()
	defer s.fwMu.Unlock()
	var b struct {
		Entries []FWEntry `json:"entries"`
		// Seconds to wait for a confirmation before putting the previous list
		// back. 0 means the change stands on its own.
		RevertAfter int `json:"revertAfter"`
	}
	if !decode(rw, r, &b) {
		return
	}
	next := make([]FWEntry, 0, len(b.Entries))
	perTier := map[string]int{}
	for _, e := range b.Entries {
		if _, ok := fwPorts[e.Tier]; !ok {
			failText(rw, "choose whether the network is for administration or for the copiers")
			return
		}
		cidr, err := normalCIDR(e.CIDR)
		if err != nil {
			fail(rw, err)
			return
		}
		e.CIDR = cidr
		e.Label = strings.TrimSpace(e.Label)
		if e.Label == "" {
			failText(rw, "give "+e.CIDR+" a name, so the next person knows whose network it is")
			return
		}
		if len([]rune(e.Label)) > fwMaxLabel {
			failText(rw, "the name of "+e.CIDR+" is too long, use at most 40 characters")
			return
		}
		// Two entries where one holds the other are one rule too many, and the
		// admin who later deletes the small one is surprised twice.
		for _, p := range next {
			if p.Tier != e.Tier {
				continue
			}
			if contains(p.CIDR, e.CIDR) {
				failText(rw, e.CIDR+" is already covered by "+p.Label+" ("+p.CIDR+")")
				return
			}
			if contains(e.CIDR, p.CIDR) {
				failText(rw, p.CIDR+" is already covered by "+e.Label+" ("+e.CIDR+")")
				return
			}
		}
		perTier[e.Tier]++
		if perTier[e.Tier] > fwMaxPerTier {
			failText(rw, "at most 32 networks can be listed for each kind of access")
			return
		}
		if e.ID == "" {
			e.ID = store.NewID("fw")
		}
		if e.AddedAt == "" {
			e.AddedAt = s.now().UTC().Format(time.RFC3339)
		}
		next = append(next, e)
	}

	// The one real lockout guard. Over the tailnet there is always a way back
	// in, so it never fires there.
	cur := s.currentFirewall()
	if ip := net.ParseIP(clientIP(r)); ip != nil && !onTailnet(ip) {
		if was, ok := covering(cur, "admin", ip); ok {
			if _, still := covering(next, "admin", ip); !still {
				failText(rw, "removing "+was.Label+" ("+was.CIDR+") would lock you out: you are connected from "+ip.String()+". Add a network that covers it first, or make the change over Tailscale")
				return
			}
		}
	}

	// A save with no window of its own supersedes a pending one, and has to do
	// so BEFORE it applies: disarming afterwards leaves a gap in which the old
	// timer can fire and restore a list two changes old over the one just made.
	if b.RevertAfter <= 0 {
		s.disarm()
	}
	// Apply first, then save: a file promising a rule the kernel never took is
	// a lie the admin cannot see.
	prev := s.currentFirewall()
	if err := s.applyFirewall(context.WithoutCancel(r.Context()), next); err != nil {
		fail(rw, err)
		return
	}
	s.mu.Lock()
	s.firewall = next
	s.mu.Unlock()

	// Armed: the kernel has the new rules but the FILE still holds the old
	// ones, so a crash or a reboot inside the window lands on the previous
	// list rather than on one nobody ever confirmed.
	if d := time.Duration(b.RevertAfter) * time.Second; d > 0 {
		if d > fwMaxRevert {
			d = fwMaxRevert
		}
		s.armRevert(prev, d)
		s.log.Info("allowed networks applied, waiting for confirmation", "networks", len(next), "for", d)
		writeJSON(rw, s.firewallResp(next, r))
		return
	}
	if err := s.saveFirewall(next); err != nil {
		fail(rw, err)
		return
	}
	s.log.Info("allowed networks changed", "networks", len(next))
	writeJSON(rw, s.firewallResp(next, r))
}

// normalCIDR masks the host bits, so 192.168.1.44/24 becomes 192.168.1.0/24 and
// the rule says what the admin meant. A bare address is that host alone.
func normalCIDR(s string) (string, error) {
	s = strings.TrimSpace(s)
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n.String(), nil
	}
	if ip := net.ParseIP(s); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String() + "/32", nil
		}
		return ip.String() + "/128", nil
	}
	return "", errors.New(s + " is not a network, write it like 192.168.30.0/24 or 192.168.30.7")
}

func netOf(cidr string) *net.IPNet {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	return n
}

// contains reports whether outer holds all of inner, which is what makes a
// second entry pointless rather than merely overlapping.
func contains(outer, inner string) bool {
	o, i := netOf(outer), netOf(inner)
	if o == nil || i == nil {
		return false
	}
	oOnes, oBits := o.Mask.Size()
	iOnes, iBits := i.Mask.Size()
	return oBits == iBits && oOnes <= iOnes && o.Contains(i.IP)
}

// covering finds the entry of a tier that an address falls into.
func covering(entries []FWEntry, tier string, ip net.IP) (FWEntry, bool) {
	if ip == nil {
		return FWEntry{}, false
	}
	for _, e := range entries {
		if e.Tier != tier {
			continue
		}
		if n := netOf(e.CIDR); n != nil && n.Contains(ip) {
			return e, true
		}
	}
	return FWEntry{}, false
}

func onTailnet(ip net.IP) bool {
	for _, n := range tailnetNets {
		if ip != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}
