// Package model holds the three objects the admin UI manages, plus the queue
// item that travels between them. A share is a source, a destination is a
// SharePoint target, and a route wires one to the other.
//
// A share may feed several routes. That is why deletion is a property of the
// item and not of a single upload: the local file goes away only once every
// route that claimed it has confirmed.
package model

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

// ConflictPolicy decides what happens when the destination already holds a file
// of that name.
type ConflictPolicy string

const (
	ConflictRename    ConflictPolicy = "rename"
	ConflictOverwrite ConflictPolicy = "overwrite"
)

// Share is an SMB share on the box. Name doubles as the share name, the
// directory under the share root and the {share} template token, so it is
// restricted to the characters that are safe in all three.
type Share struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	SMBUser   string     `json:"smbUser"`
	Enabled   bool       `json:"enabled"`
	Rules     ShareRules `json:"rules"`
	CreatedAt time.Time  `json:"createdAt"`
}

// ShareRules govern which files the watcher picks up and when the local copy
// may go away. They belong to the share rather than the route because they are
// about the file on disk, which is shared by every route.
type ShareRules struct {
	// Extensions are lowercase and without a dot. Empty means allow everything.
	Extensions []string `json:"extensions"`
	// MaxSizeBytes rejects anything larger. 0 means no limit.
	MaxSizeBytes int64 `json:"maxSizeBytes"`
	// StabilityDelay is how long size and mtime must hold still before the file
	// counts as finished. MFPs write incrementally.
	StabilityDelay Duration `json:"stabilityDelay"`
	// DeleteAfterUpload removes the local file once every route has confirmed.
	DeleteAfterUpload bool `json:"deleteAfterUpload"`
}

// Destination is a saved SharePoint target. Several routes may point at one.
type Destination struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	SiteID    string `json:"siteId"`
	SiteName  string `json:"siteName"`
	DriveID   string `json:"driveId"`
	DriveName string `json:"driveName"`
	// FolderPath is relative to the library root, no leading or trailing slash.
	// Empty means the root itself.
	FolderPath string `json:"folderPath"`
}

// Label is how a destination is named wherever a person reads it. One
// definition because it is written into the history as a snapshot and rendered
// live from the record, and the two reading differently for the same file is
// how the activity table ended up showing one scan under two names.
func (d Destination) Label() string {
	if d.SiteName == "" {
		return d.Name
	}
	return d.SiteName + " · " + d.Name
}

// Route carries files from one share to one destination.
type Route struct {
	ID            string `json:"id"`
	ShareID       string `json:"shareId"`
	DestinationID string `json:"destinationId"`
	Enabled       bool   `json:"enabled"`
	// SubfolderTemplate is appended to the destination folder. Tokens:
	// {yyyy} {MM} {dd} {share} {user}. Empty means upload straight into it.
	SubfolderTemplate string         `json:"subfolderTemplate"`
	Conflict          ConflictPolicy `json:"conflict"`
	MaxAttempts       int            `json:"maxAttempts"`
	// Filter narrows the share's extensions for this route only. Empty means
	// everything the share admits.
	Filter []string `json:"filter"`
}

// Upload is the record a finished file leaves behind. Without it a successful
// scan would vanish from the interface the moment its local copy is deleted,
// which is exactly when the admin most wants to see that it worked.
type Upload struct {
	ID string `json:"id"`
	// ItemID is the queue entry this record describes. A delivered scan deletes
	// its item, but a quarantined one is kept so an admin can retry it, and then
	// the same scan exists as both an item and a history line: the id is what
	// lets the UI count it once. Empty on records written before it existed.
	ItemID  string      `json:"itemId,omitempty"`
	At      time.Time   `json:"at"`
	Share   string      `json:"share"`
	File    string      `json:"file"`
	Size    int64       `json:"size"`
	Status  string      `json:"status"` // uploaded or quarantined
	Targets []UploadLeg `json:"targets,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type UploadLeg struct {
	RouteID     string `json:"routeId"`
	Destination string `json:"destination"`
	DriveItemID string `json:"driveItemId,omitempty"`
	WebURL      string `json:"webUrl,omitempty"`
}

// LegState is where one route's copy of one file has got to.
type LegState string

const (
	LegPending     LegState = "pending"
	LegUploading   LegState = "uploading"
	LegConfirmed   LegState = "confirmed"
	LegRetrying    LegState = "retrying"
	LegQuarantined LegState = "quarantined"
)

// Leg is one file's journey along one route.
type Leg struct {
	RouteID     string    `json:"routeId"`
	State       LegState  `json:"state"`
	Attempts    int       `json:"attempts"`
	NextAttempt time.Time `json:"nextAttempt,omitzero"`
	LastError   string    `json:"lastError,omitempty"`
	DriveItemID string    `json:"driveItemId,omitempty"`
	WebURL      string    `json:"webUrl,omitempty"`
	UploadedAt  time.Time `json:"uploadedAt,omitzero"`
	// Sent is bytes transferred so far, for the progress bar in the UI.
	Sent int64 `json:"sent"`
	// Transient counts failures that were an outage rather than a problem with
	// the scan or the destination, so they did not use the route's retry budget.
	// Together with Attempts it sets how long the next wait is.
	Transient int `json:"transient,omitempty"`
}

// Item is one scanned file and every route it owes a copy to.
type Item struct {
	ID         string    `json:"id"`
	ShareID    string    `json:"shareId"`
	Path       string    `json:"path"`
	Name       string    `json:"name"`
	Size       int64     `json:"size"`
	Discovered time.Time `json:"discovered"`
	Legs       []Leg     `json:"legs"`
	// Quarantined marks the file as moved out of the share after a route gave
	// up. The item stays visible in the UI until an admin clears it.
	Quarantined bool `json:"quarantined"`
}

// Done reports whether every leg has confirmed, which is the only condition
// under which the local file may be deleted.
func (it Item) Done() bool {
	if len(it.Legs) == 0 {
		return false
	}
	for _, l := range it.Legs {
		if l.State != LegConfirmed {
			return false
		}
	}
	return true
}

// Stuck reports whether any leg has given up for good.
func (it Item) Stuck() bool {
	for _, l := range it.Legs {
		if l.State == LegQuarantined {
			return true
		}
	}
	return false
}

// TemplateTokens are every token a subfolder template may use. There is no
// token for the device that scanned: by the time the watcher sees the file the
// SMB session is gone, and guessing from the newest session breaks as soon as
// two devices share a folder. Give each device its own share and {share} names it.
var TemplateTokens = []string{"{yyyy}", "{MM}", "{dd}", "{share}"}

var templateToken = regexp.MustCompile(`\{[^}]*\}`)

// ValidateTemplate rejects a token that does not exist. Without this an unknown
// token reaches SharePoint as a literal folder name.
func ValidateTemplate(tmpl string) error {
	for _, tok := range templateToken.FindAllString(tmpl, -1) {
		if !slices.Contains(TemplateTokens, tok) {
			return fmt.Errorf("unknown token %s, use one of %s", tok, strings.Join(TemplateTokens, " "))
		}
	}
	return nil
}

// RenderTemplate expands the tokens and returns a clean relative path. It leaves
// an unknown token alone; ValidateTemplate is what stops one being saved.
func RenderTemplate(tmpl string, at time.Time, share string) string {
	r := strings.NewReplacer(
		"{yyyy}", at.Format("2006"),
		"{MM}", at.Format("01"),
		"{dd}", at.Format("02"),
		"{share}", share,
	)
	out := path.Clean("/" + strings.Trim(r.Replace(tmpl), "/"))
	return strings.TrimPrefix(out, "/")
}

// DestPath is the full library-relative folder a route writes into.
func DestPath(d Destination, rt Route, at time.Time, share string) string {
	parts := []string{}
	if d.FolderPath != "" {
		parts = append(parts, strings.Trim(d.FolderPath, "/"))
	}
	if sub := RenderTemplate(rt.SubfolderTemplate, at, share); sub != "" {
		parts = append(parts, sub)
	}
	return strings.Join(parts, "/")
}

// Duration is a time.Duration that marshals as "5s" so the state file stays
// readable and hand-editable.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%q", time.Duration(d).String())), nil
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("bad duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) Std() time.Duration { return time.Duration(d) }
