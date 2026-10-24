package graph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Site is a SharePoint site as the destination picker needs it.
type Site struct {
	ID     string `json:"id"`
	Name   string `json:"displayName"`
	WebURL string `json:"webUrl"`
}

// Drive is a document library on a site.
type Drive struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Folder is a folder inside a library.
type Folder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Path string `json:"-"` // library-relative, filled in by Children
}

// driveChild is a driveItem trimmed to what the picker needs. The folder facet
// is only present on folders, which is how files get filtered out.
type driveChild struct {
	ID     string    `json:"id"`
	Name   string    `json:"name"`
	Folder *struct{} `json:"folder"`
}

// SearchSites queries /sites?search=. An empty query returns the sites the app
// has been granted, via /sites?search=* .
func (c *Client) SearchSites(ctx context.Context, query string) ([]Site, error) {
	if strings.TrimSpace(query) == "" {
		query = "*"
	}
	return getPaged[Site](ctx, c, "/sites?search="+url.QueryEscape(query))
}

// Drives lists the document libraries of a site.
func (c *Client) Drives(ctx context.Context, siteID string) ([]Drive, error) {
	// Site IDs are "hostname,siteGUID,webGUID" and Graph wants those commas
	// literal, so the ID goes into the path unescaped.
	return getPaged[Drive](ctx, c, "/sites/"+siteID+"/drives")
}

// Children lists only the folders under a library-relative path; an empty path
// means the library root. Files are filtered out because the picker chooses a folder.
func (c *Client) Children(ctx context.Context, driveID, folderPath string) ([]Folder, error) {
	kids, err := getPaged[driveChild](ctx, c, childrenURL(driveID, folderPath))
	if err != nil {
		return nil, err
	}
	base := strings.Trim(folderPath, "/")
	out := []Folder{}
	for _, k := range kids {
		if k.Folder == nil {
			continue
		}
		out = append(out, Folder{ID: k.ID, Name: k.Name, Path: joinPath(base, k.Name)})
	}
	return out, nil
}

// CreateFolder creates one folder under parentPath. Unlike EnsureFolderPath a
// name clash is reported, because the user typed the name and wants to know.
func (c *Client) CreateFolder(ctx context.Context, driveID, parentPath, name string) (Folder, error) {
	resp, err := c.do(ctx, http.MethodPost, childrenURL(driveID, parentPath), folderBody(name),
		map[string]string{"Content-Type": "application/json"})
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.Status == http.StatusConflict {
			return Folder{}, fmt.Errorf("a folder named %q already exists: %w", name, err)
		}
		return Folder{}, err
	}
	defer resp.Body.Close()
	var out driveChild
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Folder{}, fmt.Errorf("graph: decode createFolder: %w", err)
	}
	if out.Name == "" {
		out.Name = name
	}
	return Folder{ID: out.ID, Name: out.Name, Path: joinPath(strings.Trim(parentPath, "/"), out.Name)}, nil
}

// childrenURL builds the children collection URL for a library-relative path.
// Graph only accepts the root:/{path}: form when the path is non-empty; using
// it at the root 404s.
func childrenURL(driveID, folderPath string) string {
	p := escapePath(folderPath)
	if p == "" {
		return "/drives/" + driveID + "/root/children"
	}
	return "/drives/" + driveID + "/root:/" + p + ":/children"
}

// escapePath escapes each segment of a library-relative path on its own, so
// the "/" separators (and the ":" delimiters the caller wraps around the
// result) stay literal while every other byte that is not RFC 3986 unreserved
// is percent-encoded. url.PathEscape is not enough: it leaves "+", "&", "=",
// "$", ":" and "@" alone, and a server that decodes the path like a form reads
// "+" as a space. Encoding a character that did not need it is always safe.
func escapePath(p string) string {
	var b strings.Builder
	for _, s := range strings.Split(strings.Trim(p, "/"), "/") {
		if s == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('/')
		}
		for i := 0; i < len(s); i++ {
			if c := s[i]; 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("-._~", c) >= 0 {
				b.WriteByte(c)
			} else {
				fmt.Fprintf(&b, "%%%02X", c)
			}
		}
	}
	return b.String()
}

func joinPath(base, name string) string {
	if base == "" {
		return name
	}
	return base + "/" + name
}

// folderBody marshals the name as JSON, because %q is Go quoting: it writes
// control characters and invalid UTF-8 as escapes JSON does not have.
func folderBody(name string) *strings.Reader {
	n, _ := json.Marshal(name)
	return strings.NewReader(`{"name":` + string(n) + `,"folder":{},"@microsoft.graph.conflictBehavior":"fail"}`)
}

// getPaged GETs a Graph collection and follows @odata.nextLink until the last
// page. The links are absolute URLs, which c.newRequest passes through as-is.
func getPaged[T any](ctx context.Context, c *Client, urlStr string) ([]T, error) {
	all := []T{}
	for urlStr != "" {
		resp, err := c.do(ctx, http.MethodGet, urlStr, nil, nil)
		if err != nil {
			return nil, err
		}
		var page struct {
			Value    []T    `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		err = json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("graph: decode %s: %w", urlStr, err)
		}
		all = append(all, page.Value...)
		urlStr = page.NextLink
	}
	return all, nil
}
