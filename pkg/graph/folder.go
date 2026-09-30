package graph

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
)

// EnsureFolder creates a folder named `name` under the drive root. An existing
// folder (HTTP 409) is treated as success, so callers can create the per-job
// folder idempotently. Upload-by-path does not create missing parents, so the
// client must create the job folder before uploading job.pdf into it.
func (c *Client) EnsureFolder(ctx context.Context, driveID, name string) error {
	return c.createFolder(ctx, driveID, "", name)
}

// EnsureFolderPath creates every segment of a library-relative folder path.
// Upload-by-path creates no parents at all, so a date-templated destination
// like 2026/08/21 has to be walked one level at a time. An empty path is the
// library root and needs nothing.
func (c *Client) EnsureFolderPath(ctx context.Context, driveID, folderPath string) error {
	var parent string
	for _, seg := range strings.Split(strings.Trim(folderPath, "/"), "/") {
		if seg == "" {
			continue
		}
		if err := c.createFolder(ctx, driveID, parent, seg); err != nil {
			return err
		}
		parent = path.Join(parent, seg)
	}
	return nil
}

func (c *Client) createFolder(ctx context.Context, driveID, parent, name string) error {
	url := fmt.Sprintf("/drives/%s/root/children", driveID)
	if parent != "" {
		url = fmt.Sprintf("/drives/%s/root:/%s:/children", driveID, parent)
	}
	body := strings.NewReader(fmt.Sprintf(
		`{"name":%q,"folder":{},"@microsoft.graph.conflictBehavior":"fail"}`, name))
	resp, err := c.do(ctx, http.MethodPost, url, body, map[string]string{"Content-Type": "application/json"})
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.Status == http.StatusConflict {
			return nil // already exists
		}
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}
