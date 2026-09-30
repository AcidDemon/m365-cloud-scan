package graph

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/AcidDemon/m365-cloud-scan/pkg/transfer"
)

// DriveItem is the subset of a Graph driveItem the callers act on. Size is
// what makes an upload confirmable: an id alone does not prove the bytes landed.
type DriveItem struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	WebURL string `json:"webUrl"`
}

// UploadSession is a resumable Graph upload session. It implements
// transfer.ChunkUploader.
type UploadSession struct {
	client *Client
	url    string // pre-authenticated upload URL
	item   DriveItem
}

// Item is the driveItem Graph returned when the final chunk completed; it is
// the zero value until then. A session is driven by one goroutine at a time,
// so this needs no lock.
func (s *UploadSession) Item() DriveItem { return s.item }

var _ transfer.ChunkUploader = (*UploadSession)(nil)

// CreateUploadSession opens a resumable upload session for the driveItem at
// itemPath within drive driveID, replacing any existing item.
func (c *Client) CreateUploadSession(ctx context.Context, driveID, itemPath string) (*UploadSession, error) {
	return c.CreateUploadSessionConflict(ctx, driveID, itemPath, "replace")
}

// CreateUploadSessionConflict is CreateUploadSession with an explicit Graph
// conflictBehavior: "replace", "rename" or "fail".
func (c *Client) CreateUploadSessionConflict(ctx context.Context, driveID, itemPath, conflict string) (*UploadSession, error) {
	path := fmt.Sprintf("/drives/%s/root:/%s:/createUploadSession", driveID, itemPath)
	body := strings.NewReader(fmt.Sprintf(`{"item":{"@microsoft.graph.conflictBehavior":%q}}`, conflict))
	resp, err := c.do(ctx, http.MethodPost, path, body, map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out struct {
		UploadURL string `json:"uploadUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("graph: decode createUploadSession: %w", err)
	}
	if out.UploadURL == "" {
		return nil, fmt.Errorf("graph: createUploadSession returned no uploadUrl")
	}
	return &UploadSession{client: c, url: out.UploadURL}, nil
}

// UploadChunk PUTs one chunk to the session's pre-authenticated upload URL with
// the proper Content-Range and returns the next byte offset the server expects
// (== size when complete). The upload URL is pre-authenticated, so NO bearer
// token is attached.
func (s *UploadSession) UploadChunk(ctx context.Context, offset int64, chunk []byte, size int64) (int64, error) {
	end := offset + int64(len(chunk)) - 1
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, s.url, bytes.NewReader(chunk))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, end, size))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(chunk))

	resp, err := s.client.http.Do(req)
	if err != nil {
		return 0, &transfer.Transient{Err: err}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusAccepted: // 202: more expected
		return parseNextExpectedRange(resp.Body, offset+int64(len(chunk))), nil
	case http.StatusCreated, http.StatusOK: // 201/200: complete
		// A malformed completion body is not fatal here; the caller decides,
		// by checking Item(), whether the upload is confirmable.
		_ = json.NewDecoder(resp.Body).Decode(&s.item)
		return size, nil
	default:
		// All error statuses share the canonical classification (429/503 throttle,
		// 500/502/504 transient, others terminal) to avoid drift with client.do.
		return 0, classify(resp.StatusCode, resp.Header.Get("Retry-After"), decodeError(resp))
	}
}

// parseNextExpectedRange reads a 202 body's nextExpectedRanges and returns the
// start of the first range. On any parse problem it returns fallback.
func parseNextExpectedRange(body io.Reader, fallback int64) int64 {
	var out struct {
		NextExpectedRanges []string `json:"nextExpectedRanges"`
	}
	if err := json.NewDecoder(body).Decode(&out); err != nil || len(out.NextExpectedRanges) == 0 {
		return fallback
	}
	r := out.NextExpectedRanges[0] // "start-end" or "start-"
	dash := strings.IndexByte(r, '-')
	if dash < 0 {
		return fallback
	}
	n, err := strconv.ParseInt(r[:dash], 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

// DriveItemReader reads ranges of a driveItem's content. It implements
// transfer.RangeReader.
type DriveItemReader struct {
	client      *Client
	contentPath string // /drives/{id}/root:/{itemPath}:/content
}

var _ transfer.RangeReader = (*DriveItemReader)(nil)

// NewDriveItemReader returns a RangeReader for the content of the driveItem at
// itemPath within drive driveID.
func (c *Client) NewDriveItemReader(driveID, itemPath string) *DriveItemReader {
	return &DriveItemReader{
		client:      c,
		contentPath: fmt.Sprintf("/drives/%s/root:/%s:/content", driveID, itemPath),
	}
}

// ReadRange GETs the requested byte range. 206 returns the body + total; 200
// (server ignored Range) is only valid from offset 0, else it is an error to
// avoid writing whole-file bytes at a resumed offset; 416 (range past EOF)
// returns an empty body + total so the caller detects completion; all other
// statuses are classified (retryable vs terminal) via the canonical mapper.
func (r *DriveItemReader) ReadRange(ctx context.Context, offset, length int64) (io.ReadCloser, int64, error) {
	rng := fmt.Sprintf("bytes=%d-", offset)
	if length > 0 {
		rng = fmt.Sprintf("bytes=%d-%d", offset, offset+length-1)
	}
	req, err := r.client.newRequest(ctx, http.MethodGet, r.contentPath, nil, map[string]string{"Range": rng})
	if err != nil {
		return nil, 0, err
	}
	resp, err := r.client.http.Do(req)
	if err != nil {
		return nil, 0, &transfer.Transient{Err: err}
	}
	switch {
	case resp.StatusCode == http.StatusPartialContent: // 206
		total := parseContentRangeTotal(resp.Header.Get("Content-Range"))
		if total < 0 {
			total = resp.ContentLength
		}
		return resp.Body, total, nil
	case resp.StatusCode == http.StatusOK: // 200: server ignored Range, returned full body
		if offset > 0 {
			resp.Body.Close()
			return nil, 0, fmt.Errorf("graph: server ignored Range and returned HTTP 200 at offset %d", offset)
		}
		return resp.Body, resp.ContentLength, nil
	case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable: // 416
		total := parseContentRangeTotal(resp.Header.Get("Content-Range"))
		resp.Body.Close()
		if total < 0 {
			total = offset
		}
		return io.NopCloser(strings.NewReader("")), total, nil
	default:
		defer resp.Body.Close()
		return nil, 0, classify(resp.StatusCode, resp.Header.Get("Retry-After"), decodeError(resp))
	}
}

// parseContentRangeTotal returns the total from a Content-Range header
// ("bytes start-end/total" or "bytes */total"), or -1 if absent/unparseable.
func parseContentRangeTotal(v string) int64 {
	i := strings.LastIndexByte(v, '/')
	if i < 0 {
		return -1
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v[i+1:]), 10, 64)
	if err != nil {
		return -1
	}
	return n
}

// DeleteDriveItem removes a driveItem by id. A 404 counts as removed.
func (c *Client) DeleteDriveItem(ctx context.Context, driveID, itemID string) error {
	resp, err := c.do(ctx, http.MethodDelete, fmt.Sprintf("/drives/%s/items/%s", driveID, itemID), nil, nil)
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
			return nil
		}
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}
