package graph

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/pkg/config"
	"github.com/AcidDemon/m365-cloud-scan/pkg/transfer"
)

func fastPolicy(chunk int64) config.RetryPolicy {
	return config.RetryPolicy{MaxAttempts: 4, BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond, Jitter: 0, ChunkSize: chunk}
}

func TestCreateUploadSession(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(200)
		fmt.Fprintf(w, `{"uploadUrl":%q}`, "http://example/upload/abc")
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, staticToken("x"))
	sess, err := c.CreateUploadSession(context.Background(), "drive1", "jobs/j1.pdf")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if sess.url != "http://example/upload/abc" {
		t.Fatalf("url=%q", sess.url)
	}
	if !strings.Contains(gotPath, "createUploadSession") {
		t.Fatalf("path=%q", gotPath)
	}
}

// File names carry whatever the MFP or the user typed, and each one has to
// reach Graph as path data with its bytes intact: "%" broke the request before
// it was sent, "#" cut the path short, and "+" can be read as a space.
func TestItemPathsAreEscaped(t *testing.T) {
	for _, tc := range []struct{ name, wire string }{
		{"Rechnung 100%.pdf", "Rechnung%20100%25.pdf"},
		{"Scan#2.pdf", "Scan%232.pdf"},
		{"a+b.pdf", "a%2Bb.pdf"},
		{"Über & Co; 50%.pdf", "%C3%9Cber%20%26%20Co%3B%2050%25.pdf"},
		{"with space.pdf", "with%20space.pdf"},
		{"2026/10/Scans #1/x.pdf", "2026/10/Scans%20%231/x.pdf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var wire, decoded []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				wire = append(wire, r.RequestURI)
				decoded = append(decoded, r.URL.Path)
				fmt.Fprintf(w, `{"uploadUrl":"http://example/upload/abc"}`)
			}))
			defer srv.Close()

			c := NewClient(srv.Client(), srv.URL, staticToken("x"))
			if _, err := c.CreateUploadSession(context.Background(), "d1", tc.name); err != nil {
				t.Fatalf("create: %v", err)
			}
			body, _, err := c.NewDriveItemReader("d1", tc.name).ReadRange(context.Background(), 0, 0)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			body.Close()
			want := []string{"/drives/d1/root:/" + tc.wire + ":/createUploadSession", "/drives/d1/root:/" + tc.wire + ":/content"}
			if len(wire) != 2 || wire[0] != want[0] || wire[1] != want[1] {
				t.Errorf("on the wire %q, want %q", wire, want)
			}
			if len(decoded) != 2 || decoded[0] != "/drives/d1/root:/"+tc.name+":/createUploadSession" {
				t.Errorf("decoded %q, want the name back as it was", decoded)
			}
		})
	}
}

func TestUploadChunkAcceptedReturnsNext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("upload URL must NOT carry Authorization")
		}
		if cr := r.Header.Get("Content-Range"); cr != "bytes 0-3/10" {
			t.Errorf("Content-Range=%q", cr)
		}
		w.WriteHeader(202)
		_, _ = io.WriteString(w, `{"nextExpectedRanges":["4-9"]}`)
	}))
	defer srv.Close()

	sess := &UploadSession{client: NewClient(srv.Client(), srv.URL, staticToken("x")), url: srv.URL}
	next, err := sess.UploadChunk(context.Background(), 0, []byte("0123"), 10)
	if err != nil || next != 4 {
		t.Fatalf("next=%d err=%v", next, err)
	}
}

func TestUploadChunkCompleteReturnsSize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"id":"item1"}`)
	}))
	defer srv.Close()

	sess := &UploadSession{client: NewClient(srv.Client(), srv.URL, staticToken("x")), url: srv.URL}
	next, err := sess.UploadChunk(context.Background(), 8, []byte("89"), 10)
	if err != nil || next != 10 {
		t.Fatalf("next=%d err=%v", next, err)
	}
}

func TestUploadChunkThrottle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(429)
	}))
	defer srv.Close()

	sess := &UploadSession{client: NewClient(srv.Client(), srv.URL, staticToken("x")), url: srv.URL}
	_, err := sess.UploadChunk(context.Background(), 0, []byte("0123"), 10)
	var tr *transfer.Transient
	if !errors.As(err, &tr) || tr.RetryAfter != time.Second {
		t.Fatalf("want throttle 1s, got %T %v", err, err)
	}
}

// fakeUploadServer accumulates chunk bytes keyed by Content-Range and returns
// 202 nextExpectedRanges until full, then 201.
func fakeUploadServer(t *testing.T, size int64) (*httptest.Server, *[]byte) {
	t.Helper()
	got := make([]byte, size)
	var received int64
	mux := http.NewServeMux()
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		cr := r.Header.Get("Content-Range") // bytes start-end/total
		var start, end, total int64
		if _, err := fmt.Sscanf(cr, "bytes %d-%d/%d", &start, &end, &total); err != nil {
			http.Error(w, "bad range", 400)
			return
		}
		body, _ := io.ReadAll(r.Body)
		copy(got[start:], body)
		if end+1 > received {
			received = end + 1
		}
		if received >= total {
			w.WriteHeader(201)
			_, _ = io.WriteString(w, `{"id":"done"}`)
			return
		}
		w.WriteHeader(202)
		fmt.Fprintf(w, `{"nextExpectedRanges":[%q]}`, strconv.FormatInt(received, 10)+"-")
	})
	srv := httptest.NewServer(mux)
	return srv, &got
}

func TestUploadThroughTransferEngine(t *testing.T) {
	data := []byte("the quick brown fox jumps over") // 30 bytes
	srv, got := fakeUploadServer(t, int64(len(data)))
	defer srv.Close()

	sess := &UploadSession{client: NewClient(srv.Client(), srv.URL, staticToken("x")), url: srv.URL + "/upload"}
	store, _ := transfer.NewFileProgressStore(t.TempDir())
	if err := transfer.Upload(context.Background(), fastPolicy(8), "k", bytes.NewReader(data), int64(len(data)), sess, store); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if string(*got) != string(data) {
		t.Fatalf("server got %q want %q", *got, data)
	}
}

func TestReadRangeReturnsBytesAndTotal(t *testing.T) {
	data := []byte("abcdefghij") // 10
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/content") {
			t.Errorf("path=%q", r.URL.Path)
		}
		var start, end int64
		if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil {
			http.Error(w, "bad range", 400)
			return
		}
		if end >= int64(len(data)) {
			end = int64(len(data)) - 1
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
		w.WriteHeader(206)
		_, _ = w.Write(data[start : end+1])
	}))
	defer srv.Close()

	rd := NewClient(srv.Client(), srv.URL, staticToken("x")).NewDriveItemReader("drive1", "jobs/j1.pdf")
	rc, total, err := rd.ReadRange(context.Background(), 0, 4)
	if err != nil {
		t.Fatalf("readrange: %v", err)
	}
	defer rc.Close()
	if total != 10 {
		t.Fatalf("total=%d want 10", total)
	}
	b, _ := io.ReadAll(rc)
	if string(b) != "abcd" {
		t.Fatalf("body=%q", b)
	}
}

func TestReadRange416ReturnsTotal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Range", "bytes */10")
		w.WriteHeader(416)
	}))
	defer srv.Close()

	rd := NewClient(srv.Client(), srv.URL, staticToken("x")).NewDriveItemReader("drive1", "jobs/j1.pdf")
	rc, total, err := rd.ReadRange(context.Background(), 10, 4)
	if err != nil {
		t.Fatalf("416 should not error, got %v", err)
	}
	defer rc.Close()
	if total != 10 {
		t.Fatalf("total=%d want 10", total)
	}
	if b, _ := io.ReadAll(rc); len(b) != 0 {
		t.Fatalf("expected empty body, got %q", b)
	}
}

func fakeDownloadServer(t *testing.T, data []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		size := int64(len(data))
		var start, end int64
		end = size - 1
		if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil {
			if _, err2 := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-", &start); err2 != nil {
				start = 0
			}
		}
		if start >= size {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
			w.WriteHeader(416)
			return
		}
		if end >= size {
			end = size - 1
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
		w.WriteHeader(206)
		_, _ = w.Write(data[start : end+1])
	}))
}

func TestDownloadThroughTransferEngine(t *testing.T) {
	data := []byte("the quick brown fox jumps over") // 30
	srv := fakeDownloadServer(t, data)
	defer srv.Close()

	rd := NewClient(srv.Client(), srv.URL, staticToken("x")).NewDriveItemReader("drive1", "jobs/j1.pdf")
	dst := &bufferWriterAt{}
	store, _ := transfer.NewFileProgressStore(t.TempDir())
	size, err := transfer.Download(context.Background(), fastPolicy(8), "k", dst, rd, store)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if size != int64(len(data)) || string(dst.buf) != string(data) {
		t.Fatalf("size=%d buf=%q", size, dst.buf)
	}
}

// bufferWriterAt is a growable io.WriterAt for the integration test.
type bufferWriterAt struct{ buf []byte }

func (w *bufferWriterAt) WriteAt(p []byte, off int64) (int, error) {
	if need := off + int64(len(p)); int64(len(w.buf)) < need {
		grown := make([]byte, need)
		copy(grown, w.buf)
		w.buf = grown
	}
	copy(w.buf[off:], p)
	return len(p), nil
}

func TestReadRange200WithOffsetErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200) // ignores Range, returns a full body
		_, _ = io.WriteString(w, "full body ignoring range")
	}))
	defer srv.Close()

	rd := NewClient(srv.Client(), srv.URL, staticToken("x")).NewDriveItemReader("drive1", "jobs/j1.pdf")
	if _, _, err := rd.ReadRange(context.Background(), 5, 4); err == nil {
		t.Fatalf("expected error when server returns 200 to a resumed (offset>0) range request")
	}
}

func TestReadRange200AtOffsetZeroIsFullBody(t *testing.T) {
	body := "complete contents"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	rd := NewClient(srv.Client(), srv.URL, staticToken("x")).NewDriveItemReader("drive1", "jobs/j1.pdf")
	rc, total, err := rd.ReadRange(context.Background(), 0, 8)
	if err != nil {
		t.Fatalf("offset 0 with 200 should be ok, got %v", err)
	}
	defer rc.Close()
	if total != int64(len(body)) {
		t.Fatalf("total=%d want %d", total, len(body))
	}
}
