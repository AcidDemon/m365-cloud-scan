package graph

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnsureFolderCreates(t *testing.T) {
	var gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"01ABC"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, staticToken("t"))
	if err := c.EnsureFolder(context.Background(), "drive1", "job-guid"); err != nil {
		t.Fatalf("EnsureFolder: %v", err)
	}
	if gotPath != "/drives/drive1/root/children" {
		t.Errorf("path = %q", gotPath)
	}
	if !strings.Contains(gotBody, `"name":"job-guid"`) || !strings.Contains(gotBody, `"folder":{}`) {
		t.Errorf("body = %q", gotBody)
	}
}

func TestEnsureFolderConflictIsOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"nameAlreadyExists","message":"exists"}}`))
	}))
	defer srv.Close()
	c := NewClient(srv.Client(), srv.URL, staticToken("t"))
	if err := c.EnsureFolder(context.Background(), "drive1", "job-guid"); err != nil {
		t.Fatalf("conflict should be nil, got %v", err)
	}
}

func TestEnsureFolderOtherErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"accessDenied","message":"no"}}`))
	}))
	defer srv.Close()
	c := NewClient(srv.Client(), srv.URL, staticToken("t"))
	if err := c.EnsureFolder(context.Background(), "drive1", "job-guid"); err == nil {
		t.Fatal("expected error on 403")
	}
}

func TestEnsureFolderPathCreatesEachSegmentInOrder(t *testing.T) {
	var paths, names []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.EscapedPath())
		b, _ := io.ReadAll(r.Body)
		var body struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(b, &body)
		names = append(names, body.Name)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"01ABC"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, staticToken("t"))
	if err := c.EnsureFolderPath(context.Background(), "d1", "Scans/März 2026/Eingang"); err != nil {
		t.Fatalf("EnsureFolderPath: %v", err)
	}

	wantPaths := []string{
		"/drives/d1/root/children",
		"/drives/d1/root:/Scans:/children",
		"/drives/d1/root:/Scans/M%C3%A4rz%202026:/children",
	}
	wantNames := []string{"Scans", "März 2026", "Eingang"}
	if len(paths) != len(wantPaths) {
		t.Fatalf("got %d requests %q, want %d", len(paths), paths, len(wantPaths))
	}
	for i := range wantPaths {
		if paths[i] != wantPaths[i] {
			t.Errorf("request %d path = %q, want %q", i, paths[i], wantPaths[i])
		}
		if names[i] != wantNames[i] {
			t.Errorf("request %d name = %q, want %q", i, names[i], wantNames[i])
		}
	}
}

func TestEnsureFolderPathTolerates(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		wantOK bool
	}{
		{"already exists", http.StatusConflict, `{"error":{"code":"nameAlreadyExists","message":"exists"}}`, true},
		{"created", http.StatusCreated, `{"id":"01ABC"}`, true},
		{"denied", http.StatusForbidden, `{"error":{"code":"accessDenied","message":"no"}}`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			c := NewClient(srv.Client(), srv.URL, staticToken("t"))
			err := c.EnsureFolderPath(context.Background(), "d1", "Scans/2026")
			if tt.wantOK && err != nil {
				t.Fatalf("want nil, got %v", err)
			}
			if !tt.wantOK && err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestEnsureFolderPathEmptyIsNoop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request to %s", r.URL.Path)
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, staticToken("t"))
	for _, p := range []string{"", "/", "//"} {
		if err := c.EnsureFolderPath(context.Background(), "d1", p); err != nil {
			t.Fatalf("EnsureFolderPath(%q): %v", p, err)
		}
	}
}
