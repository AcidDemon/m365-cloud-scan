package graph

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// pathRecorder serves body for every request and records the escaped paths it
// was asked for, which is what the URL-form and escaping assertions check.
func pathRecorder(t *testing.T, body string) (*httptest.Server, *[]string) {
	t.Helper()
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.URL.EscapedPath())
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func TestChildrenURLForms(t *testing.T) {
	tests := []struct {
		name       string
		folderPath string
		want       string
	}{
		{"root", "", "/drives/d1/root/children"},
		{"single segment", "Scans", "/drives/d1/root:/Scans:/children"},
		{"nested", "Scans/2026", "/drives/d1/root:/Scans/2026:/children"},
		{"surrounding slashes trimmed", "/Scans/", "/drives/d1/root:/Scans:/children"},
		{"root stays root when path is only slashes", "//", "/drives/d1/root/children"},
		{"space and umlaut", "Rechnungen März/Büro 2", "/drives/d1/root:/Rechnungen%20M%C3%A4rz/B%C3%BCro%202:/children"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, got := pathRecorder(t, `{"value":[]}`)
			c := NewClient(srv.Client(), srv.URL, staticToken("t"))
			if _, err := c.Children(context.Background(), "d1", tt.folderPath); err != nil {
				t.Fatalf("Children: %v", err)
			}
			if len(*got) != 1 || (*got)[0] != tt.want {
				t.Errorf("path = %q, want %q", *got, tt.want)
			}
		})
	}
}

func TestChildrenFiltersFilesAndFillsPath(t *testing.T) {
	srv, _ := pathRecorder(t, `{"value":[
		{"id":"1","name":"Eingang","folder":{"childCount":2}},
		{"id":"2","name":"scan.pdf","file":{"mimeType":"application/pdf"}},
		{"id":"3","name":"Archiv","folder":{}}
	]}`)
	c := NewClient(srv.Client(), srv.URL, staticToken("t"))

	got, err := c.Children(context.Background(), "d1", "Scans/2026")
	if err != nil {
		t.Fatalf("Children: %v", err)
	}
	want := []Folder{
		{ID: "1", Name: "Eingang", Path: "Scans/2026/Eingang"},
		{ID: "3", Name: "Archiv", Path: "Scans/2026/Archiv"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d folders %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("folder %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestChildrenAtRootHasBareNameAsPath(t *testing.T) {
	srv, _ := pathRecorder(t, `{"value":[{"id":"1","name":"Scans","folder":{}}]}`)
	c := NewClient(srv.Client(), srv.URL, staticToken("t"))
	got, err := c.Children(context.Background(), "d1", "")
	if err != nil {
		t.Fatalf("Children: %v", err)
	}
	if len(got) != 1 || got[0].Path != "Scans" {
		t.Fatalf("got %+v, want one folder with Path \"Scans\"", got)
	}
}

func TestChildrenFollowsNextLink(t *testing.T) {
	var srv *httptest.Server
	var hits int
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch r.URL.Query().Get("page") {
		case "2":
			_, _ = w.Write([]byte(`{"value":[{"id":"3","name":"C","folder":{}}]}`))
		default:
			_, _ = w.Write([]byte(`{"value":[{"id":"1","name":"A","folder":{}},{"id":"2","name":"B","folder":{}}],
				"@odata.nextLink":"` + srv.URL + `/drives/d1/root/children?page=2"}`))
		}
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, staticToken("t"))
	got, err := c.Children(context.Background(), "d1", "")
	if err != nil {
		t.Fatalf("Children: %v", err)
	}
	if hits != 2 {
		t.Errorf("hits = %d, want 2", hits)
	}
	if len(got) != 3 || got[0].Name != "A" || got[2].Name != "C" {
		t.Fatalf("got %+v, want A B C in order", got)
	}
}

func TestSearchSites(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  string
	}{
		{"empty means everything granted", "", "*"},
		{"blank means everything granted", "   ", "*"},
		{"verbatim query", "Buchhaltung", "Buchhaltung"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/sites" {
					t.Errorf("path = %q", r.URL.Path)
				}
				got = r.URL.Query().Get("search")
				_, _ = w.Write([]byte(`{"value":[{"id":"h,s,w","displayName":"Buchhaltung","webUrl":"https://x/sites/b"}]}`))
			}))
			defer srv.Close()

			c := NewClient(srv.Client(), srv.URL, staticToken("t"))
			sites, err := c.SearchSites(context.Background(), tt.query)
			if err != nil {
				t.Fatalf("SearchSites: %v", err)
			}
			if got != tt.want {
				t.Errorf("search = %q, want %q", got, tt.want)
			}
			if len(sites) != 1 || sites[0].ID != "h,s,w" || sites[0].Name != "Buchhaltung" {
				t.Errorf("sites = %+v", sites)
			}
		})
	}
}

func TestDrivesKeepsSiteIDCommasLiteral(t *testing.T) {
	const siteID = "contoso.sharepoint.com,3c4e,7b9f"
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{"value":[{"id":"b!x","name":"Dokumente"}]}`))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, staticToken("t"))
	drives, err := c.Drives(context.Background(), siteID)
	if err != nil {
		t.Fatalf("Drives: %v", err)
	}
	if want := "/sites/" + siteID + "/drives"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
	if len(drives) != 1 || drives[0].Name != "Dokumente" {
		t.Errorf("drives = %+v", drives)
	}
}

func TestCreateFolder(t *testing.T) {
	var gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"01NEW","name":"März","folder":{}}`))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, staticToken("t"))
	got, err := c.CreateFolder(context.Background(), "d1", "Scans/2026", "März")
	if err != nil {
		t.Fatalf("CreateFolder: %v", err)
	}
	if want := "/drives/d1/root:/Scans/2026:/children"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
	if want := `{"name":"März","folder":{},"@microsoft.graph.conflictBehavior":"fail"}`; gotBody != want {
		t.Errorf("body = %q, want %q", gotBody, want)
	}
	want := Folder{ID: "01NEW", Name: "März", Path: "Scans/2026/März"}
	if got != want {
		t.Errorf("folder = %+v, want %+v", got, want)
	}
}

func TestCreateFolderConflictIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":{"code":"nameAlreadyExists","message":"exists"}}`))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, staticToken("t"))
	_, err := c.CreateFolder(context.Background(), "d1", "", "Scans")
	if err == nil {
		t.Fatal("409 should be reported by CreateFolder")
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusConflict {
		t.Fatalf("want wrapped APIError 409, got %T %v", err, err)
	}
}

func TestEscapePathLeavesSeparatorsAlone(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"/", ""},
		{"a", "a"},
		{"a/b", "a/b"},
		{"a//b", "a/b"},
		{"Rechnungen März", "Rechnungen%20M%C3%A4rz"},
		{"a b/c d", "a%20b/c%20d"},
		{"Größe & Preis", "Gr%C3%B6%C3%9Fe%20&%20Preis"},
	}
	for _, tt := range tests {
		if got := escapePath(tt.in); got != tt.want {
			t.Errorf("escapePath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
