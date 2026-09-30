package scanui

import (
	"bytes"
	"regexp"
	"testing"
)

// The page carries its own fonts as base64, so a truncated paste is a silent
// downgrade to whatever the client OS happens to have.
func TestIndexHTMLIsSelfContained(t *testing.T) {
	for _, want := range []string{
		"__CSRF__",
		"@font-face",
		"IBM Plex Sans",
		"IBM Plex Mono",
		"data:font/woff2;base64,",
	} {
		if !bytes.Contains(IndexHTML, []byte(want)) {
			t.Errorf("the embedded page no longer contains %q", want)
		}
	}
	if n := bytes.Count(IndexHTML, []byte("@font-face")); n != 4 {
		t.Errorf("got %d @font-face rules, want 4 (Plex Sans variable plus Mono 400/500/600)", n)
	}
	if bytes.Contains(IndexHTML, []byte("fonts.googleapis.com")) {
		t.Error("the page fetches a font from the network; the box has no outbound internet")
	}
}

// Several $('id') lookups run while the script is parsing, so one missing id
// throws before any handler is bound: the page then renders but does nothing,
// with no visible symptom. Nothing else in the suite reads the real markup.
func TestEveryScriptedIDExistsInTheMarkup(t *testing.T) {
	for _, m := range regexp.MustCompile(`\$\('([A-Za-z0-9_-]+)'\)`).FindAllSubmatch(IndexHTML, -1) {
		if !bytes.Contains(IndexHTML, []byte(`id="`+string(m[1])+`"`)) {
			t.Errorf("$('%s') has no matching id in the markup", m[1])
		}
	}
}
