package scanui

import (
	"testing"
	"time"

	"github.com/AcidDemon/m365-cloud-scan/internal/deviceauth"
)

// Assigning over the struct would replace the mutex while it is held, which is
// a fatal error rather than a recoverable panic, so it kills the daemon.
func TestOnboardingResetKeepsItsMutex(t *testing.T) {
	o := &onboarding{}
	for i := 0; i < 3; i++ {
		o.mu.Lock()
		o.code, o.started = deviceauth.Code{UserCode: "ABC"}, time.Now()
		o.token, o.sites = deviceauth.Token{}, nil
		o.failed, o.finished = "", false
		o.mu.Unlock()
	}
	if got := o.stage(); got != "waiting" {
		t.Fatalf("a started flow should be waiting, got %q", got)
	}
	o.token = deviceauth.Token{AccessToken: "x"}
	if got := o.stage(); got != "sites" {
		t.Fatalf("a signed-in flow should offer sites, got %q", got)
	}
	o.finished = true
	if got := o.stage(); got != "done" {
		t.Fatalf("got %q", got)
	}
	o.failed = "nope"
	if got := o.stage(); got != "failed" {
		t.Fatalf("a failure outranks the rest, got %q", got)
	}
}
