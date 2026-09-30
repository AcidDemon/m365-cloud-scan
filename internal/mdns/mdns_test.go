package mdns

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type call struct {
	name string
	args []string
}

type fakeRunner struct {
	calls    []call
	hostname string
	fail     string
}

func (f *fakeRunner) Run(_ context.Context, name string, args []string, _ []byte) ([]byte, []byte, error) {
	f.calls = append(f.calls, call{name, args})
	if name == "hostname" {
		return []byte(f.hostname + "\n"), nil, nil
	}
	if f.fail == name {
		return nil, []byte("boom"), os.ErrPermission
	}
	return nil, nil, nil
}

func (f *fakeRunner) ran(name string) bool {
	for _, c := range f.calls {
		if c.name == name {
			return true
		}
	}
	return false
}

func setup(t *testing.T) {
	t.Helper()
	ServicePath = filepath.Join(t.TempDir(), "services", "m365-scan.service")
}

func TestPublishWritesServiceAndReloads(t *testing.T) {
	setup(t)
	r := &fakeRunner{hostname: "m365scan"}
	if err := Publish(context.Background(), r, "m365scan", 8444); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(ServicePath)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	for _, want := range []string{"_smb._tcp", "<port>445</port>", "_https._tcp", "<port>8444</port>", "m365scan"} {
		if !strings.Contains(body, want) {
			t.Errorf("service file is missing %q:\n%s", want, body)
		}
	}
	if !r.ran("systemctl") {
		t.Error("avahi was never reloaded, so the advertisement would not appear until a reboot")
	}
	// The hostname already matched, so it must not be touched.
	if r.ran("hostnamectl") {
		t.Error("the hostname already matched and should have been left alone")
	}
}

func TestPublishSetsHostnameWhenItDiffers(t *testing.T) {
	setup(t)
	r := &fakeRunner{hostname: "debian"}
	if err := Publish(context.Background(), r, "scanbox", 8444); err != nil {
		t.Fatal(err)
	}
	if !r.ran("hostnamectl") {
		t.Fatal("avahi derives <host>.local from the hostname, so it has to follow the server name")
	}
}

func TestPublishRejectsBadInput(t *testing.T) {
	setup(t)
	r := &fakeRunner{hostname: "m365scan"}
	if err := Publish(context.Background(), r, "a name with spaces", 8444); err == nil {
		t.Error("a name that is not a valid NetBIOS name should be refused")
	}
	if err := Publish(context.Background(), r, "m365scan", 0); err == nil {
		t.Error("port 0 should be refused")
	}
	if len(r.calls) != 0 {
		t.Errorf("nothing should have been executed for bad input, got %v", r.calls)
	}
}

func TestPublishReportsAReloadFailure(t *testing.T) {
	setup(t)
	r := &fakeRunner{hostname: "m365scan", fail: "systemctl"}
	if err := Publish(context.Background(), r, "m365scan", 8444); err == nil {
		t.Fatal("a failed reload should be reported, the caller decides whether it is fatal")
	}
}
