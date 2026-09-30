package smb

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type call struct {
	name  string
	args  []string
	stdin string
}

type fakeRunner struct {
	calls []call
	// hook decides stdout and failure per command; nil means every command
	// succeeds silently.
	hook func(name string, args []string) ([]byte, error)
}

func (f *fakeRunner) Run(_ context.Context, name string, args []string, stdin []byte) ([]byte, []byte, error) {
	f.calls = append(f.calls, call{name, append([]string(nil), args...), string(stdin)})
	if f.hook == nil {
		return nil, nil, nil
	}
	out, err := f.hook(name, args)
	return out, nil, err
}

// argv renders the recorded commands the way a shell would show them.
func (f *fakeRunner) argv() []string {
	var out []string
	for _, c := range f.calls {
		out = append(out, strings.Join(append([]string{c.name}, c.args...), " "))
	}
	return out
}

func joined(name string, args []string) string {
	return strings.Join(append([]string{name}, args...), " ")
}

// shareAbsent makes `net conf showshare` fail, which is how a fresh box looks.
func shareAbsent(name string, args []string) ([]byte, error) {
	if strings.Contains(joined(name, args), "conf showshare") {
		return nil, errors.New("exit status 255")
	}
	return nil, nil
}

func newManager(t *testing.T, hook func(string, []string) ([]byte, error)) (*Manager, *fakeRunner, string) {
	t.Helper()
	root := t.TempDir()
	f := &fakeRunner{hook: hook}
	return New(f, root), f, root
}

func wantArgv(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("commands:\n got %v\nwant %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("command %d:\n got %q\nwant %q", i, got[i], want[i])
		}
	}
}

func TestEnsureShare(t *testing.T) {
	m, f, root := newManager(t, shareAbsent)
	dir := filepath.Join(root, "scans")

	if err := m.EnsureShare(context.Background(), "scans", "scan-front"); err != nil {
		t.Fatalf("EnsureShare: %v", err)
	}
	wantArgv(t, f.argv(), []string{
		"chown scan-front " + dir,
		"net conf showshare scans",
		"net conf addshare scans " + dir + " writeable=y guest_ok=n",
		"net conf setparm scans valid users scan-front",
		"net conf setparm scans create mask 0660",
		"net conf setparm scans directory mask 0770",
		"net conf setparm scans browseable yes",
		"net conf setparm scans veto files /.DS_Store/Thumbs.db/._*/",
	})
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("share dir: %v", err)
	}
	if fi.Mode().Perm() != 0o770 {
		t.Errorf("share dir mode = %v, want 0770", fi.Mode().Perm())
	}
}

func TestEnsureShareIdempotent(t *testing.T) {
	// Second run: the registry already knows the share, so it is updated in
	// place instead of re-added.
	m, f, root := newManager(t, nil)
	if err := m.EnsureShare(context.Background(), "scans", "scan-front"); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := m.EnsureShare(context.Background(), "scans", "scan-front"); err != nil {
		t.Fatalf("second run: %v", err)
	}
	for _, c := range f.argv() {
		if strings.Contains(c, "addshare") {
			t.Errorf("re-added an existing share: %q", c)
		}
	}
	if n := strings.Count(strings.Join(f.argv(), "\n"), "setparm"); n != 10 {
		t.Errorf("setparm calls = %d, want 10", n)
	}
	if fi, err := os.Stat(filepath.Join(root, "scans")); err != nil || fi.Mode().Perm() != 0o770 {
		t.Errorf("share dir after re-run: %v %v", fi, err)
	}
}

func TestRemoveShareKeepsDirectory(t *testing.T) {
	m, f, root := newManager(t, nil)
	dir := filepath.Join(root, "scans")
	if err := os.MkdirAll(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := m.RemoveShare(context.Background(), "scans"); err != nil {
		t.Fatalf("RemoveShare: %v", err)
	}
	wantArgv(t, f.argv(), []string{
		"net conf showshare scans",
		"net conf delshare scans",
	})
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("share dir was removed: %v", err)
	}
}

func TestRemoveShareUnknownIsNoop(t *testing.T) {
	m, f, _ := newManager(t, shareAbsent)
	if err := m.RemoveShare(context.Background(), "scans"); err != nil {
		t.Fatalf("RemoveShare: %v", err)
	}
	wantArgv(t, f.argv(), []string{"net conf showshare scans"})
}

func TestEnsureUserPasswordOnStdin(t *testing.T) {
	const pw = "Kd7hRt2mQx4vBn6y"
	m, f, _ := newManager(t, nil)
	if err := m.EnsureUser(context.Background(), "scan-front", pw); err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	wantArgv(t, f.argv(), []string{
		"useradd --system --no-create-home --shell /usr/sbin/nologin scan-front",
		"smbpasswd -a -s scan-front",
	})
	last := f.calls[len(f.calls)-1]
	if last.stdin != pw+"\n"+pw+"\n" {
		t.Errorf("smbpasswd stdin = %q, want the password twice", last.stdin)
	}
	for _, c := range f.argv() {
		if strings.Contains(c, pw) {
			t.Errorf("password leaked into argv (visible in ps): %q", c)
		}
	}
}

func TestSetPassword(t *testing.T) {
	const pw = "Zx9pLm3kWq7tRs2v"
	m, f, _ := newManager(t, nil)
	if err := m.SetPassword(context.Background(), "scan-front", pw); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	wantArgv(t, f.argv(), []string{"smbpasswd -s scan-front"})
	if f.calls[0].stdin != pw+"\n"+pw+"\n" {
		t.Errorf("stdin = %q, want the password twice", f.calls[0].stdin)
	}
}

func TestEnsureUserToleratesExisting(t *testing.T) {
	m, f, _ := newManager(t, func(name string, args []string) ([]byte, error) {
		if name == "useradd" {
			return nil, errors.New("useradd: user 'scan-front' already exists")
		}
		return nil, nil
	})
	if err := m.EnsureUser(context.Background(), "scan-front", "Kd7hRt2mQx4vBn6y"); err != nil {
		t.Fatalf("EnsureUser on an existing account: %v", err)
	}
	if len(f.calls) != 2 || f.calls[1].name != "smbpasswd" {
		t.Errorf("password was not set after useradd failed: %v", f.argv())
	}
}

func TestRemoveUser(t *testing.T) {
	m, f, _ := newManager(t, func(name string, args []string) ([]byte, error) {
		if name == "userdel" {
			return nil, errors.New("userdel: user 'scan-front' does not exist")
		}
		return nil, nil
	})
	if err := m.RemoveUser(context.Background(), "scan-front"); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	wantArgv(t, f.argv(), []string{
		"smbpasswd -x scan-front",
		"userdel scan-front",
	})
}

func TestSetGlobal(t *testing.T) {
	m, f, _ := newManager(t, nil)
	if err := m.SetGlobal(context.Background(), "SMB3", "scanbox", "ACIDNET"); err != nil {
		t.Fatalf("SetGlobal: %v", err)
	}
	wantArgv(t, f.argv(), []string{
		"net conf setparm global server min protocol SMB3",
		"net conf setparm global netbios name scanbox",
		"net conf setparm global workgroup ACIDNET",
	})
}

// Samba still calls SMB1 NT1, and the UI does not.
func TestSetGlobalMapsSMB1ToNT1(t *testing.T) {
	m, f, _ := newManager(t, nil)
	if err := m.SetGlobal(context.Background(), "SMB1", "m365scan", "WORKGROUP"); err != nil {
		t.Fatalf("SetGlobal: %v", err)
	}
	if got := f.argv()[0]; got != "net conf setparm global server min protocol NT1" {
		t.Errorf("first command = %q", got)
	}
}

func TestBadNamesExecuteNothing(t *testing.T) {
	const pw = "Kd7hRt2mQx4vBn6y"
	cases := []struct {
		name string
		do   func(*Manager) error
	}{
		{"share with a space", func(m *Manager) error { return m.EnsureShare(context.Background(), "scan folder", "scan") }},
		{"share with a slash", func(m *Manager) error { return m.EnsureShare(context.Background(), "../etc", "scan") }},
		{"uppercase share", func(m *Manager) error { return m.EnsureShare(context.Background(), "Scans", "scan") }},
		{"user with a space", func(m *Manager) error { return m.EnsureShare(context.Background(), "scans", "scan front") }},
		{"uppercase user", func(m *Manager) error { return m.EnsureUser(context.Background(), "Scan", pw) }},
		{"user starting with a digit", func(m *Manager) error { return m.EnsureUser(context.Background(), "1scan", pw) }},
		{"user with a semicolon", func(m *Manager) error { return m.SetPassword(context.Background(), "scan;reboot", pw) }},
		{"empty password", func(m *Manager) error { return m.SetPassword(context.Background(), "scan", "") }},
		{"password with a newline", func(m *Manager) error { return m.EnsureUser(context.Background(), "scan", "a\nb") }},
		{"remove a bad share name", func(m *Manager) error { return m.RemoveShare(context.Background(), "-scans") }},
		{"remove a bad user name", func(m *Manager) error { return m.RemoveUser(context.Background(), "root oops") }},
		{"short password", func(m *Manager) error { return m.SetPassword(context.Background(), "scan", "kurz123") }},
		{"password with a null byte", func(m *Manager) error { return m.EnsureUser(context.Background(), "scan", "abcdefgh\x00xyz") }},
		{"unknown protocol", func(m *Manager) error { return m.SetGlobal(context.Background(), "SMB4", "box", "WG") }},
		{"server name with a dot", func(m *Manager) error { return m.SetGlobal(context.Background(), "SMB3", "box.local", "WG") }},
		{"server name of 16 characters", func(m *Manager) error {
			return m.SetGlobal(context.Background(), "SMB3", "abcdefghijklmnop", "WG")
		}},
		{"workgroup with a semicolon", func(m *Manager) error { return m.SetGlobal(context.Background(), "SMB3", "box", "WG;reboot") }},
		{"empty workgroup", func(m *Manager) error { return m.SetGlobal(context.Background(), "SMB3", "box", "") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, f, root := newManager(t, nil)
			if err := tc.do(m); err == nil {
				t.Fatal("want an error")
			}
			if len(f.calls) != 0 {
				t.Errorf("ran commands anyway: %v", f.argv())
			}
			if entries, _ := os.ReadDir(root); len(entries) != 0 {
				t.Errorf("created %d directories anyway", len(entries))
			}
		})
	}
}

func TestStatus(t *testing.T) {
	m, _, _ := newManager(t, func(name string, args []string) ([]byte, error) {
		switch name {
		case "systemctl":
			return []byte("active\n"), nil
		case "smbd":
			return []byte("Version 4.19.5-Debian\n"), nil
		case "testparm":
			return []byte("SMB3_00\n"), nil
		}
		return nil, nil
	})
	running, version, minProto, err := m.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !running || version != "4.19.5-Debian" || minProto != "SMB3_00" {
		t.Errorf("Status = %v %q %q", running, version, minProto)
	}
}

func TestStatusNotRunning(t *testing.T) {
	m, _, _ := newManager(t, func(name string, args []string) ([]byte, error) {
		if name == "systemctl" {
			return []byte("inactive\n"), errors.New("exit status 3")
		}
		return []byte("Version 4.19.5-Debian\n"), nil
	})
	running, version, _, err := m.Status(context.Background())
	if err != nil || running || version != "4.19.5-Debian" {
		t.Errorf("Status = %v %q %v", running, version, err)
	}
}

func TestGeneratePassword(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		p := GeneratePassword()
		if len(p) != 16 {
			t.Fatalf("length = %d, want 16", len(p))
		}
		for _, r := range p {
			if !strings.ContainsRune(pwAlphabet, r) {
				t.Fatalf("password %q contains %q, which is not in the alphabet", p, r)
			}
		}
		seen[p] = true
	}
	if len(seen) != 200 {
		t.Errorf("%d distinct passwords out of 200", len(seen))
	}
}
