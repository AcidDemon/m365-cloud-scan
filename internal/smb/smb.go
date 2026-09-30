// Package smb manages the box's Samba shares and their accounts. smb.conf is
// static and ansible-managed with `config backend = registry`, so every share
// lives in the registry and is created through `net conf` at runtime: the web
// UI can add one without rewriting a file or reloading the service.
package smb

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/AcidDemon/m365-cloud-scan/internal/config"
	"github.com/AcidDemon/m365-cloud-scan/internal/store"
)

// Runner is the single OS-execution seam, so every command in this package is
// testable without touching a real Samba.
type Runner interface {
	Run(ctx context.Context, name string, args []string, stdin []byte) (stdout, stderr []byte, err error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// NewExecRunner returns the production Runner.
func NewExecRunner() Runner { return execRunner{} }

// unixUser is deliberately narrower than what useradd accepts: these names are
// minted by the UI, never by a human, and they end up on a command line.
var unixUser = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// Manager owns the share directories and the Samba registry.
type Manager struct {
	run  Runner
	root string
}

// New builds a Manager whose shares live under shareRoot.
func New(r Runner, shareRoot string) *Manager { return &Manager{run: r, root: shareRoot} }

// Runner exposes the exec seam, so a caller that has a Manager does not need a
// second Runner threaded through it for a neighbouring command.
func (m *Manager) Runner() Runner { return m.run }

// ShareDir is where a share's files land on disk.
func (m *Manager) ShareDir(name string) string { return filepath.Join(m.root, name) }

// exec runs one command and folds stderr into the error, which is otherwise
// just "exit status 1".
func (m *Manager) exec(ctx context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	stdout, stderr, err := m.run.Run(ctx, name, args, stdin)
	if err != nil {
		msg := strings.TrimSpace(string(bytes.TrimSpace(stderr)))
		if msg == "" {
			msg = strings.TrimSpace(string(bytes.TrimSpace(stdout)))
		}
		if msg != "" {
			return stdout, fmt.Errorf("%s: %v: %s", name, err, msg)
		}
		return stdout, fmt.Errorf("%s: %v", name, err)
	}
	return stdout, nil
}

func checkNames(share, user string) error {
	if share != "" {
		if err := store.ValidShareName(share); err != nil {
			return err
		}
	}
	if user != "" && !unixUser.MatchString(user) {
		return errors.New("use up to 31 characters: a lowercase letter, then lowercase letters, digits and hyphens")
	}
	return nil
}

// EnsureShare creates the directory and the registry entry, and updates both if
// they already exist.
func (m *Manager) EnsureShare(ctx context.Context, name, user string) error {
	if err := checkNames(name, user); err != nil {
		return err
	}
	dir := m.ShareDir(name)
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return err
	}
	// MkdirAll obeys the umask, and an existing directory keeps its old mode.
	if err := os.Chmod(dir, 0o770); err != nil {
		return err
	}
	if _, err := m.exec(ctx, "chown", []string{user, dir}, nil); err != nil {
		return err
	}
	if !m.shareExists(ctx, name) {
		if _, err := m.exec(ctx, "net", []string{"conf", "addshare", name, dir, "writeable=y", "guest_ok=n"}, nil); err != nil {
			return err
		}
	}
	for _, p := range [][2]string{
		{"valid users", user},
		{"create mask", "0660"},
		{"directory mask", "0770"},
		{"browseable", "yes"},
		{"veto files", "/.DS_Store/Thumbs.db/._*/"},
	} {
		if _, err := m.exec(ctx, "net", []string{"conf", "setparm", name, p[0], p[1]}, nil); err != nil {
			return err
		}
	}
	return nil
}

// sambaProtocol maps what the UI offers onto what `server min protocol` takes.
// Samba still calls SMB1 by its old name.
var sambaProtocol = map[string]string{"SMB1": "NT1", "SMB2": "SMB2", "SMB3": "SMB3"}

// ValidMinProtocol reports whether p is one of the three floors the box offers.
func ValidMinProtocol(p string) bool { _, ok := sambaProtocol[p]; return ok }

// SetGlobal writes the global registry parameters that the admin UI owns.
func (m *Manager) SetGlobal(ctx context.Context, minProtocol, serverName, workgroup string) error {
	proto, ok := sambaProtocol[minProtocol]
	if !ok {
		return errors.New("the minimum SMB protocol must be SMB1, SMB2 or SMB3")
	}
	if !config.ValidNetBIOSName(serverName) {
		return errors.New("the server name must be up to 15 letters, digits or hyphens")
	}
	if !config.ValidNetBIOSName(workgroup) {
		return errors.New("the workgroup must be up to 15 letters, digits or hyphens")
	}
	for _, p := range [][2]string{
		{"server min protocol", proto},
		{"netbios name", serverName},
		{"workgroup", workgroup},
	} {
		if _, err := m.exec(ctx, "net", []string{"conf", "setparm", "global", p[0], p[1]}, nil); err != nil {
			return err
		}
	}
	return nil
}

// shareExists asks the registry rather than matching net's error text, which is
// translated.
func (m *Manager) shareExists(ctx context.Context, name string) bool {
	_, _, err := m.run.Run(ctx, "net", []string{"conf", "showshare", name}, nil)
	return err == nil
}

// RemoveShare drops the registry entry and leaves the directory alone: deleting
// scans because someone removed a share is not recoverable, so the data is the
// caller's call.
func (m *Manager) RemoveShare(ctx context.Context, name string) error {
	if err := checkNames(name, ""); err != nil {
		return err
	}
	if !m.shareExists(ctx, name) {
		return nil
	}
	_, err := m.exec(ctx, "net", []string{"conf", "delshare", name}, nil)
	return err
}

// EnsureUser creates the system account behind a share and sets its Samba
// password.
func (m *Manager) EnsureUser(ctx context.Context, user, password string) error {
	if err := checkNames("", user); err != nil {
		return err
	}
	if err := ValidPassword(password); err != nil {
		return err
	}
	args := []string{"--system", "--no-create-home", "--shell", "/usr/sbin/nologin", user}
	if _, err := m.exec(ctx, "useradd", args, nil); err != nil && !alreadyExists(err) {
		return err
	}
	return m.smbpasswd(ctx, []string{"-a", "-s", user}, password)
}

// SetPassword rotates the Samba password of an existing account.
func (m *Manager) SetPassword(ctx context.Context, user, password string) error {
	if err := checkNames("", user); err != nil {
		return err
	}
	if err := ValidPassword(password); err != nil {
		return err
	}
	return m.smbpasswd(ctx, []string{"-s", user}, password)
}

// smbpasswd feeds the password twice on stdin. It must never be an argv
// element, where every user on the box would read it out of ps.
func (m *Manager) smbpasswd(ctx context.Context, args []string, password string) error {
	_, err := m.exec(ctx, "smbpasswd", args, []byte(password+"\n"+password+"\n"))
	return err
}

// minPassword is what an admin may type for a share. The generated one is
// longer.
const minPassword = 8

// ValidPassword checks a share password before it reaches smbpasswd, which
// reads it from stdin as one line.
func ValidPassword(p string) error {
	if len(p) < minPassword {
		return errors.New("the password must be at least 8 characters")
	}
	if strings.ContainsAny(p, "\n\r") {
		return errors.New("the password cannot contain a line break")
	}
	if strings.ContainsRune(p, 0) {
		return errors.New("the password cannot contain a null byte")
	}
	return nil
}

// RemoveUser deletes the Samba account and the system account. A half-created
// user must still be removable, so a missing one is not an error.
func (m *Manager) RemoveUser(ctx context.Context, user string) error {
	if err := checkNames("", user); err != nil {
		return err
	}
	m.run.Run(ctx, "smbpasswd", []string{"-x", user}, nil) // may not exist
	if _, err := m.exec(ctx, "userdel", []string{user}, nil); err != nil && !missing(err) {
		return err
	}
	return nil
}

// Status reports whether Samba is up and what it negotiates.
func (m *Manager) Status(ctx context.Context) (running bool, version, minProtocol string, err error) {
	out, _, _ := m.run.Run(ctx, "systemctl", []string{"is-active", "smbd"}, nil) // exits 3 when down
	running = strings.TrimSpace(string(out)) == "active"

	out, err = m.exec(ctx, "smbd", []string{"--version"}, nil)
	if err != nil {
		return running, "", "", err
	}
	version = strings.TrimPrefix(strings.TrimSpace(string(out)), "Version ")

	// testparm prints its banner on stderr, so stdout is the bare value.
	out, _ = m.exec(ctx, "testparm", []string{"-s", "--parameter-name", "server min protocol"}, nil)
	minProtocol = strings.TrimSpace(string(out))
	return running, version, minProtocol, nil
}

// alreadyExists covers useradd's "already exists" (exit 9) so a re-run is a
// no-op instead of a failure.
func alreadyExists(err error) bool {
	return exitCode(err) == 9 || strings.Contains(err.Error(), "already exists")
}

// missing covers userdel's "does not exist" (exit 6).
func missing(err error) bool {
	return exitCode(err) == 6 || strings.Contains(err.Error(), "does not exist")
}

func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// pwAlphabet drops the glyphs that get misread on a printer panel: l, o, I, O,
// 0 and 1.
const pwAlphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// GeneratePassword returns a 16-character password from an alphabet with no
// ambiguous glyphs, because a human retypes this one into an MFP panel.
func GeneratePassword() string {
	const n = 16
	out := make([]byte, n)
	buf := make([]byte, n)
	limit := byte(256 - 256%len(pwAlphabet)) // reject the tail that would bias the modulo
	for i := 0; i < n; {
		rand.Read(buf)
		for _, b := range buf {
			if b < limit {
				out[i] = pwAlphabet[b%byte(len(pwAlphabet))]
				if i++; i == n {
					break
				}
			}
		}
	}
	return string(out)
}
