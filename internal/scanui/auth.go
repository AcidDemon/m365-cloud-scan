package scanui

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	maxFailures   = 5
	lockoutWindow = 15 * time.Minute
)

// Auth verifies the admin password, mints/checks HMAC session tokens, and
// rate-limits failed logins per source IP.
type Auth struct {
	secret []byte
	ttl    time.Duration

	hmu  sync.RWMutex // guards hash (mutable via SetPasswordHash)
	hash string

	mu    sync.Mutex
	fails map[string]failState
}

type failState struct {
	count int
	until time.Time
}

// NewAuth builds an Auth from a bcrypt password hash, an HMAC session secret,
// and a session TTL.
func NewAuth(bcryptHash string, sessionSecret []byte, ttl time.Duration) *Auth {
	return &Auth{hash: bcryptHash, secret: sessionSecret, ttl: ttl, fails: map[string]failState{}}
}

// CheckPassword reports whether pw matches the current bcrypt hash.
func (a *Auth) CheckPassword(pw string) bool {
	a.hmu.RLock()
	h := a.hash
	a.hmu.RUnlock()
	return bcrypt.CompareHashAndPassword([]byte(h), []byte(pw)) == nil
}

// SetPasswordHash replaces the admin password hash (used by change-password).
func (a *Auth) SetPasswordHash(bcryptHash string) {
	a.hmu.Lock()
	a.hash = bcryptHash
	a.hmu.Unlock()
}

// IssueToken returns "<expiryUnix>.<base64(hmac)>" valid for ttl from now.
func (a *Auth) IssueToken(now time.Time) string {
	exp := strconv.FormatInt(now.Add(a.ttl).Unix(), 10)
	return exp + "." + a.sign(exp)
}

// ValidToken checks the signature and that the embedded expiry is in the future.
func (a *Auth) ValidToken(tok string, now time.Time) bool {
	exp, sig, ok := strings.Cut(tok, ".")
	if !ok {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(sig), []byte(a.sign(exp))) != 1 {
		return false
	}
	n, err := strconv.ParseInt(exp, 10, 64)
	return err == nil && now.Unix() < n
}

func (a *Auth) sign(msg string) string {
	m := hmac.New(sha256.New, a.secret)
	m.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Allow reports whether ip may attempt a login now (not currently locked out).
func (a *Auth) Allow(ip string, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.fails[ip]
	if s.count >= maxFailures && now.Before(s.until) {
		return false
	}
	if s.count >= maxFailures && !now.Before(s.until) {
		delete(a.fails, ip) // window elapsed; reset
	}
	return true
}

// RecordFailure increments the failure counter and (re)arms the lockout window.
// Must be called only after Allow returned true; calling after Allow returned false
// will slide the lockout window indefinitely.
func (a *Auth) RecordFailure(ip string, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.fails[ip]
	s.count++
	s.until = now.Add(lockoutWindow)
	a.fails[ip] = s
}

// Reset clears the failure counter for ip (after a successful login).
func (a *Auth) Reset(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.fails, ip)
}
