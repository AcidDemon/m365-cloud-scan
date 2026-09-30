package scanui

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestPasswordAndToken(t *testing.T) {
	h, _ := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.DefaultCost)
	a := NewAuth(string(h), []byte("secret-key-32-bytes-long-xxxxxxx"), time.Hour)

	if !a.CheckPassword("hunter2") || a.CheckPassword("wrong") {
		t.Fatal("CheckPassword wrong")
	}
	now := time.Unix(1_700_000_000, 0)
	tok := a.IssueToken(now)
	if !a.ValidToken(tok, now.Add(30*time.Minute)) {
		t.Error("token should be valid within ttl")
	}
	if a.ValidToken(tok, now.Add(2*time.Hour)) {
		t.Error("token should be expired past ttl")
	}
	if a.ValidToken(tok+"x", now) {
		t.Error("tampered token must be rejected")
	}
}

func TestLockout(t *testing.T) {
	a := NewAuth("", []byte("k"), time.Hour)
	now := time.Unix(0, 0)
	for i := 0; i < 5; i++ {
		if !a.Allow("1.2.3.4", now) {
			t.Fatalf("should allow attempt %d", i)
		}
		a.RecordFailure("1.2.3.4", now)
	}
	if a.Allow("1.2.3.4", now) {
		t.Error("should be locked out after 5 failures")
	}
	if !a.Allow("1.2.3.4", now.Add(16*time.Minute)) {
		t.Error("lockout should expire after the window")
	}
}

func TestSetPasswordHash(t *testing.T) {
	h1, _ := bcrypt.GenerateFromPassword([]byte("old"), bcrypt.MinCost)
	a := NewAuth(string(h1), []byte("0123456789abcdef0123456789abcdef"), time.Hour)
	if !a.CheckPassword("old") {
		t.Fatal("old password should work initially")
	}
	h2, _ := bcrypt.GenerateFromPassword([]byte("newsecret"), bcrypt.MinCost)
	a.SetPasswordHash(string(h2))
	if a.CheckPassword("old") {
		t.Error("old password must be rejected after SetPasswordHash")
	}
	if !a.CheckPassword("newsecret") {
		t.Error("new password must work after SetPasswordHash")
	}
}
