package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestPasswordAuthenticatorAcceptsHexHash(t *testing.T) {
	a := NewPasswordAuthenticator("hunter2")
	sum := sha256.Sum256([]byte("hunter2"))
	blob := hex.EncodeToString(sum[:])
	id, ok, err := a.Authenticate("1.2.3.4:5", blob, 0)
	if err != nil || !ok {
		t.Fatalf("auth failed: ok=%v err=%v", ok, err)
	}
	if !strings.HasPrefix(id, "pw-") {
		t.Fatalf("id %q missing pw- prefix", id)
	}

	id2, _, _ := a.Authenticate("9.9.9.9:9", blob, 0)
	if id != id2 {
		t.Fatalf("id should be stable across calls: %q vs %q", id, id2)
	}
}

func TestPasswordAuthenticatorRejectsBadHash(t *testing.T) {
	a := NewPasswordAuthenticator("hunter2")
	if _, ok, _ := a.Authenticate("x", "00", 0); ok {
		t.Fatal("expected rejection of wrong credential")
	}
}

func TestPasswordAuthenticatorIDDoesNotLeakHash(t *testing.T) {
	a := NewPasswordAuthenticator("hunter2")
	sum := sha256.Sum256([]byte("hunter2"))
	hex := hex.EncodeToString(sum[:])
	id, _, _ := a.Authenticate("x", hex, 0)
	if strings.Contains(id, hex[:8]) {
		t.Fatal("id leaks the password hash")
	}
}
