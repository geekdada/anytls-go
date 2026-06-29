package auth

import (
	"crypto/sha256"
	"encoding/hex"
)

// PasswordAuthenticator accepts a single shared password hash. It returns a
// stable synthetic id derived from the password hash so that all sessions for
// the same password collapse into a single stats bucket. The id never leaks
// the underlying password.
type PasswordAuthenticator struct {
	passwordSha256 []byte
	id             string
}

func NewPasswordAuthenticator(password string) *PasswordAuthenticator {
	sum := sha256.Sum256([]byte(password))
	hash := sum[:]
	// id is the first 8 bytes of sha256(passwordSha256) so it doesn't expose
	// the wire credential (which is sha256(password) itself).
	idSum := sha256.Sum256(hash)
	return &PasswordAuthenticator{
		passwordSha256: hash,
		id:             "pw-" + hex.EncodeToString(idSum[:8]),
	}
}

// PasswordHash exposes the 32-byte SHA256 the client must send in its
// handshake.
func (p *PasswordAuthenticator) PasswordHash() []byte {
	return p.passwordSha256
}

func (p *PasswordAuthenticator) Authenticate(addr, authBlob string, _ int64) (string, bool, error) {
	want := hex.EncodeToString(p.passwordSha256)
	if authBlob != want {
		return "", false, nil
	}
	return p.id, true, nil
}
