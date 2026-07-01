package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
)

// PasswordAuthenticator accepts a single shared password hash. It returns a
// stable synthetic id derived from the password hash so that all sessions for
// the same password collapse into a single stats bucket. The id never leaks
// the underlying password.
type PasswordAuthenticator struct {
	passwordHex string
	id          string
}

func NewPasswordAuthenticator(password string) *PasswordAuthenticator {
	sum := sha256.Sum256([]byte(password))
	hash := sum[:]
	// id is the first 8 bytes of sha256(passwordSha256) so it doesn't expose
	// the wire credential (which is sha256(password) itself).
	idSum := sha256.Sum256(hash)
	return &PasswordAuthenticator{
		passwordHex: hex.EncodeToString(hash),
		id:          "pw-" + hex.EncodeToString(idSum[:8]),
	}
}

func (p *PasswordAuthenticator) Authenticate(addr, authBlob string, _ int64) (string, bool, error) {
	if len(authBlob) != len(p.passwordHex) {
		return "", false, nil
	}
	if subtle.ConstantTimeCompare([]byte(authBlob), []byte(p.passwordHex)) != 1 {
		return "", false, nil
	}
	return p.id, true, nil
}
