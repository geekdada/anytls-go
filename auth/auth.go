package auth

// Authenticator validates a client at handshake time and returns the stable
// per-user id that the traffic-stats API will key on.
//
// addr is the client's remote network address (host:port).
// authBlob is the credential the client sent on the wire, encoded as hex.
// tx is the server-observed transmit rate hint in bytes/sec (0 if unknown).
//
// ok=false means the credential is invalid (reject the connection).
// A non-nil err signals an infrastructure failure (e.g. backend down); the
// caller should treat it as an authentication failure but may log it
// separately.
type Authenticator interface {
	Authenticate(addr, authBlob string, tx int64) (id string, ok bool, err error)
}
