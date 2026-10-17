// Package outbound dials destinations for server-side streams.
package outbound

import (
	"context"
	"errors"
	"net"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Outbound interface {
	DialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	// ListenUDP returns one socket per UoT stream.
	ListenUDP(ctx context.Context) (N.PacketConn, error)
	// RemoteResolve reports whether domains must be passed through
	// unresolved so the outbound can resolve them.
	RemoteResolve() bool
}

var ErrRejected = errors.New("rejected by ACL")

// Reject refuses every request.
type Reject struct{}

func (Reject) DialTCP(context.Context, M.Socksaddr) (net.Conn, error) {
	return nil, ErrRejected
}

func (Reject) ListenUDP(context.Context) (N.PacketConn, error) {
	return nil, ErrRejected
}

func (Reject) RemoteResolve() bool {
	return false
}

var (
	_ Outbound = (*Direct)(nil)
	_ Outbound = Reject{}
	_ Outbound = (*SOCKS5)(nil)
)
