// Package outboundtest provides test helpers for the outbound package.
package outboundtest

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

// SOCKS5Server is a minimal SOCKS5 proxy that relays every request, so tests
// can observe what an outbound sends and control when a session dies.
type SOCKS5Server struct {
	Addr string

	authenticator *auth.Authenticator
	listener      net.Listener

	mu                 sync.Mutex
	conns              []net.Conn
	destinations       []string
	packetDestinations []string
}

func NewSOCKS5Server(t testing.TB, username, password string) *SOCKS5Server {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var users []auth.User
	if username != "" {
		users = []auth.User{{Username: username, Password: password}}
	}
	server := &SOCKS5Server{
		Addr:          listener.Addr().String(),
		authenticator: auth.NewAuthenticator(users),
		listener:      listener,
	}
	ctx, cancel := context.WithCancel(context.Background())
	go server.serve(ctx)
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		server.DropControls()
	})
	return server
}

func (s *SOCKS5Server) serve(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, conn)
		s.mu.Unlock()
		go func() {
			_ = socks.HandleConnection(ctx, conn, s.authenticator, s, M.Metadata{})
			_ = conn.Close()
		}()
	}
}

// ConnectDestinations returns the CONNECT targets seen so far, in order.
func (s *SOCKS5Server) ConnectDestinations() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.destinations...)
}

// PacketDestinations returns the UDP destinations seen so far, in order.
func (s *SOCKS5Server) PacketDestinations() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.packetDestinations...)
}

// DropControls closes every accepted TCP connection, ending the SOCKS
// sessions and the UDP associations that depend on them.
func (s *SOCKS5Server) DropControls() {
	s.mu.Lock()
	conns := s.conns
	s.conns = nil
	s.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func (s *SOCKS5Server) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	destination := metadata.Destination.String()
	s.mu.Lock()
	s.destinations = append(s.destinations, destination)
	s.mu.Unlock()

	remote, err := net.Dial("tcp", destination)
	if err != nil {
		return err
	}
	defer remote.Close()
	return bufio.CopyConn(ctx, conn, remote)
}

func (s *SOCKS5Server) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	remote, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	packetConn := bufio.NewPacketConn(remote)
	defer packetConn.Close()
	return bufio.CopyPacketConn(ctx, &recordingPacketConn{PacketConn: conn, server: s}, packetConn)
}

// recordingPacketConn records the destinations the SOCKS5 client asks the
// proxy to forward, so tests can tell a proxied path from a direct one.
type recordingPacketConn struct {
	N.PacketConn
	server *SOCKS5Server
}

func (c *recordingPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, err := c.PacketConn.ReadPacket(buffer)
	if err == nil {
		c.server.mu.Lock()
		c.server.packetDestinations = append(c.server.packetDestinations, destination.String())
		c.server.mu.Unlock()
	}
	return destination, err
}

// Upstream lets headroom and MTU calculations see the wrapped conn; without it
// the relay reserves no room for the SOCKS5 UDP header.
func (c *recordingPacketConn) Upstream() any {
	return c.PacketConn
}
