package outbound

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"anytls/proxy"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks5"
	"github.com/sirupsen/logrus"
)

// socks5HandshakeTimeout bounds the whole SOCKS5 handshake. It is a variable
// so tests can shorten it.
var socks5HandshakeTimeout = 10 * time.Second

// SOCKS5 sends every stream to a SOCKS5 proxy and leaves name resolution to it.
type SOCKS5 struct {
	addr     string
	username string
	password string
	dialer   *net.Dialer
}

func NewSOCKS5(addr, username, password string) *SOCKS5 {
	return &SOCKS5{
		addr:     addr,
		username: username,
		password: password,
		dialer:   proxy.SystemDialer,
	}
}

func (*SOCKS5) RemoteResolve() bool {
	return true
}

func (s *SOCKS5) DialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, _, err := s.handshake(ctx, socks5.CommandConnect, destination)
	return conn, err
}

func (s *SOCKS5) ListenUDP(ctx context.Context) (N.PacketConn, error) {
	control, response, err := s.handshake(ctx, socks5.CommandUDPAssociate, M.SocksaddrFrom(netip.IPv4Unspecified(), 0))
	if err != nil {
		return nil, err
	}
	relay := relayAddr(response.Bind, control.RemoteAddr())
	udpConn, err := s.dialer.DialContext(ctx, "udp", relay.String())
	if err != nil {
		control.Close()
		err = fmt.Errorf("socks5 %s: relay %s: %w", s.addr, relay, err)
		s.logFailure(ctx, socks5.CommandUDPAssociate, socks5.Response{}, err)
		return nil, err
	}
	return newSOCKS5PacketConn(socks.NewAssociatePacketConn(udpConn, M.Socksaddr{}, control), control), nil
}

func (s *SOCKS5) handshake(ctx context.Context, command byte, destination M.Socksaddr) (net.Conn, socks5.Response, error) {
	conn, response, err := s.negotiate(ctx, command, destination)
	if err != nil {
		err = fmt.Errorf("socks5 %s: %w", s.addr, err)
		s.logFailure(ctx, command, response, err)
		return nil, socks5.Response{}, err
	}
	return conn, response, nil
}

// negotiate dials the proxy and runs one SOCKS5 request on the connection. On
// failure it still returns the proxy's reply, so the caller can tell a refused
// request from a broken proxy.
func (s *SOCKS5) negotiate(ctx context.Context, command byte, destination M.Socksaddr) (net.Conn, socks5.Response, error) {
	conn, err := s.dialer.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return nil, socks5.Response{}, err
	}
	response, err := s.clientHandshake(conn, command, destination)
	if err != nil {
		conn.Close()
		return nil, response, err
	}
	return conn, response, nil
}

func (s *SOCKS5) clientHandshake(conn net.Conn, command byte, destination M.Socksaddr) (socks5.Response, error) {
	err := conn.SetDeadline(time.Now().Add(socks5HandshakeTimeout))
	if err != nil {
		return socks5.Response{}, err
	}
	response, err := socks.ClientHandshake5(conn, command, destination, s.username, s.password)
	if err != nil {
		return response, err
	}
	return response, conn.SetDeadline(time.Time{})
}

// logFailure warns when the proxy itself is at fault: it cannot be dialed, the
// handshake or authentication fails or times out, or it refuses UDP ASSOCIATE.
// The operator has to fix those, and at debug level they would go unnoticed.
// A reply code refusing a CONNECT reports the destination, as a failed direct
// dial would, and a canceled context means the client went away, so both stay
// at debug. err never carries the credentials.
func (s *SOCKS5) logFailure(ctx context.Context, command byte, response socks5.Response, err error) {
	refusedConnect := command == socks5.CommandConnect && response.ReplyCode != socks5.ReplyCodeSuccess
	if refusedConnect || ctx.Err() != nil {
		logrus.Debugln("[Outbound]", err)
		return
	}
	logrus.Warnln("[Outbound]", err)
}

// relayAddr replaces an unspecified bind address with the address the proxy
// was dialed at, which is the only one the client can reach.
func relayAddr(bind M.Socksaddr, proxy net.Addr) M.Socksaddr {
	if bind.Addr.IsUnspecified() {
		return M.SocksaddrFrom(M.AddrFromNet(proxy).Unmap(), bind.Port)
	}
	return bind
}

type socks5PacketConn struct {
	*socks.AssociatePacketConn
	control net.Conn
}

func newSOCKS5PacketConn(conn *socks.AssociatePacketConn, control net.Conn) *socks5PacketConn {
	packetConn := &socks5PacketConn{AssociatePacketConn: conn, control: control}
	go packetConn.hold()
	return packetConn
}

// hold closes the association once the control connection ends, so a dead
// proxy does not leave the UDP socket open.
func (c *socks5PacketConn) hold() {
	_, err := io.Copy(io.Discard, c.control)
	if err != nil {
		logrus.Debugln("socks5 outbound control connection:", err)
	}
	c.Close()
}

func (c *socks5PacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	headroom := 3 + M.SocksaddrSerializer.AddrPortLen(destination)
	if buffer.Start() < headroom {
		buffer = bufferWithHeadroom(buffer, headroom)
	}
	return c.AssociatePacketConn.WritePacket(buffer, destination)
}

// bufferWithHeadroom copies buffer into a new buffer that has the given
// headroom, because AssociatePacketConn writes the SOCKS5 header there in
// place.
func bufferWithHeadroom(buffer *buf.Buffer, headroom int) *buf.Buffer {
	newBuffer := buf.NewSize(headroom + buffer.Len())
	newBuffer.Extend(headroom)
	common.Must1(newBuffer.Write(buffer.Bytes()))
	newBuffer.Advance(headroom)
	buffer.Release()
	return newBuffer
}
