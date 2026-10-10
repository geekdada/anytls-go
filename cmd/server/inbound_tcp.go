package main

import (
	"anytls/limiter"
	"anytls/proxy/padding"
	"anytls/proxy/session"
	"anytls/stats"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"net"
	"runtime/debug"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
	"github.com/sirupsen/logrus"
)

// Variables so tests can shorten them.
var (
	// handshakeTimeout bounds the TLS handshake plus reading the auth packet,
	// so a client that connects and stays silent cannot hold a connection.
	handshakeTimeout = 10 * time.Second
	// requestTimeout bounds reading a new stream's target address (and the
	// UoT request), so idle streams cannot pile up on a session.
	requestTimeout = 10 * time.Second
)

func handleTcpConnection(ctx context.Context, c net.Conn, s *myServer) {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorln("[BUG]", r, string(debug.Stack()))
		}
	}()

	tlsConn := tls.Server(c, s.tlsConfig)
	c = tlsConn
	defer c.Close()
	_ = tlsConn.SetDeadline(time.Now().Add(handshakeTimeout))

	b := buf.NewPacket()
	defer b.Release()

	n, err := b.ReadOnceFrom(c)
	if err != nil {
		logrus.Debugln("ReadOnceFrom:", err)
		return
	}
	c = bufio.NewCachedConn(c, b)

	by, err := b.ReadBytes(32)
	if err != nil {
		b.Resize(0, n)
		fallback(ctx, c)
		return
	}
	id, ok, authErr := s.auth.Authenticate(c.RemoteAddr().String(), hex.EncodeToString(by), 0)
	if authErr != nil {
		logrus.Warnln("auth backend error from", c.RemoteAddr(), ":", authErr)
	}
	if !ok {
		b.Resize(0, n)
		fallback(ctx, c)
		return
	}

	by, err = b.ReadBytes(2)
	if err != nil {
		b.Resize(0, n)
		fallback(ctx, c)
		return
	}
	paddingLen := binary.BigEndian.Uint16(by)
	if paddingLen > 0 {
		_, err = b.ReadBytes(int(paddingLen))
		if err != nil {
			b.Resize(0, n)
			fallback(ctx, c)
			return
		}
	}

	_ = tlsConn.SetDeadline(time.Time{})

	var conn *stats.Conn
	if s.stats != nil {
		conn = s.stats.AcquireConn(id, c.RemoteAddr().String())
		defer s.stats.ReleaseConn(conn)
	}

	if s.limits != nil {
		dev := s.limits.Acquire(id, c.RemoteAddr().String())
		defer s.limits.Release(dev)
		c = limiter.WrapConn(c, dev)
	}

	// Declared first so the stream handler can reach sess.Identity.
	var sess *session.Session
	sess = session.NewServerSession(c, func(stream *session.Stream) {
		defer func() {
			if r := recover(); r != nil {
				logrus.Errorln("[BUG]", r, string(debug.Stack()))
			}
		}()
		defer stream.Close()

		_ = stream.SetReadDeadline(time.Now().Add(requestTimeout))
		destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err != nil {
			logrus.Debugln("ReadAddrPort:", err)
			return
		}

		if isUoT(destination) {
			// Hysteria traces only TCP streams in /dump/streams and counts
			// only the UDP payload in /traffic, so the UoT framing stays out
			// of the user's traffic. proxyOutboundUoT clears the deadline once
			// the UoT request is read.
			proxyOutboundUoT(ctx, stream, destination.Fqdn == uot.LegacyMagicAddress, sess.Identity, s.policy)
			return
		}

		stream.CountIdentity = true
		var st *stats.StreamStats
		if s.stats != nil {
			st = s.stats.TraceStream(id, conn.ID(), conn.NextStreamID())
			st.SetReqAddr(destination.String())
			stream.Counter = st
			defer s.stats.UntraceStream(st)
		}
		_ = stream.SetReadDeadline(time.Time{})
		proxyOutboundTCP(ctx, stream, destination, st, s.policy)
	}, &padding.DefaultPaddingFactory)

	if s.stats != nil {
		u := s.stats.Attach(id, c.RemoteAddr().String(), sess)
		sess.Identity = u
		defer s.stats.Detach(id, sess)
	}

	sess.Run()
	sess.Close()
}

// isUoT reports whether a stream's target is a sing UoT magic address (v2 or
// legacy v1) rather than a real TCP destination.
func isUoT(destination M.Socksaddr) bool {
	return destination.Fqdn == uot.MagicAddress || destination.Fqdn == uot.LegacyMagicAddress
}

func fallback(ctx context.Context, c net.Conn) {
	// 暂未实现
	logrus.Debugln("fallback:", c.RemoteAddr())
}
