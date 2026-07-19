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
	"strings"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sirupsen/logrus"
)

func handleTcpConnection(ctx context.Context, c net.Conn, s *myServer) {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorln("[BUG]", r, string(debug.Stack()))
		}
	}()

	c = tls.Server(c, s.tlsConfig)
	defer c.Close()

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

	sess := session.NewServerSession(c, func(stream *session.Stream) {
		defer func() {
			if r := recover(); r != nil {
				logrus.Errorln("[BUG]", r, string(debug.Stack()))
			}
		}()
		defer stream.Close()

		destination, err := M.SocksaddrSerializer.ReadAddrPort(stream)
		if err != nil {
			logrus.Debugln("ReadAddrPort:", err)
			return
		}

		var st *stats.StreamStats
		if s.stats != nil {
			st = s.stats.TraceStream(id, conn.ID(), conn.NextStreamID())
			st.SetReqAddr(destination.String())
			stream.Counter = st
			defer s.stats.UntraceStream(st)
		}

		if strings.Contains(destination.String(), "udp-over-tcp.arpa") {
			proxyOutboundUoT(ctx, stream, destination, st, s.acl)
		} else {
			proxyOutboundTCP(ctx, stream, destination, st, s.acl)
		}
	}, &padding.DefaultPaddingFactory)

	if s.stats != nil {
		u := s.stats.Attach(id, c.RemoteAddr().String(), sess)
		sess.Identity = u
		defer s.stats.Detach(id, sess)
	}

	sess.Run()
	sess.Close()
}

func fallback(ctx context.Context, c net.Conn) {
	// 暂未实现
	logrus.Debugln("fallback:", c.RemoteAddr())
}
