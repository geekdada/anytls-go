package main

import (
	"anytls/acl"
	"anytls/proxy"
	"anytls/stats"
	"context"
	"net"

	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sirupsen/logrus"
)

func proxyOutboundTCP(ctx context.Context, conn net.Conn, destination M.Socksaddr, st *stats.StreamStats, aclEngine *acl.Engine) error {
	dialAddr := destination
	if aclEngine != nil {
		var ok bool
		dialAddr, ok = aclTCPDialAddr(aclEngine, destination)
		if !ok {
			logrus.Debugln("proxyOutboundTCP ACL reject:", destination)
			err := E.Errors(errACLRejected, N.ReportHandshakeFailure(conn, errACLRejected))
			return err
		}
	}

	c, err := proxy.SystemDialer.DialContext(ctx, "tcp", dialAddr.String())
	if err != nil {
		logrus.Debugln("proxyOutboundTCP DialContext:", err)
		err = E.Errors(err, N.ReportHandshakeFailure(conn, err))
		return err
	}

	err = N.ReportHandshakeSuccess(conn)
	if err != nil {
		return err
	}
	if st != nil {
		st.SetState(stats.StreamStateEstablished)
	}

	return bufio.CopyConn(ctx, conn, c)
}

func proxyOutboundUoT(ctx context.Context, conn net.Conn, destination M.Socksaddr, st *stats.StreamStats, aclEngine *acl.Engine) error {
	request, err := uot.ReadRequest(conn)
	if err != nil {
		logrus.Debugln("proxyOutboundUoT ReadRequest:", err)
		return err
	}

	c, err := net.ListenPacket("udp", "")
	if err != nil {
		logrus.Debugln("proxyOutboundUoT ListenPacket:", err)
		err = E.Errors(err, N.ReportHandshakeFailure(conn, err))
		return err
	}

	err = N.ReportHandshakeSuccess(conn)
	if err != nil {
		return err
	}
	if st != nil {
		st.SetState(stats.StreamStateEstablished)
	}

	packetConn := N.PacketConn(bufio.NewPacketConn(c))
	if aclEngine != nil {
		packetConn = newACLPacketConn(packetConn, aclEngine)
	}

	return bufio.CopyPacketConn(ctx, uot.NewConn(conn, *request), packetConn)
}
