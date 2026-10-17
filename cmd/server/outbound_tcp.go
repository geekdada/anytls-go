package main

import (
	"anytls/acl"
	"anytls/proxy/session"
	"anytls/resolver"
	"anytls/stats"
	"context"
	"errors"
	"net"
	"time"

	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sirupsen/logrus"
)

var (
	errClientBlocked       = errors.New("blocked by server policy")
	errClientResolveFailed = errors.New("resolve failed")
	errClientDialFailed    = errors.New("dial failed")
)

// clientError maps an outbound failure to the message sent back to the client.
// The full error goes to the server log only, because it can name the
// resolver and internal addresses.
func clientError(err error) error {
	var resolveErr resolver.Error
	switch {
	case errors.Is(err, errACLRejected), errors.Is(err, errPrivateDestination):
		return errClientBlocked
	case errors.As(err, &resolveErr):
		return errClientResolveFailed
	default:
		return errClientDialFailed
	}
}

func proxyOutboundTCP(ctx context.Context, conn net.Conn, destination M.Socksaddr, st *stats.StreamStats, policy *outboundPolicy) error {
	r, err := policy.selectRoute(ctx, destination, acl.ProtocolTCP)
	if err != nil {
		logrus.Debugln("proxyOutboundTCP:", destination, err)
		return E.Errors(err, N.ReportHandshakeFailure(conn, clientError(err)))
	}

	c, err := r.outbound.DialTCP(ctx, r.target)
	if err != nil {
		logrus.Debugln("proxyOutboundTCP DialTCP:", err)
		err = E.Errors(err, N.ReportHandshakeFailure(conn, clientError(err)))
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

// proxyOutboundUoT relays a UoT stream. A non-nil counter receives the UDP
// payload bytes, the way hysteria counts UDP traffic.
func proxyOutboundUoT(ctx context.Context, conn net.Conn, legacy bool, counter session.TrafficCounter, policy *outboundPolicy) error {
	// Legacy v1 has no request header. Every packet carries its own address.
	request := &uot.Request{}
	if !legacy {
		var err error
		request, err = uot.ReadRequest(conn)
		if err != nil {
			logrus.Debugln("proxyOutboundUoT ReadRequest:", err)
			return err
		}
	}
	_ = conn.SetReadDeadline(time.Time{})

	c, err := net.ListenPacket("udp", "")
	if err != nil {
		logrus.Debugln("proxyOutboundUoT ListenPacket:", err)
		err = E.Errors(err, N.ReportHandshakeFailure(conn, clientError(err)))
		return err
	}

	err = N.ReportHandshakeSuccess(conn)
	if err != nil {
		return err
	}

	packetConn := newPolicyPacketConn(ctx, bufio.NewPacketConn(c), policy)

	uotConn := N.PacketConn(uot.NewConn(conn, *request))
	if counter != nil {
		uotConn = bufio.NewCounterPacketConn(uotConn,
			[]N.CountFunc{func(n int64) { counter.AddTx(n) }},
			[]N.CountFunc{func(n int64) { counter.AddRx(n) }})
	}
	return bufio.CopyPacketConn(ctx, uotConn, packetConn)
}
