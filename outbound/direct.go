package outbound

import (
	"context"
	"net"

	"anytls/proxy"

	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Direct dials destinations itself.
type Direct struct {
	dialer *net.Dialer
}

func NewDirect() *Direct {
	return &Direct{dialer: proxy.SystemDialer}
}

func (*Direct) RemoteResolve() bool {
	return false
}

func (d *Direct) DialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	return d.dialer.DialContext(ctx, "tcp", destination.String())
}

func (*Direct) ListenUDP(context.Context) (N.PacketConn, error) {
	conn, err := net.ListenPacket("udp", "")
	if err != nil {
		return nil, err
	}
	return bufio.NewPacketConn(conn), nil
}
