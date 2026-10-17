package outbound

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"anytls/outbound/outboundtest"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func TestSOCKS5DialTCP(t *testing.T) {
	echoAddr := startTCPEcho(t)
	echo := M.ParseSocksaddr(echoAddr)
	server := outboundtest.NewSOCKS5Server(t, "", "")

	conn, err := NewSOCKS5(server.Addr, "", "").DialTCP(context.Background(), echo)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	assertEcho(t, conn)

	destinations := server.ConnectDestinations()
	if len(destinations) != 1 || destinations[0] != echo.String() {
		t.Fatalf("got destinations %v, want [%s]", destinations, echo)
	}
}

func TestSOCKS5DialTCPSendsDomain(t *testing.T) {
	echoAddr := startTCPEcho(t)
	echoPort := M.ParseSocksaddr(echoAddr).Port
	server := outboundtest.NewSOCKS5Server(t, "", "")

	destination := M.ParseSocksaddrHostPort("localhost", echoPort)
	conn, err := NewSOCKS5(server.Addr, "", "").DialTCP(context.Background(), destination)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	assertEcho(t, conn)

	destinations := server.ConnectDestinations()
	want := fmt.Sprintf("localhost:%d", echoPort)
	if len(destinations) != 1 || destinations[0] != want {
		t.Fatalf("got destinations %v, want [%s]", destinations, want)
	}
}

func TestSOCKS5DialTCPAuth(t *testing.T) {
	echoAddr := startTCPEcho(t)
	echo := M.ParseSocksaddr(echoAddr)
	server := outboundtest.NewSOCKS5Server(t, "user", "pass")

	conn, err := NewSOCKS5(server.Addr, "user", "pass").DialTCP(context.Background(), echo)
	if err != nil {
		t.Fatal(err)
	}
	assertEcho(t, conn)
	conn.Close()

	_, err = NewSOCKS5(server.Addr, "user", "wrong").DialTCP(context.Background(), echo)
	if err == nil {
		t.Fatal("expected authentication error")
	}
}

func TestSOCKS5HandshakeTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case conn := <-accepted:
			_ = conn.Close()
		default:
		}
	})

	original := socks5HandshakeTimeout
	socks5HandshakeTimeout = 100 * time.Millisecond
	t.Cleanup(func() {
		socks5HandshakeTimeout = original
	})

	start := time.Now()
	_, err = NewSOCKS5(listener.Addr().String(), "", "").DialTCP(context.Background(), M.ParseSocksaddr("1.1.1.1:443"))
	if err == nil {
		t.Fatal("expected handshake timeout")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("handshake took %s, want under 2s", elapsed)
	}
}

func TestSOCKS5ListenUDPWithoutHeadroom(t *testing.T) {
	echoAddr := startUDPEcho(t)
	server := outboundtest.NewSOCKS5Server(t, "", "")

	packetConn, err := NewSOCKS5(server.Addr, "", "").ListenUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()

	packet := buf.NewSize(4)
	packet.WriteString("ping")
	if packet.Start() != 0 {
		t.Fatalf("Start() = %d, want 0", packet.Start())
	}
	err = packetConn.WritePacket(packet, M.ParseSocksaddr(echoAddr))
	if err != nil {
		t.Fatal(err)
	}

	response := buf.NewPacket()
	defer response.Release()
	_, err = packetConn.ReadPacket(response)
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Bytes()) != "ping" {
		t.Fatalf("got %q, want %q", response.Bytes(), "ping")
	}
}

func TestSOCKS5ListenUDPClosesWithControl(t *testing.T) {
	server := outboundtest.NewSOCKS5Server(t, "", "")

	packetConn, err := NewSOCKS5(server.Addr, "", "").ListenUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()

	server.DropControls()

	readErr := make(chan error, 1)
	go func() {
		buffer := buf.NewPacket()
		defer buffer.Release()
		_, err := packetConn.ReadPacket(buffer)
		readErr <- err
	}()
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("ReadPacket succeeded after control connection closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadPacket did not return after control connection closed")
	}
}

func TestRelayAddr(t *testing.T) {
	proxy := &net.TCPAddr{IP: net.ParseIP("10.0.0.9"), Port: 1080}

	if got := relayAddr(M.ParseSocksaddr("0.0.0.0:5000"), proxy).String(); got != "10.0.0.9:5000" {
		t.Fatalf("got %s, want 10.0.0.9:5000", got)
	}
	if got := relayAddr(M.ParseSocksaddr("[::]:5000"), proxy).String(); got != "10.0.0.9:5000" {
		t.Fatalf("got %s, want 10.0.0.9:5000", got)
	}
	if got := relayAddr(M.ParseSocksaddr("203.0.113.5:5000"), proxy).String(); got != "203.0.113.5:5000" {
		t.Fatalf("got %s, want 203.0.113.5:5000", got)
	}
}
