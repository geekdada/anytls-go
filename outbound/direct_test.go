package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func TestDirectDialTCP(t *testing.T) {
	echoAddr := startTCPEcho(t)
	conn, err := NewDirect().DialTCP(context.Background(), M.ParseSocksaddr(echoAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	assertEcho(t, conn)
}

func TestDirectListenUDP(t *testing.T) {
	echoAddr := startUDPEcho(t)
	packetConn, err := NewDirect().ListenUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer packetConn.Close()

	packet := buf.NewPacket()
	packet.WriteString("ping")
	err = packetConn.WritePacket(packet, M.ParseSocksaddr(echoAddr))
	if err != nil {
		t.Fatal(err)
	}

	response := buf.NewPacket()
	defer response.Release()
	source, err := packetConn.ReadPacket(response)
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Bytes()) != "ping" {
		t.Fatalf("got %q, want %q", response.Bytes(), "ping")
	}
	if source.String() != echoAddr {
		t.Fatalf("got source %s, want %s", source, echoAddr)
	}
}

func TestRejectRefuses(t *testing.T) {
	ctx := context.Background()
	_, err := Reject{}.DialTCP(ctx, M.ParseSocksaddr("1.1.1.1:443"))
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("DialTCP error = %v, want ErrRejected", err)
	}
	_, err = Reject{}.ListenUDP(ctx)
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("ListenUDP error = %v, want ErrRejected", err)
	}
}

func assertEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 4)
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if string(response) != "ping" {
		t.Fatalf("got %q, want %q", response, "ping")
	}
}

func startTCPEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

func startUDPEcho(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})
	go func() {
		packet := make([]byte, 65535)
		for {
			n, addr, err := conn.ReadFrom(packet)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(packet[:n], addr)
		}
	}()
	return conn.LocalAddr().String()
}
