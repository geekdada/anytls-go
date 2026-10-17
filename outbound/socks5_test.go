package outbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"anytls/outbound/outboundtest"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/protocol/socks/socks5"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
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

	logs := captureWarnings(t)
	result := make(chan error, 1)
	go func() {
		_, err := NewSOCKS5(listener.Addr().String(), "", "").DialTCP(context.Background(), M.ParseSocksaddr("1.1.1.1:443"))
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("err = %v, want os.ErrDeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handshake did not time out within 2s")
	}
	logs.requireWarning(t, listener.Addr().String())
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

// warningLog collects the warnings the standard logger emits during a test.
type warningLog struct {
	hook *logtest.Hook
}

func captureWarnings(t *testing.T) warningLog {
	t.Helper()
	hook := logtest.NewGlobal()
	t.Cleanup(func() {
		logrus.StandardLogger().ReplaceHooks(make(logrus.LevelHooks))
	})
	return warningLog{hook}
}

func (l warningLog) warnings() []string {
	var messages []string
	for _, entry := range l.hook.AllEntries() {
		if entry.Level <= logrus.WarnLevel {
			messages = append(messages, entry.Message)
		}
	}
	return messages
}

// requireWarning fails unless exactly one warning was logged and it names
// the proxy address.
func (l warningLog) requireWarning(t *testing.T, proxyAddr string) string {
	t.Helper()
	messages := l.warnings()
	if len(messages) != 1 || !strings.Contains(messages[0], proxyAddr) {
		t.Fatalf("warnings = %q, want one naming %s", messages, proxyAddr)
	}
	return messages[0]
}

func (l warningLog) requireNone(t *testing.T) {
	t.Helper()
	if messages := l.warnings(); len(messages) != 0 {
		t.Fatalf("warnings = %q, want none", messages)
	}
}

func TestSOCKS5DialFailureWarns(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()

	logs := captureWarnings(t)
	if _, err := NewSOCKS5(addr, "", "").DialTCP(context.Background(), M.ParseSocksaddr("1.1.1.1:443")); err == nil {
		t.Fatal("expected a dial error")
	}
	logs.requireWarning(t, addr)
}

func TestSOCKS5AuthFailureWarnsWithoutCredentials(t *testing.T) {
	server := outboundtest.NewSOCKS5Server(t, "user", "pass")

	logs := captureWarnings(t)
	_, err := NewSOCKS5(server.Addr, "someuser", "secretpw").DialTCP(context.Background(), M.ParseSocksaddr("1.1.1.1:443"))
	if err == nil {
		t.Fatal("expected an authentication error")
	}
	message := logs.requireWarning(t, server.Addr)
	if strings.Contains(message, "someuser") || strings.Contains(message, "secretpw") {
		t.Fatalf("warning %q leaks credentials", message)
	}
}

func TestSOCKS5ConnectRefusedByProxyStaysDebug(t *testing.T) {
	addr := startRefusingSOCKS5(t, socks5.ReplyCodeConnectionRefused)

	logs := captureWarnings(t)
	if _, err := NewSOCKS5(addr, "", "").DialTCP(context.Background(), M.ParseSocksaddr("1.1.1.1:443")); err == nil {
		t.Fatal("expected the CONNECT to be refused")
	}
	logs.requireNone(t)
}

func TestSOCKS5AssociateRefusedWarns(t *testing.T) {
	addr := startRefusingSOCKS5(t, socks5.ReplyCodeUnsupported)

	logs := captureWarnings(t)
	if _, err := NewSOCKS5(addr, "", "").ListenUDP(context.Background()); err == nil {
		t.Fatal("expected UDP ASSOCIATE to be refused")
	}
	logs.requireWarning(t, addr)
}

func TestSOCKS5CanceledDialStaysDebug(t *testing.T) {
	server := outboundtest.NewSOCKS5Server(t, "", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	logs := captureWarnings(t)
	if _, err := NewSOCKS5(server.Addr, "", "").DialTCP(ctx, M.ParseSocksaddr("1.1.1.1:443")); err == nil {
		t.Fatal("expected a canceled dial to fail")
	}
	logs.requireNone(t)
}

// startRefusingSOCKS5 runs a SOCKS5 proxy that needs no authentication and
// answers every request with replyCode.
func startRefusingSOCKS5(t *testing.T, replyCode byte) string {
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
			go refuseSOCKS5(conn, replyCode)
		}
	}()
	return listener.Addr().String()
}

func refuseSOCKS5(conn net.Conn, replyCode byte) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	if _, err := socks5.ReadAuthRequest(reader); err != nil {
		return
	}
	if err := socks5.WriteAuthResponse(conn, socks5.AuthResponse{Method: socks5.AuthTypeNotRequired}); err != nil {
		return
	}
	if _, err := socks5.ReadRequest(reader); err != nil {
		return
	}
	_ = socks5.WriteResponse(conn, socks5.Response{ReplyCode: replyCode, Bind: M.ParseSocksaddr("0.0.0.0:0")})
}
