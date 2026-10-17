package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"anytls/auth"
	"anytls/outbound"
	"anytls/outbound/outboundtest"
	"anytls/proxy/padding"
	"anytls/resolver"
	"anytls/stats"
	"anytls/util"

	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

func shortenTimeouts(t *testing.T, d time.Duration) {
	t.Helper()
	oldHandshake, oldRequest := handshakeTimeout, requestTimeout
	handshakeTimeout, requestTimeout = d, d
	t.Cleanup(func() { handshakeTimeout, requestTimeout = oldHandshake, oldRequest })
}

func testServer(t *testing.T, password string) *myServer {
	t.Helper()
	cert, err := util.GenerateKeyPair(time.Now, "")
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{*cert}}
	return NewMyServer(tlsConfig, auth.NewPasswordAuthenticator(password), nil, nil, newOutboundPolicy(nil, nil, true, nil))
}

// serve runs handleTcpConnection on one end of a pipe and reports when it
// returns.
func serve(t *testing.T, s *myServer) (net.Conn, <-chan struct{}) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleTcpConnection(context.Background(), serverConn, s)
	}()
	return clientConn, done
}

func TestSilentClientIsDisconnected(t *testing.T) {
	shortenTimeouts(t, 100*time.Millisecond)
	_, done := serve(t, testServer(t, "pw"))

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler still running after the handshake deadline")
	}
}

func TestIdleStreamIsClosed(t *testing.T) {
	shortenTimeouts(t, 100*time.Millisecond)
	clientConn, _ := serve(t, testServer(t, "pw"))
	conn := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true})

	sum := sha256.Sum256([]byte("pw"))
	authPacket := append(sum[:], 0, 0) // no padding
	settings := []byte("v=1\npadding-md5=" + padding.DefaultPaddingFactory.Load().Md5)
	frames := [][]byte{
		authPacket,
		frameBytes(4, 0, settings), // cmdSettings
		frameBytes(1, 1, nil),      // cmdSYN, then no target address
	}
	for _, b := range frames {
		if _, err := conn.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	// The server must stay up past the handshake deadline and close the stream
	// once the request deadline passes.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var hdr [7]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		t.Fatalf("waiting for FIN: %v", err)
	}
	if hdr[0] != 3 || binary.BigEndian.Uint32(hdr[1:5]) != 1 {
		t.Fatalf("frame = cmd %d sid %d, want FIN for stream 1", hdr[0], binary.BigEndian.Uint32(hdr[1:5]))
	}
}

func TestTCPThroughSOCKS5(t *testing.T) {
	srv := outboundtest.NewSOCKS5Server(t, "u", "p")
	echo := tcpEcho(t)
	conn := openStream(t, stats.NewRegistry(), echo, []byte("ping"),
		newOutboundPolicy(nil, nil, false, outbound.NewSOCKS5(srv.Addr, "u", "p")))

	if got := readPSH(t, conn, 1); string(got) != "ping" {
		t.Fatalf("echo = %q, want ping", got)
	}
	if got := srv.ConnectDestinations(); !slices.Equal(got, []string{echo.String()}) {
		t.Fatalf("connect destinations = %v, want [%s]", got, echo)
	}
}

func TestUoTThroughSOCKS5(t *testing.T) {
	srv := outboundtest.NewSOCKS5Server(t, "u", "p")
	echo := udpEcho(t)
	conn := openStream(t, stats.NewRegistry(), uot.RequestDestination(uot.Version), uotBody(t, uot.Version, echo),
		newOutboundPolicy(nil, nil, false, outbound.NewSOCKS5(srv.Addr, "u", "p")))

	if got := readPSH(t, conn, 1); len(got) == 0 {
		t.Fatal("no echoed UoT packet")
	}
	if got := srv.PacketDestinations(); !slices.Contains(got, echo.String()) {
		t.Fatalf("packet destinations = %v, want to contain %s", got, echo)
	}
}

func TestTCPThroughLoopbackSOCKS5WithPrivateFilter(t *testing.T) {
	// The private filter checks destinations, not the proxy's own address,
	// so a SOCKS5 proxy on loopback still works with the filter on. The stub
	// resolver gives a public answer, and the proxy resolves localhost itself.
	srv := outboundtest.NewSOCKS5Server(t, "u", "p")
	target := M.ParseSocksaddrHostPort("localhost", tcpEcho(t).Port)
	res := &stubResolver{result: resolver.Result{IPv4: net.IPv4(1, 2, 3, 4).To4()}}
	conn := openStream(t, stats.NewRegistry(), target, []byte("ping"),
		newOutboundPolicy(nil, res, true, outbound.NewSOCKS5(srv.Addr, "u", "p")))

	if got := readPSH(t, conn, 1); string(got) != "ping" {
		t.Fatalf("echo = %q, want ping", got)
	}
	if got := srv.ConnectDestinations(); !slices.Equal(got, []string{target.String()}) {
		t.Fatalf("connect destinations = %v, want [%s]", got, target)
	}
}

func frameBytes(cmd byte, sid uint32, data []byte) []byte {
	b := make([]byte, 7+len(data))
	b[0] = cmd
	binary.BigEndian.PutUint32(b[1:5], sid)
	binary.BigEndian.PutUint16(b[5:7], uint16(len(data)))
	copy(b[7:], data)
	return b
}

func TestUoTStreamIsNotTraced(t *testing.T) {
	for _, version := range []uint8{uot.Version, uot.LegacyVersion} {
		t.Run(uot.RequestDestination(version).Fqdn, func(t *testing.T) {
			registry := stats.NewRegistry()
			conn := openStream(t, registry, uot.RequestDestination(version), uotBody(t, version, udpEcho(t)), newOutboundPolicy(nil, nil, false, nil))
			if got := readPSH(t, conn, 1); len(got) == 0 {
				t.Fatal("no echoed UoT packet")
			}

			// hysteria traces only TCP streams, so UDP must not show in /dump/streams.
			if rows := registry.DumpStreams(); len(rows) != 0 {
				t.Fatalf("DumpStreams = %+v, want none", rows)
			}
			// Like hysteria, /traffic counts only the UDP payload, without the
			// target address header or the per-packet UoT framing.
			waitTraffic(t, registry, stats.TrafficEntry{Tx: 4, Rx: 4})
		})
	}
}

func TestTCPTrafficExcludesTargetHeader(t *testing.T) {
	registry := stats.NewRegistry()
	conn := openStream(t, registry, tcpEcho(t), []byte("ping"), newOutboundPolicy(nil, nil, false, nil))
	if got := readPSH(t, conn, 1); string(got) != "ping" {
		t.Fatalf("echo = %q, want ping", got)
	}
	// Hysteria leaves the request header out of /traffic.
	waitTraffic(t, registry, stats.TrafficEntry{Tx: 4, Rx: 4})
}

// openStream authenticates to a server that reports to registry and uses
// policy, opens stream 1 to target and sends body on it.
func openStream(t *testing.T, registry *stats.Registry, target M.Socksaddr, body []byte, policy *outboundPolicy) net.Conn {
	t.Helper()
	s := testServer(t, "pw")
	s.stats = registry
	s.policy = policy
	clientConn, _ := serve(t, s)
	conn := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true})

	var payload bytes.Buffer
	if err := M.SocksaddrSerializer.WriteAddrPort(&payload, target); err != nil {
		t.Fatal(err)
	}
	payload.Write(body)
	sum := sha256.Sum256([]byte("pw"))
	settings := []byte("v=2\npadding-md5=" + padding.DefaultPaddingFactory.Load().Md5)
	frames := [][]byte{
		append(sum[:], 0, 0),
		frameBytes(4, 0, settings),        // cmdSettings
		frameBytes(1, 1, nil),             // cmdSYN
		frameBytes(2, 1, payload.Bytes()), // cmdPSH
	}
	// net.Pipe is unbuffered and a v2 server writes its settings frame while
	// the client is still writing.
	go func() {
		for _, b := range frames {
			if _, err := conn.Write(b); err != nil {
				return
			}
		}
	}()
	return conn
}

// uotBody is a UoT stream body of the given version carrying one "ping"
// packet to target.
func uotBody(t *testing.T, version uint8, target M.Socksaddr) []byte {
	t.Helper()
	var body bytes.Buffer
	if version == uot.Version {
		if err := uot.WriteRequest(&body, uot.Request{Destination: target}); err != nil {
			t.Fatal(err)
		}
	}
	if err := uot.AddrParser.WriteAddrPort(&body, target); err != nil {
		t.Fatal(err)
	}
	_ = binary.Write(&body, binary.BigEndian, uint16(4))
	body.WriteString("ping")
	return body.Bytes()
}

// waitTraffic waits until registry holds one user with traffic want. The
// server counts Rx after sending a frame, so the client can see the echo first.
func waitTraffic(t *testing.T, registry *stats.Registry, want stats.TrafficEntry) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		traffic := registry.Snapshot()
		if len(traffic) == 1 && onlyEntry(traffic) == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("traffic = %+v, want one user with %+v", traffic, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// readPSH returns the data of the first PSH frame on sid, skipping control frames.
func readPSH(t *testing.T, conn net.Conn, sid uint32) []byte {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		var hdr [7]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			t.Fatalf("waiting for PSH: %v", err)
		}
		data := make([]byte, binary.BigEndian.Uint16(hdr[5:7]))
		if _, err := io.ReadFull(conn, data); err != nil {
			t.Fatalf("reading frame data: %v", err)
		}
		if hdr[0] == 2 && binary.BigEndian.Uint32(hdr[1:5]) == sid {
			return data
		}
	}
}

func udpEcho(t *testing.T) M.Socksaddr {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(b[:n], addr)
		}
	}()
	return M.SocksaddrFromNet(pc.LocalAddr())
}

func onlyEntry(traffic map[string]stats.TrafficEntry) stats.TrafficEntry {
	for _, e := range traffic {
		return e
	}
	return stats.TrafficEntry{}
}

func tcpEcho(t *testing.T) M.Socksaddr {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return M.SocksaddrFromNet(l.Addr())
}
