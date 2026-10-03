package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"anytls/auth"
	"anytls/proxy/padding"
	"anytls/util"
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
	return NewMyServer(tlsConfig, auth.NewPasswordAuthenticator(password), nil, nil, nil, nil, true)
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

func frameBytes(cmd byte, sid uint32, data []byte) []byte {
	b := make([]byte, 7+len(data))
	b[0] = cmd
	binary.BigEndian.PutUint32(b[1:5], sid)
	binary.BigEndian.PutUint16(b[5:7], uint16(len(data)))
	copy(b[7:], data)
	return b
}
