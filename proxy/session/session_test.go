package session

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"anytls/proxy/padding"
)

func encodeFrame(cmd byte, sid uint32, data []byte) []byte {
	b := make([]byte, headerOverHeadSize+len(data))
	b[0] = cmd
	binary.BigEndian.PutUint32(b[1:5], sid)
	binary.BigEndian.PutUint16(b[5:7], uint16(len(data)))
	copy(b[headerOverHeadSize:], data)
	return b
}

type testFrame struct {
	cmd  byte
	sid  uint32
	data []byte
}

// frameReader decodes the frames a server session writes to the peer end of a
// net.Pipe.
func frameReader(t *testing.T, conn net.Conn) <-chan testFrame {
	t.Helper()
	frames := make(chan testFrame, 4096)
	go func() {
		defer close(frames)
		var hdr rawHeader
		for {
			if _, err := io.ReadFull(conn, hdr[:]); err != nil {
				return
			}
			data := make([]byte, hdr.Length())
			if _, err := io.ReadFull(conn, data); err != nil {
				return
			}
			frames <- testFrame{cmd: hdr.Cmd(), sid: hdr.StreamID(), data: data}
		}
	}()
	return frames
}

func waitFrame(t *testing.T, frames <-chan testFrame, cmd byte) testFrame {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case f, ok := <-frames:
			if !ok {
				t.Fatalf("connection closed while waiting for cmd %d", cmd)
			}
			if f.cmd == cmd {
				return f
			}
		case <-timeout:
			t.Fatalf("timed out waiting for cmd %d", cmd)
		}
	}
}

// startServerSession runs a server session whose stream handler blocks until
// the test ends, so every opened stream stays open.
func startServerSession(t *testing.T, clientVersion string) (net.Conn, <-chan testFrame) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	release := make(chan struct{})
	sess := NewServerSession(serverConn, func(*Stream) { <-release }, &padding.DefaultPaddingFactory)
	go sess.Run()
	t.Cleanup(func() {
		close(release)
		sess.Close()
		clientConn.Close()
	})
	frames := frameReader(t, clientConn)
	settings := "v=" + clientVersion + "\npadding-md5=" + padding.DefaultPaddingFactory.Load().Md5
	writeFrame(t, clientConn, encodeFrame(cmdSettings, 0, []byte(settings)))
	return clientConn, frames
}

func writeFrame(t *testing.T, conn net.Conn, b []byte) {
	t.Helper()
	if _, err := conn.Write(b); err != nil {
		t.Fatal(err)
	}
}

func openStreams(t *testing.T, conn net.Conn, count int) {
	t.Helper()
	for sid := 1; sid <= count; sid++ {
		writeFrame(t, conn, encodeFrame(cmdSYN, uint32(sid), nil))
	}
}

func TestServerRefusesStreamsOverCapV1(t *testing.T) {
	conn, frames := startServerSession(t, "1")
	openStreams(t, conn, maxServerStreams+1)

	f := waitFrame(t, frames, cmdFIN)
	if f.sid != maxServerStreams+1 {
		t.Fatalf("FIN for stream %d, want %d", f.sid, maxServerStreams+1)
	}
}

func TestServerRefusesStreamsOverCapV2(t *testing.T) {
	conn, frames := startServerSession(t, "2")
	waitFrame(t, frames, cmdServerSettings)
	openStreams(t, conn, maxServerStreams+1)

	f := waitFrame(t, frames, cmdSYNACK)
	if f.sid != maxServerStreams+1 || len(f.data) == 0 {
		t.Fatalf("SYNACK = (sid %d, %q), want an error for stream %d", f.sid, f.data, maxServerStreams+1)
	}
}

func TestWriteSplitsOversizedPayload(t *testing.T) {
	serverConn, peer := net.Pipe()
	defer peer.Close()
	sess := NewServerSession(serverConn, nil, &padding.DefaultPaddingFactory)
	defer sess.Close()
	frames := frameReader(t, peer)

	payload := make([]byte, maxFramePayload*2+10)
	stream := newStream(1, sess)
	n, err := stream.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(payload))
	}

	var sizes []int
	for range 3 {
		sizes = append(sizes, len(waitFrame(t, frames, cmdPSH).data))
	}
	if sizes[0] != maxFramePayload || sizes[1] != maxFramePayload || sizes[2] != 10 {
		t.Fatalf("frame sizes = %v, want [%d %d 10]", sizes, maxFramePayload, maxFramePayload)
	}
}

// Run with -race: Write reads dieErr while closeLocally stores it.
func TestStreamCloseConcurrentWithWrite(t *testing.T) {
	serverConn, peer := net.Pipe()
	defer peer.Close()
	go io.Copy(io.Discard, peer)
	sess := NewServerSession(serverConn, nil, &padding.DefaultPaddingFactory)
	defer sess.Close()

	stream := newStream(1, sess)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			stream.Write([]byte("x"))
		}
	}()
	stream.closeLocally()
	<-done
	if _, err := stream.Write([]byte("x")); err == nil {
		t.Fatal("Write after close succeeded, want an error")
	}
}
