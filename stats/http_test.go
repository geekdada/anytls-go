package stats

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestHandler(t *testing.T) (http.Handler, *Registry, *fakeSession, *fakeSession) {
	t.Helper()
	r := NewRegistry()
	a := &fakeSession{}
	b := &fakeSession{}
	r.Attach("alice", "1.1.1.1:1", a).AddTx(100)
	r.Attach("alice", "1.1.1.1:1", a)
	r.Attach("bob", "2.2.2.2:2", b)
	h := NewHandler(ServerOptions{Secret: "s3cr3t", Registry: r})
	return h, r, a, b
}

func TestHTTPAuthRequired(t *testing.T) {
	h, _, _, _ := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/traffic", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestHTTPTraffic(t *testing.T) {
	h, _, _, _ := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/traffic", nil)
	req.Header.Set("Authorization", "s3cr3t")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var got map[string]TrafficEntry
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["alice"].Tx != 100 {
		t.Fatalf("alice.tx = %d", got["alice"].Tx)
	}
	if _, ok := got["bob"]; !ok {
		t.Fatal("bob missing")
	}
}

func TestHTTPOnline(t *testing.T) {
	h, _, _, _ := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/online", nil)
	req.Header.Set("Authorization", "s3cr3t")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var got map[string]int
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["alice"] != 1 || got["bob"] != 1 {
		t.Fatalf("online = %#v", got)
	}
}

func TestHTTPKick(t *testing.T) {
	h, _, a, b := newTestHandler(t)
	body := strings.NewReader(`["alice"]`)
	req := httptest.NewRequest(http.MethodPost, "/kick", body)
	req.Header.Set("Authorization", "s3cr3t")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		buf, _ := io.ReadAll(rec.Body)
		t.Fatalf("status = %d body = %s", rec.Code, buf)
	}
	if !waitClosed(a) {
		t.Fatal("alice not closed")
	}
	if b.closed.Load() {
		t.Fatal("bob should not have been kicked")
	}
}

func TestHTTPKickRejectsGet(t *testing.T) {
	h, _, _, _ := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/kick", nil)
	req.Header.Set("Authorization", "s3cr3t")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestHTTPTrafficClear(t *testing.T) {
	h, _, _, _ := newTestHandler(t)

	// clear=true returns the pre-clear snapshot.
	req := httptest.NewRequest(http.MethodGet, "/traffic?clear=true", nil)
	req.Header.Set("Authorization", "s3cr3t")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var got map[string]TrafficEntry
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["alice"].Tx != 100 {
		t.Fatalf("clear should return current stats first, got %#v", got)
	}

	// A follow-up read shows live users zeroed.
	req2 := httptest.NewRequest(http.MethodGet, "/traffic", nil)
	req2.Header.Set("Authorization", "s3cr3t")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	var after map[string]TrafficEntry
	if err := json.NewDecoder(rec2.Body).Decode(&after); err != nil {
		t.Fatal(err)
	}
	if after["alice"].Tx != 0 {
		t.Fatalf("alice should be zeroed after clear, got %#v", after["alice"])
	}
}

func TestHTTPTrafficClearParseBool(t *testing.T) {
	// hysteria parses ?clear with strconv.ParseBool, so "1" must also clear.
	h, _, _, _ := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/traffic?clear=1", nil)
	req.Header.Set("Authorization", "s3cr3t")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var got map[string]TrafficEntry
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got["alice"].Tx != 100 {
		t.Fatalf("clear=1 should return pre-clear snapshot, got %#v", got)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/traffic", nil)
	req2.Header.Set("Authorization", "s3cr3t")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	var after map[string]TrafficEntry
	if err := json.NewDecoder(rec2.Body).Decode(&after); err != nil {
		t.Fatal(err)
	}
	if after["alice"].Tx != 0 {
		t.Fatalf("alice should be zeroed after clear=1, got %#v", after["alice"])
	}
}

func TestHTTPTrafficClearRequiresAuth(t *testing.T) {
	h, _, _, _ := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/traffic?clear=true", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("clear without secret = %d, want 401", rec.Code)
	}
}

func TestHTTPDumpStreams(t *testing.T) {
	r := NewRegistry()
	aliceConn := r.AcquireConn("alice", "1.1.1.1:1")
	s := r.TraceStream("alice", aliceConn.ID(), aliceConn.NextStreamID())
	s.SetReqAddr("example.com:443")
	s.AddTx(10)
	bobConn := r.AcquireConn("bob", "2.2.2.2:2")
	r.TraceStream("bob", bobConn.ID(), bobConn.NextStreamID())
	h := NewHandler(ServerOptions{Secret: "s3cr3t", Registry: r})

	req := httptest.NewRequest(http.MethodGet, "/dump/streams", nil)
	req.Header.Set("Authorization", "s3cr3t")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("content-type = %q", ct)
	}
	var wrapper struct {
		Streams []StreamEntry `json:"streams"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&wrapper); err != nil {
		t.Fatal(err)
	}
	if len(wrapper.Streams) != 2 {
		t.Fatalf("streams = %d, want 2", len(wrapper.Streams))
	}
	if wrapper.Streams[0].Auth != "alice" || wrapper.Streams[0].ReqAddr != "example.com:443" {
		t.Fatalf("stream0 = %+v", wrapper.Streams[0])
	}
}

func TestHTTPDumpStreamsTextPlain(t *testing.T) {
	r := NewRegistry()
	aliceConn := r.AcquireConn("alice", "1.1.1.1:1")
	s := r.TraceStream("alice", aliceConn.ID(), aliceConn.NextStreamID())
	s.SetReqAddr("example.com:443")
	h := NewHandler(ServerOptions{Secret: "s3cr3t", Registry: r})

	req := httptest.NewRequest(http.MethodGet, "/dump/streams", nil)
	req.Header.Set("Authorization", "s3cr3t")
	req.Header.Set("Accept", "text/plain")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("content-type = %q", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "State") || !strings.Contains(body, "Hooked-Req-Addr") {
		t.Fatalf("missing table header: %q", body)
	}
	// State is uppercased and the empty hooked addr renders as "-".
	if !strings.Contains(body, "CONNECT") || !strings.Contains(body, "example.com:443") {
		t.Fatalf("missing stream row: %q", body)
	}
}
