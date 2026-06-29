package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPAuthenticatorSuccess(t *testing.T) {
	var got HTTPAuthRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("missing JSON content-type")
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(HTTPAuthResponse{OK: true, ID: "alice"})
	}))
	defer srv.Close()

	a := NewHTTPAuthenticator(srv.URL, false)
	id, ok, err := a.Authenticate("1.2.3.4:5678", "deadbeef", 42)
	if err != nil || !ok || id != "alice" {
		t.Fatalf("Authenticate = (%q, %v, %v), want (alice, true, nil)", id, ok, err)
	}
	if got.Addr != "1.2.3.4:5678" || got.Auth != "deadbeef" || got.Tx != 42 {
		t.Fatalf("backend received unexpected payload: %+v", got)
	}
}

func TestHTTPAuthenticatorRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(HTTPAuthResponse{OK: false})
	}))
	defer srv.Close()

	a := NewHTTPAuthenticator(srv.URL, false)
	_, ok, err := a.Authenticate("x", "y", 0)
	if ok || err != nil {
		t.Fatalf("want (false, nil), got (%v, %v)", ok, err)
	}
}

func TestHTTPAuthenticatorNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	a := NewHTTPAuthenticator(srv.URL, false)
	_, ok, err := a.Authenticate("x", "y", 0)
	if ok {
		t.Fatal("expected rejection on 5xx")
	}
	if err == nil {
		t.Fatal("expected non-nil err on 5xx")
	}
}

func TestHTTPAuthenticatorNon200Success(t *testing.T) {
	// hysteria treats only an exact 200 as success; a 2xx like 204 is a reject.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	a := NewHTTPAuthenticator(srv.URL, false)
	if _, ok, err := a.Authenticate("x", "y", 0); ok || err == nil {
		t.Fatalf("204 must reject with error, got ok=%v err=%v", ok, err)
	}
}

func TestHTTPAuthenticatorEmptyIDAdmitted(t *testing.T) {
	// Matching hysteria: ok=true with an empty id still admits the client.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(HTTPAuthResponse{OK: true, ID: ""})
	}))
	defer srv.Close()

	a := NewHTTPAuthenticator(srv.URL, false)
	id, ok, err := a.Authenticate("x", "y", 0)
	if !ok || err != nil || id != "" {
		t.Fatalf("want (\"\", true, nil), got (%q, %v, %v)", id, ok, err)
	}
}

func TestHTTPAuthenticatorTLSInsecure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(HTTPAuthResponse{OK: true, ID: "tls-user"})
	}))
	defer srv.Close()

	a := NewHTTPAuthenticator(srv.URL, true)
	id, ok, err := a.Authenticate("x", "y", 0)
	if err != nil || !ok || id != "tls-user" {
		t.Fatalf("insecure TLS auth failed: id=%q ok=%v err=%v", id, ok, err)
	}

	b := NewHTTPAuthenticator(srv.URL, false)
	if _, ok, err := b.Authenticate("x", "y", 0); ok || err == nil {
		t.Fatal("expected TLS verification to fail without Insecure")
	}
}
