package auth

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPAuthenticator delegates authentication to an external HTTP endpoint
// compatible with hysteria 2's external auth backend.
type HTTPAuthenticator struct {
	url    string
	client *http.Client
}

// authVariant identifies this protocol implementation so a backend shared by
// multiple proxy protocols can distinguish anytls-go requests.
const authVariant = "geekdada/anytls-go"

// HTTPAuthRequest is the JSON body sent to the backend.
type HTTPAuthRequest struct {
	Addr    string `json:"addr"`
	Auth    string `json:"auth"`
	Tx      int64  `json:"tx"`
	Variant string `json:"variant"`
}

// HTTPAuthResponse is the JSON body the backend must return.
type HTTPAuthResponse struct {
	OK bool   `json:"ok"`
	ID string `json:"id"`
}

func NewHTTPAuthenticator(url string, insecure bool) *HTTPAuthenticator {
	// Clone the default transport (proxy-from-environment, connection pooling,
	// sane dialer/keepalive defaults) and only override TLS verification, exactly
	// as hysteria 2 does.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecure}
	return &HTTPAuthenticator{
		url: url,
		client: &http.Client{
			// hysteria 2 uses a fixed 10s timeout for the auth backend call.
			Timeout:   10 * time.Second,
			Transport: tr,
		},
	}
}

func (h *HTTPAuthenticator) Authenticate(addr, authBlob string, tx int64) (string, bool, error) {
	body, err := json.Marshal(HTTPAuthRequest{Addr: addr, Auth: authBlob, Tx: tx, Variant: authVariant})
	if err != nil {
		return "", false, fmt.Errorf("marshal auth request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return "", false, fmt.Errorf("build auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("call auth backend: %w", err)
	}
	defer resp.Body.Close()

	// hysteria 2 treats only an exact 200 as success; any other status is an
	// infrastructure failure that rejects the connection.
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", false, fmt.Errorf("auth backend status %d", resp.StatusCode)
	}

	var ar HTTPAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return "", false, fmt.Errorf("decode auth response: %w", err)
	}
	// Match hysteria 2: the backend's "ok" is authoritative and the id is passed
	// through verbatim (an empty id is admitted and simply buckets stats under
	// the empty key, exactly as upstream does).
	return ar.ID, ar.OK, nil
}
