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

// HTTPAuthRequest is the JSON body sent to the backend.
type HTTPAuthRequest struct {
	Addr string `json:"addr"`
	Auth string `json:"auth"`
	Tx   int64  `json:"tx"`
}

// HTTPAuthResponse is the JSON body the backend must return.
type HTTPAuthResponse struct {
	OK bool   `json:"ok"`
	ID string `json:"id"`
}

func NewHTTPAuthenticator(url string, insecure bool) *HTTPAuthenticator {
	return &HTTPAuthenticator{
		url: url,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
			},
		},
	}
}

func (h *HTTPAuthenticator) Authenticate(addr, authBlob string, tx int64) (string, bool, error) {
	body, err := json.Marshal(HTTPAuthRequest{Addr: addr, Auth: authBlob, Tx: tx})
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

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", false, fmt.Errorf("auth backend status %d", resp.StatusCode)
	}

	var ar HTTPAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return "", false, fmt.Errorf("decode auth response: %w", err)
	}
	if !ar.OK || ar.ID == "" {
		return "", false, nil
	}
	return ar.ID, true, nil
}
