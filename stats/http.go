package stats

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// ServerOptions controls the stats HTTP API.
type ServerOptions struct {
	Listen   string
	Secret   string
	Registry *Registry
}

// NewHandler returns an *http.ServeMux mounted with the hysteria-2 compatible
// stats endpoints. Exposed separately from Serve so tests can drive it with
// httptest.NewRecorder.
func NewHandler(opts ServerOptions) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/traffic", auth(opts.Secret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, opts.Registry.Snapshot())
	})))
	mux.Handle("/online", auth(opts.Secret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, opts.Registry.Online())
	})))
	mux.Handle("/kick", auth(opts.Secret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var ids []string
		if err := json.NewDecoder(r.Body).Decode(&ids); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		opts.Registry.Kick(ids)
		w.WriteHeader(http.StatusNoContent)
	})))
	mux.Handle("/dump/streams", auth(opts.Secret, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, opts.Registry.DumpSessions())
	})))
	return mux
}

// Serve runs the stats HTTP API until ctx is cancelled or the listener fails.
func Serve(ctx context.Context, opts ServerOptions) error {
	srv := &http.Server{
		Addr:              opts.Listen,
		Handler:           NewHandler(opts),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errc:
		return err
	}
}

func auth(secret string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if secret != "" && r.Header.Get("Authorization") != secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
