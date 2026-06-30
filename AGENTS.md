# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`anytls-go` is the reference implementation of the **AnyTLS** proxy protocol, which mitigates the "TLS-in-TLS" nested-handshake fingerprinting problem via flexible packet-splitting/padding and session multiplexing. It ships two binaries — a server and a client — plus the protocol library they share.

The authoritative protocol spec is `docs/protocol.md` (Chinese). Read it before changing anything in `proxy/session/` or `proxy/padding/` — the wire format, command set, version negotiation (v1 vs v2), and padding-scheme semantics are all defined there and must stay in sync.

## Commands

```bash
# Build
go build -o anytls-server ./cmd/server
go build -o anytls-client ./cmd/client

# Test (whole module / single package / single test)
go test ./...
go test ./auth/
go test -run TestCachingAuthenticator ./auth/

go vet ./...

# Run server / client (sample, insecure TLS by default)
go run ./cmd/server -l 0.0.0.0:8443 -p password
go run ./cmd/client -l 127.0.0.1:1080 -s "anytls://password@host:port"

# Release builds are produced by goreleaser (.goreleaser.yaml)
```

Useful env vars: `LOG_LEVEL` (logrus level, default `info`), `TLS_KEY_LOG` (client, writes TLS keys for debugging), `CLIENT_DEBUG_SESSION_POOL=1` and `CLIENT_DEBUG_PADDING_SCHEME=1` (verbose client diagnostics).

## Architecture

The module path is `anytls` (see `go.mod`); internal imports are `anytls/...`. Data flows through these layers on the client: `TCP Proxy -> Stream -> Session -> TLS -> TCP` (server is the mirror).

- **`proxy/session/`** — the protocol core, used by both binaries.
  - `session.go` — `Session` runs the frame event loop (`recvLoop`/`writeConn`). Frames are `command(uint8) | streamId(uint32) | length(uint16) | data`. The same struct serves client and server (`isClient` flag). Padding is applied in `writeConn` per the active `PaddingFactory`.
  - `stream.go` — `Stream` implements `net.Conn` over a session; this is the unit the proxy code reads/writes. It also reports per-stream Tx/Rx into `Session.Identity` (see stats).
  - `client.go` — `Client` owns **session reuse**: an idle-session pool (skiplist keyed by `MaxUint64-seq`, so newest session is reused first) with a background cleanup goroutine. `minIdleSession` keeps N spare sessions; `disableReuse` turns pooling off. Reuse is mandatory in the protocol — preserve this behavior.
  - `frame.go` — command constants. v2 added `cmdSYNACK`, heartbeats, and `cmdServerSettings`; gate v2 features on `peerVersion >= 2`.
- **`proxy/padding/`** — `PaddingFactory` parses a padding scheme (`stop=N`, per-packet size lists with `c` check-marks) into record sizes. The default scheme is embedded; the server can push updates to clients via `cmdUpdatePaddingScheme` keyed by md5. Held in an atomic `DefaultPaddingFactory`.
- **`proxy/pipe/`** — in-memory `net.Conn`-style pipe with deadlines, backing `Stream`'s read side.
- **`cmd/server/`** — `main.go` wires config → authenticator → optional stats server → listener. `inbound_tcp.go` is the per-connection handshake: TLS accept, read `sha256(password)` + padding, authenticate, then run a server session whose `onNewStream` callback reads the SOCKS target address and dials out (`outbound_tcp.go`, with UoT for `udp-over-tcp.arpa`). Auth failure falls through to `fallback()` (currently a stub).
- **`cmd/client/`** — `main.go` parses flags / `anytls://` URI, builds the dial-out closure (TCP + TLS, `InsecureSkipVerify` by default in the sample). `myclient.go` creates streams and writes the SOCKS target; `inbound.go` is the local SOCKS5/HTTP listener.

### Server-only subsystems (branch additions)

- **`auth/`** — pluggable `Authenticator` interface: `Authenticate(addr, authBlob, tx) -> (id, ok, err)`. Implementations: `password` (default, constant single password), `http` (POSTs to a hysteria-2-compatible external backend), and `cache` (a TTL+LRU wrapper that caches **positive results only** — rejects and backend errors always fall through). The returned `id` is the stable key for stats. Selected in `cmd/server/main.go` from config.
- **`stats/`** — `Registry` tracks per-id traffic + live sessions. The session reports bytes through the `TrafficCounter` interface (`Session.Identity`), declared in the session package to avoid an import cycle; `Kickable` plays the same role for the stats→session direction. `http.go` exposes a hysteria-2-compatible API (`/traffic`, `/traffic?clear=true`, `/online`, `/kick`, `/dump/streams`) guarded by a shared `Secret`. There is **no background sweeper** — memory is reclaimed only by `?clear=true` (offline entries deleted, live ones zeroed in place).
- **`config/`** — YAML config (`-c` flag). CLI flags override YAML only when explicitly set (`flag.Visit`). Auth and stats are configured here; helpers `UseHTTPAuth()`, `StatsEnabled()`, `AuthCacheTTL()` gate the wiring in `main.go`.

## Conventions

- Logging is logrus. `[BUG]` + stack traces guard goroutine entry points (`recvLoop`, `onNewStream`, connection handlers) — keep panics from killing the process.
- Buffers come from `github.com/sagernet/sing/common/buf` (`buf.Get`/`buf.Put` pooling) — release what you get.
- `Session.Close` and `Stream.close*` use `sync.Once` (`dieOnce`) and a `die` channel; follow that pattern for any new teardown so close stays idempotent.
- When touching the wire format, update `docs/protocol.md` and bump `util.ProgramVersionName`.
