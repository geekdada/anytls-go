# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

`anytls-go` is the reference implementation of the **AnyTLS** proxy protocol, which mitigates the "TLS-in-TLS" nested-handshake fingerprinting problem via flexible packet-splitting/padding and session multiplexing. It ships two binaries — a server and a client — plus the protocol library they share.

The authoritative protocol spec is `docs/protocol.md` (Chinese). Read it before changing anything in `proxy/session/` or `proxy/padding/` — the wire format, command set, version negotiation (v1 vs v2), and padding-scheme semantics are all defined there and must stay in sync.

## Commands

```bash
make help   # list all targets; `make` defaults to help

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
  - `session.go` — `Session` runs the frame event loop (`recvLoop`/`writeConn`). Frames are `command(uint8) | streamId(uint32) | length(uint16) | data`. The same struct serves client and server (`isClient` flag). Padding is applied in `writeConn` per the active `PaddingFactory`. A server session caps open streams at `maxServerStreams` (refused with SYNACK+error for v2, FIN for v1); `writeDataFrame` splits payloads over 65535 bytes.
  - `stream.go` — `Stream` implements `net.Conn` over a session; this is the unit the proxy code reads/writes. It also reports per-stream Tx/Rx into `Session.Identity` (see stats).
  - `client.go` — `Client` owns **session reuse**: an idle-session pool (skiplist keyed by `MaxUint64-seq`, so newest session is reused first) with a background cleanup goroutine. `minIdleSession` keeps N spare sessions; `disableReuse` turns pooling off. Reuse is mandatory in the protocol — preserve this behavior.
  - `frame.go` — command constants. v2 added `cmdSYNACK`, heartbeats, and `cmdServerSettings`; gate v2 features on `peerVersion >= 2`.
- **`proxy/padding/`** — `PaddingFactory` parses a padding scheme (`stop=N`, per-packet size lists with `c` check-marks) into record sizes. The default scheme is embedded; the server can push updates to clients via `cmdUpdatePaddingScheme` keyed by md5. Held in an atomic `DefaultPaddingFactory`.
- **`proxy/pipe/`** — in-memory `net.Conn`-style pipe with deadlines, backing `Stream`'s read side.
- **`cmd/server/`** — `main.go` wires config → authenticator → optional resolver/ACL/stats server → listener. `inbound_tcp.go` is the per-connection handshake: TLS accept and read `sha256(password)` + padding under `handshakeTimeout`, authenticate, then run a server session whose `onNewStream` callback reads the SOCKS target address (under `requestTimeout`) and dials out (`outbound_tcp.go`, with UoT for the exact magic addresses `sp.v2.udp-over-tcp.arpa` and legacy v1 `sp.udp-over-tcp.arpa`, which has no request header). Like hysteria, only TCP streams are traced in `/dump/streams`; UoT traffic counts only toward `/traffic`, and only the UDP payload (through a `bufio.CounterPacketConn`). TCP streams set `Stream.CountIdentity` after the target address is read, so no stream counts its address header, matching hysteria. Auth failure falls through to `fallback()` (currently a stub).
- **`cmd/client/`** — `main.go` parses flags / `anytls://` URI, builds the dial-out closure (TCP + TLS, certificate verified unless `-insecure` or `insecure=1`). `myclient.go` creates streams and writes the SOCKS target; `inbound.go` is the local SOCKS5/HTTP listener.

### Server-only subsystems (branch additions)

- **`auth/`** — pluggable `Authenticator` interface: `Authenticate(addr, authBlob, tx) -> (id, ok, err)`. Implementations: `password` (default, constant single password), `http` (POSTs to a hysteria-2-compatible external backend), `limit` (`LimitedAuthenticator`, bounds in-flight backend calls; main wraps HTTP auth as `cache(limit(http))`), and `cache` (a TTL+LRU wrapper over two independent caches — positive results `authBlob->id` (default TTL 10s) and negative results (rejected `authBlob`s, default TTL 60s) — so a stale/revoked client that keeps reconnecting stops hammering the backend; **backend errors always fall through and are never cached**, and separate caches keep a flood of bad blobs from evicting good entries). The returned `id` is the stable key for stats. Selected in `cmd/server/main.go` from config.
- **`stats/`** — `Registry` tracks per-id traffic + live sessions. The session reports bytes through the `TrafficCounter` interface (`Session.Identity`), declared in the session package to avoid an import cycle; `Kickable` plays the same role for the stats→session direction. `http.go` exposes a hysteria-2-compatible API (`/traffic`, `/traffic?clear=true`, `/online`, `/kick`, `/dump/streams`) guarded by a shared `Secret`, which config validation requires whenever the API is enabled. There is **no background sweeper** — `/traffic`-tracked memory is reclaimed only by `?clear=true` (offline entries deleted, live ones zeroed in place). The `/dump/streams` `connection` is a **per-device logical id** (`stats.Conn`, inferred from `auth`+source IP since anytls has no on-wire device identity), reference-counted via `AcquireConn`/`ReleaseConn` and freed when the device's last session drops — so one device's pooled TLS sessions share one `connection` and its streams get monotonic ids, mirroring a hysteria QUIC connection. `/online` likewise counts devices (source-IP-deduped), not raw sessions.
- **`outbound/`**: server-side egress. `Outbound` exposes `DialTCP`, `ListenUDP` and `RemoteResolve`; `RemoteResolve` tells the policy to pass domains through unresolved. `Direct` dials destinations itself, `Reject` refuses everything, and `SOCKS5` sends TCP CONNECT or UDP ASSOCIATE to a proxy and leaves name resolution to it. Two SOCKS5 details matter: `WritePacket` copies a buffer that lacks UDP-header headroom, and an unspecified bind address in the ASSOCIATE reply is replaced with the address the proxy was dialed at.
- **`acl/`** — hysteria-2-consistent ACL engine (rule syntax, matching order, LRU result cache). Rules compile against a name → `outbound.Outbound` map (`Compile[O]`, `Engine[O]`), so any configured outbound name is a valid rule target; the built-ins `direct`, `reject` and `default` fill names the user did not define. Hijack addresses are supported. Rules compile at startup via `config` (`acl.file` or `acl.inline`, mutually exclusive). `acl/v2geo/` loads v2ray `geoip.dat`/`geosite.dat` for `geoip:`/`geosite:` rules; `FileGeoLoader` lazy-loads them and auto-downloads from the Loyalsoldier mirror (7-day default refresh, overridable via `acl.geoUpdateInterval`). The engine itself is pure — `Engine.Lookup(host, ipv4, ipv6, proto, port)` takes **pre-resolved** IPs, so all resolution lives in `cmd/server/acl.go` (see `resolver/`). Geo-dependent unit tests skip unless the `.dat` fixtures are present under `acl/v2geo/`.
- **`resolver/`** — hysteria-2-consistent custom DNS resolver for the server's outbound path. One interface, `Resolve(ctx, host) Result`, with `Result{IPv4, IPv6, Err}`: a lookup can return an error **and** a partial address, so callers check `Result.Empty()`, not `Err`. `standard.go` covers `udp`/`tcp`/`tls` through one `miekg/dns` `dns.Client` (`Net: ""`/`"tcp"`/`"tcp-tls"`); `doh.go` covers `https` (RFC 8484 POST). Ported behavior that must not drift: 2s default timeout **per exchange**, default port 53/853, A and AAAA queried in parallel with 2 attempts each (DoH: no retry), only the first record of each family kept, in-packet CNAME chains collapsed by `skipCNAMEChain` and bounded by depth 16 + a `seen` cycle guard, the A error winning over the AAAA one, IP literals short-circuiting via `tryParseIP` (4-byte form, which `acl`'s geoip matcher requires). There is deliberately **no DNS cache**, matching hysteria; `tcp`/`tls` reuse connections through `pool.go` (a closed idle connection falls back to a fresh dial, a timeout does not). Built in `cmd/server/resolver.go` from `config.ResolverConfig`.
  - `cmd/server/acl.go` holds `outboundPolicy{acl, resolver, blockPrivate, fallback}`. `blockPrivate` (on unless `outbound.allowPrivate`) rejects non-public dial addresses (`private.go`) after the ACL runs; hijack targets are exempt. Errors sent to clients go through `clientError` so resolver/internal addresses stay in the server log. The ACL and resolver are optional. `selectRoute` mirrors hysteria's `Resolver(ACL(outbound))` chain and returns a `route{outbound, target}`: resolve → ACL (reject wins, hijack replaces the result) → fail with `resolver.Error` if resolution ran and produced nothing → reject private addresses (both resolved families for a remote-resolving outbound, since it resolves again and may pick either) → target is the resolved IP, or the original domain when the outbound resolves names itself, though the private filter still requires a successful local resolution in that case. Order matters: resolution failure is not fatal until after the ACL has run, so name rules still fire and hijack rules can rescue an unresolvable domain. A configured resolver applies **whether or not ACL is enabled**, and never falls back to the system resolver. With no resolver configured, `systemResolve` is used only when the ACL or `blockPrivate` needs the IPs; with `outbound.allowPrivate` and no ACL, the dialer resolves on its own as before the resolver existed. `routedPacketConn` applies the same policy per UoT packet: a lazy socket opens on the first allowed packet and binds the stream to that outbound, packets the ACL routes elsewhere are dropped, rejected and unresolvable packets are dropped silently (an error would tear down the whole multiplexed stream), decisions cached per destination for the stream's life.
- **`config/`** — YAML config (`-c` flag). CLI flags override YAML only when explicitly set (`flag.Visit`). Auth, ACL, resolver, outbounds and stats are configured here; helpers `UseHTTPAuth()`, `ACLEnabled()`, `StatsEnabled()`, `ResolverEnabled()`, `AuthCacheTTL()`, `AuthNegativeCacheTTL()` gate the wiring in `main.go`. `ResolverConfig` carries its own `Kind()`/`Addr()`/`Validate()` (type aliases: `tcp-tls` = `tls`, `http` = `https`, `""` = `system`); note `timeout` is a real `time.Duration` — yaml.v3 decodes `4s` natively, unlike the older string-plus-`ParseDuration` fields.

## Conventions

- Logging is logrus. `[BUG]` + stack traces guard goroutine entry points (`recvLoop`, `onNewStream`, connection handlers) — keep panics from killing the process.
- Buffers come from `github.com/sagernet/sing/common/buf` (`buf.Get`/`buf.Put` pooling) — release what you get.
- `Session.Close` and `Stream.close*` use `sync.Once` (`dieOnce`) and a `die` channel; follow that pattern for any new teardown so close stays idempotent.
- When touching the wire format, update `docs/protocol.md` and bump `util.ProgramVersionName`.
