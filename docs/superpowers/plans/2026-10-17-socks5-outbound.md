# SOCKS5 Outbound Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the server send client traffic (TCP and UoT) through upstream SOCKS5 proxies declared in a hysteria-2-style `outbounds:` list, with ACL rules choosing an outbound by name.

**Architecture:** A new `outbound` package defines one `Outbound` interface with three implementations: `Direct`, `Reject` and `SOCKS5`. The `acl` package becomes generic over the outbound type, as it is upstream in hysteria (`Compile[O]`, `Engine[O]`), so a rule resolves straight to an `Outbound` value. `cmd/server`'s `outboundPolicy` returns a `route{outbound, target}` in place of a bare dial address. The UoT path opens its socket lazily, on the outbound chosen by the stream's first allowed packet.

**Tech Stack:** Go 1.25, `github.com/sagernet/sing` v0.5.1 (`protocol/socks` client and server, `common/bufio`), `gopkg.in/yaml.v3`, logrus.

**Spec:** No separate spec. The requirements are the request ("为 outbounds 增加 socks5 支持"), hysteria 2's outbound behavior (`extras/outbounds/acl.go`, `ob_socks5.go`, `app/cmd/server.go` `fillOutboundConfig`) and these two decisions from the user:
1. UDP goes through SOCKS5 too (UDP ASSOCIATE). The first packet of a UoT stream picks the outbound.
2. `outbound.allowPrivate: false` (the default) still blocks private destinations reached through SOCKS5. The domain is resolved and checked locally, then the **domain** is sent to the proxy.

## Global Constraints

- Module path `anytls`. No new module dependencies: use `github.com/sagernet/sing/protocol/socks` (client `ClientHandshake5`, `NewAssociatePacketConn`; server `HandleConnection` for tests).
- Config keys follow hysteria 2: top-level `outbounds:` list, entries `name`, `type`, `socks5.addr`, `socks5.username`, `socks5.password`. Supported `type` values: `direct` and `socks5`, matched case-insensitively. `http` is out of scope.
- Built-in outbound names: `direct` (Direct), `reject` (Reject), `default` (the first `outbounds` entry, or `direct` when the list is empty). A user entry with one of these names overrides the built-in. Outbound names in ACL rules are case-insensitive.
- With no ACL, every request uses `default` (hysteria: "No ACL, use the first outbound").
- A SOCKS5 outbound receives the original host, or the hijack IP when a rule rewrites it. The locally resolved IP stays on the server (hysteria `socks5Outbound` "ignores ResolveInfo").
- SOCKS5 handshake deadline: 10s (hysteria `socks5NegotiationTimeout`/`socks5RequestTimeout`). The proxy itself is dialed with `proxy.SystemDialer`.
- The private-destination filter skips the SOCKS5 proxy's own address, because the operator chose it.
- Client-facing errors still go through `clientError`. SOCKS5 failures map to `errClientDialFailed`, and the proxy address stays in the server log.
- Wire format is unchanged: do not edit `docs/protocol.md` or bump `util.ProgramVersionName`.
- Every task ends with `go vet ./... && go test ./...` passing.

## Review Focus

1. **A UDP buffer with no front headroom written to a SOCKS5 association.** `AssociatePacketConn.WritePacket` calls `buffer.ExtendHeader`, which panics when headroom is short. Expected: the packet arrives at the echo server without a panic. Test: `TestSOCKS5ListenUDPWithoutHeadroom` (Task 1).
2. **A proxy that answers UDP ASSOCIATE with bind `0.0.0.0` or `::`.** Expected: packets go to the proxy's own IP on the bind port. Test: `TestRelayAddr` (Task 1).
3. **A proxy that accepts TCP and then stays silent through the handshake.** Expected: the dial fails at the handshake deadline and the stream does not hang. Test: `TestSOCKS5HandshakeTimeout` (Task 1).
4. **The proxy closes the UDP ASSOCIATE control connection.** RFC 1928 ends the association with it. Expected: the packet conn closes and the UoT stream ends. Test: `TestSOCKS5ListenUDPClosesWithControl` (Task 1).
5. **A UoT stream that closes before any packet is allowed** (no packets, or only rejected ones). Expected: the blocked `ReadPacket` returns and no goroutine leaks. Test: `TestRoutedPacketConnCloseUnblocksRead` (Task 4).

---

### Task 1: `outbound` package (Direct, Reject, SOCKS5 TCP + UDP)

**Files:**
- Create: `outbound/outbound.go`, `outbound/direct.go`, `outbound/socks5.go`
- Create: `outbound/outboundtest/socks5server.go` (test helper shared with `cmd/server` tests)
- Test: `outbound/direct_test.go`, `outbound/socks5_test.go`

**Interfaces:**
- Consumes: `proxy.SystemDialer` (`*net.Dialer`, 5s timeout).
- Produces:
  ```go
  package outbound
  type Outbound interface {
      DialTCP(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
      ListenUDP(ctx context.Context) (N.PacketConn, error) // one socket per UoT stream
      RemoteResolve() bool // true: pass domains through unresolved
  }
  var ErrRejected = errors.New("rejected by ACL")
  type Direct struct{ dialer *net.Dialer }           // non-zero size, so two distinct pointers compare unequal
  func NewDirect() *Direct                           // RemoteResolve() == false
  type Reject struct{}                               // both methods return ErrRejected
  type SOCKS5 struct{ /* addr, username, password, dialer */ }
  func NewSOCKS5(addr, username, password string) *SOCKS5 // RemoteResolve() == true

  package outboundtest
  type SOCKS5Server struct{ Addr string /* ... */ }
  func NewSOCKS5Server(t testing.TB, username, password string) *SOCKS5Server
  func (s *SOCKS5Server) ConnectDestinations() []string // CONNECT targets seen, in order
  func (s *SOCKS5Server) DropControls()                // closes every accepted TCP connection
  ```

- [ ] **Step 1: Write the test SOCKS5 server** in `outbound/outboundtest/socks5server.go`. It listens on `127.0.0.1:0`, and for each accepted conn runs `socks.HandleConnection(ctx, conn, auth.NewAuthenticator(users), handler, M.Metadata{})`. `users` is empty when `username == ""`. The handler records `metadata.Destination.String()` on `NewConnection`, dials it with `net.Dial`, and runs `bufio.CopyConn`. On `NewPacketConnection` it relays through `net.ListenPacket("udp", "127.0.0.1:0")` with `bufio.CopyPacketConn`. Close the listener and all conns in `t.Cleanup`.

- [ ] **Step 2: Write the failing tests**

`outbound/direct_test.go`:
```go
func TestDirectDialTCP(t *testing.T)  // DialTCP to a local TCP echo; write "ping", read "ping"
func TestDirectListenUDP(t *testing.T) // ListenUDP; WritePacket "ping" to a local UDP echo; ReadPacket returns "ping" from the echo addr
func TestRejectRefuses(t *testing.T) {
    _, err := Reject{}.DialTCP(ctx, M.ParseSocksaddr("1.1.1.1:443")); errors.Is(err, ErrRejected) // must be true
    _, err = Reject{}.ListenUDP(ctx);                                  errors.Is(err, ErrRejected) // must be true
}
```

`outbound/socks5_test.go`:
```go
func TestSOCKS5DialTCP(t *testing.T) {
    srv := outboundtest.NewSOCKS5Server(t, "", "")
    // DialTCP(echo) -> "ping" round-trips; srv.ConnectDestinations() == []string{echo.String()}
}
func TestSOCKS5DialTCPSendsDomain(t *testing.T) {
    // destination M.ParseSocksaddrHostPort("localhost", echoPort)
    // srv.ConnectDestinations()[0] == fmt.Sprintf("localhost:%d", echoPort)  (not "127.0.0.1:…")
}
func TestSOCKS5DialTCPAuth(t *testing.T) {
    srv := outboundtest.NewSOCKS5Server(t, "user", "pass")
    // NewSOCKS5(srv.Addr, "user", "pass").DialTCP -> ok
    // NewSOCKS5(srv.Addr, "user", "wrong").DialTCP -> err != nil
}
func TestSOCKS5HandshakeTimeout(t *testing.T) {
    // listener that accepts and stays silent; socks5HandshakeTimeout = 100ms (restore in Cleanup)
    // DialTCP returns err != nil in under 2s
}
func TestSOCKS5ListenUDPWithoutHeadroom(t *testing.T) {
    // b := buf.NewSize(4); b.WriteString("ping")   // Start() == 0, no headroom
    // pc.WritePacket(b, udpEcho) must not panic; pc.ReadPacket returns "ping"
}
func TestSOCKS5ListenUDPClosesWithControl(t *testing.T) {
    // pc := ListenUDP; srv.DropControls(); pc.ReadPacket returns err != nil within 5s
}
func TestRelayAddr(t *testing.T) {
    proxy := &net.TCPAddr{IP: net.ParseIP("10.0.0.9"), Port: 1080}
    relayAddr(M.ParseSocksaddr("0.0.0.0:5000"), proxy).String()     == "10.0.0.9:5000"
    relayAddr(M.ParseSocksaddr("[::]:5000"), proxy).String()        == "10.0.0.9:5000"
    relayAddr(M.ParseSocksaddr("203.0.113.5:5000"), proxy).String() == "203.0.113.5:5000"
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./outbound/...`
Expected: FAIL (undefined: `NewDirect`, `NewSOCKS5`, `Reject`, `relayAddr`, …).

- [ ] **Step 4: Implement `outbound/outbound.go` and `outbound/direct.go`**

`Direct.DialTCP` dials `destination.String()` over `"tcp"`. `Direct.ListenUDP` returns `bufio.NewPacketConn(net.ListenPacket("udp", ""))`, which is what `proxyOutboundUoT` does today.

- [ ] **Step 5: Implement `outbound/socks5.go`**

- `var socks5HandshakeTimeout = 10 * time.Second`. It is a var so tests can shorten it.
- `handshake(ctx, command byte, destination M.Socksaddr) (net.Conn, socks5.Response, error)`: dial `addr` over TCP, `SetDeadline(now+socks5HandshakeTimeout)`, `socks.ClientHandshake5(conn, command, destination, username, password)`, then clear the deadline. On error, close the conn and wrap the error as `fmt.Errorf("socks5 %s: %w", addr, err)`.
- `DialTCP` = `handshake(ctx, socks5.CommandConnect, destination)`.
- `ListenUDP` = `handshake(ctx, socks5.CommandUDPAssociate, M.SocksaddrFrom(netip.IPv4Unspecified(), 0))`. Next, dial UDP to `relayAddr(resp.Bind, tcpConn.RemoteAddr())` and wrap the result in `socks.NewAssociatePacketConn(udpConn, M.Socksaddr{}, tcpConn)`. Return a `socks5PacketConn` that:
  - starts a goroutine running `io.Copy(io.Discard, tcpConn)` and closes the packet conn when that returns (same as hysteria's `hold`);
  - in `WritePacket`, copies `b` into a fresh buffer with `3 + M.SocksaddrSerializer.AddrPortLen(destination)` bytes of headroom when `b.Start()` is smaller, and releases the original.
- `relayAddr(bind M.Socksaddr, proxy net.Addr) M.Socksaddr`: when `bind.Addr.IsUnspecified()`, return the proxy's IP with `bind.Port`. Otherwise return `bind` unchanged.

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test -race ./outbound/... && go vet ./...`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add outbound/
git commit -m "feat(outbound): add direct, reject and socks5 outbounds"
```

---

### Task 2: `outbounds` config block

**Files:**
- Modify: `config/config.go` (add the `Config.Outbounds` field and types, `ValidateOutbounds`, and call it from `LoadFile`)
- Test: `config/config_test.go`

**Interfaces:**
- Produces:
  ```go
  type Config struct { /* … */ Outbounds []OutboundEntry `yaml:"outbounds"` }
  type OutboundEntry struct {
      Name   string               `yaml:"name"`
      Type   string               `yaml:"type"`
      Direct map[string]any       `yaml:"direct"` // only so options can be rejected
      SOCKS5 OutboundSOCKS5Config `yaml:"socks5"`
  }
  type OutboundSOCKS5Config struct {
      Addr     string `yaml:"addr"`
      Username string `yaml:"username"`
      Password string `yaml:"password"`
  }
  func (e *OutboundEntry) Kind() string // strings.ToLower(strings.TrimSpace(e.Type))
  func (c *Config) ValidateOutbounds() error
  ```

- [ ] **Step 1: Write the failing tests** (table style, same pattern as `TestLoadFileResolverValidation`, each body prefixed with `password: hunter2\n`)

```go
func TestLoadFileOutbounds(t *testing.T) {
    // body: outbounds: [{name: warp, type: SOCKS5, socks5: {addr: 127.0.0.1:40000, username: u, password: p}}, {name: direct, type: direct}]
    // len(c.Outbounds) == 2; c.Outbounds[0].Kind() == "socks5"; c.Outbounds[0].SOCKS5.Addr == "127.0.0.1:40000"
}
func TestLoadFileOutboundsValidation(t *testing.T) // each case: LoadFile fails and err mentions wantErr
//  empty name                   -> "outbounds[0].name: empty outbound name"
//  duplicate name "a" and "A"   -> `outbounds[1].name: duplicate outbound name "A"`
//  type http                    -> `outbounds[0].type: unsupported outbound type "http"`
//  socks5 without addr          -> "outbounds[0].socks5.addr: empty socks5 address"
//  socks5 addr "127.0.0.1"      -> "outbounds[0].socks5.addr"        (no port)
//  username without password    -> "outbounds[0].socks5: username and password must both be set or both be omitted"
//  256-byte username + password -> "outbounds[0].socks5: username and password must be at most 255 bytes"
//  direct with {bindIPv4: 1.2.3.4} -> "outbounds[0].direct: direct outbound options are not supported"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run 'TestLoadFileOutbounds' ./config/`
Expected: FAIL (`c.Outbounds` undefined).

- [ ] **Step 3: Implement the types and `ValidateOutbounds`**

Check entries in order and return the first error, using the exact messages above. Compare names case-insensitively, because ACL rule names are case-insensitive. Check the address with `net.SplitHostPort`. Call `ValidateOutbounds` from `LoadFile` with the same `config %q: %w` wrapping as the other validators. The 255-byte limit comes from RFC 1929 (one-byte length fields).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./config/ && go vet ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add config/
git commit -m "feat(config): add outbounds block with socks5 entries"
```

---

### Task 3: ACL routes to outbounds; TCP dials through the chosen outbound

The ACL and policy move from `Action` to `Outbound` values. After this task the only outbounds are the built-ins, so behavior is unchanged. `policyPacketConn` keeps its pre-opened direct socket until Task 4.

**Files:**
- Modify: `acl/compile.go`, `acl/engine.go`, `acl/compile_test.go`, `acl/engine_test.go`
- Create: `cmd/server/outbound.go`, `cmd/server/outbound_test.go`
- Modify: `cmd/server/acl.go`, `cmd/server/outbound_tcp.go`, `cmd/server/myserver.go`, `cmd/server/main.go`, `cmd/server/acl_test.go`, `cmd/server/private_test.go`, `cmd/server/inbound_tcp_test.go`

**Interfaces:**
- Consumes: `outbound.Outbound`, `outbound.NewDirect`, `outbound.Reject`, `outbound.ErrRejected` (Task 1).
- Produces:
  ```go
  // acl
  type CompiledRuleSet[O any] interface { Match(host HostInfo, proto Protocol, port uint16) (O, bool, net.IP) }
  func Compile[O any](rules []TextRule, outbounds map[string]O, cacheSize int, geoLoader GeoLoader) (CompiledRuleSet[O], error)
  type Engine[O any] struct { RuleSet CompiledRuleSet[O]; Default O }
  func NewEngineFromString[O any](rules string, outbounds map[string]O, geoLoader GeoLoader) (*Engine[O], error) // Default = outbounds["default"]
  func NewEngineFromFile[O any](filename string, outbounds map[string]O, geoLoader GeoLoader) (*Engine[O], error)
  func (e *Engine[O]) Lookup(host string, ipv4, ipv6 net.IP, proto Protocol, port uint16) (O, net.IP) // Default on no match
  // Action, ActionDirect, ActionReject and outboundActions are removed.

  // cmd/server
  type namedOutbound struct { name string; outbound outbound.Outbound }
  func outboundMap(entries []namedOutbound, direct outbound.Outbound) map[string]outbound.Outbound
  type route struct { outbound outbound.Outbound; target M.Socksaddr }
  func newOutboundPolicy(engine *acl.Engine[outbound.Outbound], res resolver.Resolver, blockPrivate bool, fallback outbound.Outbound) *outboundPolicy // nil fallback -> outbound.NewDirect()
  func (p *outboundPolicy) selectRoute(ctx context.Context, destination M.Socksaddr, proto acl.Protocol) (route, error) // replaces dialAddr
  func NewMyServer(tlsConfig *tls.Config, a auth.Authenticator, reg *stats.Registry, lim *limiter.Registry, policy *outboundPolicy) *myServer
  var errACLRejected = outbound.ErrRejected
  ```

- [ ] **Step 1: Make the `acl` tests use the generic API (they should fail to compile)**

At the top of `acl/compile_test.go`, define the test outbound type so the existing tables stay as they are:
```go
type testAction string
const (ActionDirect testAction = "direct"; ActionReject testAction = "reject")
var testOutbounds = map[string]testAction{"direct": ActionDirect, "default": ActionDirect, "reject": ActionReject}
```
Change each `Compile(rules, 100, …)` to `Compile(rules, testOutbounds, 100, …)` and each `NewEngineFromString(rules, …)` to `NewEngineFromString(rules, testOutbounds, …)`. Add:
```go
func TestCompileOutboundNameCaseInsensitive(t *testing.T) // rule Outbound "WARP", map {"warp": "warp"}; Match(all) returns ("warp", true, nil)
func TestEngineLookupNoMatchUsesDefault(t *testing.T)     // map {"direct": ..., "default": "warp"}, rules "direct(1.1.1.1)"; Lookup("example.org", …) returns "warp"
```

- [ ] **Step 2: Run to verify failure**

Run: `go test ./acl/`
Expected: FAIL (compile errors in the test files).

- [ ] **Step 3: Make `acl` generic**

Port hysteria's generic shape. `compiledRule[O]` holds `Outbound O`, and the LRU caches `matchResult[O]`. Look rule names up as `outbounds[strings.ToLower(rule.Outbound)]`. A missing name returns `CompilationError{…, "outbound <name> not found"}`. Update the doc comments on `Engine` and `Compile`, which still say anytls has no outbounds list.

- [ ] **Step 4: Run `go test ./acl/`. Expected: PASS.**

- [ ] **Step 5: Write the failing `cmd/server` tests**

Shared test helpers (in `cmd/server/outbound_test.go`):
```go
// stubOutbound records TCP dials and hands out its packets conn on ListenUDP.
type stubOutbound struct {
    remote    bool
    mu        sync.Mutex
    dialed    []string
    listens   int
    listenErr error
    packets   *stubPacketConn
}
func testEngineWith(t *testing.T, rules string, obs map[string]outbound.Outbound) *acl.Engine[outbound.Outbound]
```
Keep `testEngine(t, rules)` with the body `testEngineWith(t, rules, outboundMap(nil, outbound.NewDirect()))`. Append `, nil` to every existing `newOutboundPolicy(…)` call. `tcpDialAddr` keeps its signature and returns `r.target` from `selectRoute`. The direct `p.dialAddr(…)` call in `TestPolicyPrivateFilterAllowsHijack` becomes `p.selectRoute(…)` and asserts on `.target`. Remove the `p.active()` assertions in `TestPolicyDialAddrNothingConfiguredKeepsFqdn` and `TestPolicyBlocksLocalhostWithSystemResolver`, because `active()` goes away. `testServer` calls `NewMyServer(…, newOutboundPolicy(nil, nil, true, nil))`, and `openStream` sets `s.policy = newOutboundPolicy(nil, nil, false, nil)`.

New tests (`warp := &stubOutbound{remote: true}`, `direct := &stubOutbound{}`):
```go
func TestOutboundMapBuiltins(t *testing.T)          // outboundMap(nil, direct): keys exactly {direct, reject, default}; m["default"] == direct; m["reject"] is outbound.Reject
func TestOutboundMapDefaultIsFirstEntry(t *testing.T) // entries [{"WARP", warp}, {"other", direct}]: m["warp"] == warp (lowercased); m["default"] == warp
func TestOutboundMapEntryOverridesBuiltin(t *testing.T) // entries [{"reject", warp}]: m["reject"] == warp

func TestPolicyRouteACLPicksNamedOutbound(t *testing.T) {
    obs := outboundMap([]namedOutbound{{"warp", warp}}, direct)
    res := &stubResolver{result: resolver.Result{IPv4: net.IPv4(1, 2, 3, 4).To4()}}
    p := newOutboundPolicy(testEngineWith(t, "warp(suffix:example.com)\ndirect(all)\n", obs), res, false, obs["default"])
    // "www.example.com:443" -> outbound == warp, target == "www.example.com:443"   (domain, not 1.2.3.4)
    // "9.9.9.9:443"         -> outbound == direct, target == "9.9.9.9:443"
}
func TestPolicyRouteNoACLUsesFallback(t *testing.T)      // newOutboundPolicy(nil, nil, false, warp): "example.com:443" -> (warp, "example.com:443"), resolver call count 0
func TestPolicyRouteRemoteBlocksPrivate(t *testing.T)    // fallback warp, blockPrivate true; res 192.168.0.1 -> errPrivateDestination; res 1.2.3.4 -> target "example.com:443"; literal "10.0.0.1:443" -> errPrivateDestination
func TestPolicyRouteRemoteResolveFailure(t *testing.T)   // res Err "boom", fallback warp: blockPrivate false -> (warp, "example.com:443"); blockPrivate true -> errors.As(err, &resolver.Error{}) is true
func TestPolicyRouteHijackViaRemote(t *testing.T)        // rule "warp(example.com,*,1.1.1.1)": "example.com:443" -> (warp, "1.1.1.1:443")
func TestProxyOutboundTCPDialsRouteTarget(t *testing.T)  // stub := &stubOutbound{remote: true}; proxyOutboundTCP(ctx, pipeEnd, "example.com:443", nil, newOutboundPolicy(nil, nil, false, stub)) returns err; stub.dialed == []string{"example.com:443"}
```

- [ ] **Step 6: Run to verify failure**

Run: `go test ./cmd/server/`
Expected: FAIL (undefined `outboundMap`, `selectRoute`, …).

- [ ] **Step 7: Implement**

- `cmd/server/outbound.go`: `outboundMap` mirrors hysteria's `outboundsToMap`. Add user entries under lowercased names. Then add `direct` (the given direct), `reject` (`outbound.Reject{}`) and `default` (`entries[0].outbound`, else the direct entry in the map) for each name not already present.
- `cmd/server/acl.go`: add `fallback outbound.Outbound` to `outboundPolicy` and delete `active()`. `selectRoute` keeps the current ordering and adds the remote-resolve rules:
  ```go
  host, result, attempted := p.hostInfo(ctx, destination)
  ob := p.fallback
  if p.acl != nil {
      var hijack net.IP
      ob, hijack = p.acl.Lookup(host, result.IPv4, result.IPv6, proto, destination.Port)
      if _, ok := ob.(outbound.Reject); ok {
          return route{}, errACLRejected
      }
      if hijack != nil {
          return route{ob, M.SocksaddrFrom(ipToNetip(hijack), destination.Port)}, nil
      }
  }
  addr, err := pickDialAddr(destination, result, attempted)
  if err != nil {
      // A remote-resolving outbound can still reach a name the local resolver
      // cannot, unless the private filter needs the IP to decide.
      if !ob.RemoteResolve() || p.blockPrivate {
          return route{}, err
      }
      return route{ob, destination}, nil
  }
  if p.blockPrivate && addr.IsIP() && isPrivateAddr(addr.Addr) {
      return route{}, errPrivateDestination
  }
  if ob.RemoteResolve() {
      return route{ob, destination}, nil
  }
  return route{ob, addr}, nil
  ```
  `policyPacketConn.decide` calls `selectRoute` and stores `r.target` as `dest`. Leave the rest of it unchanged for now.
- `outbound_tcp.go`: `proxyOutboundTCP` always calls `policy.selectRoute`, then `r.outbound.DialTCP(ctx, r.target)` in place of `proxy.SystemDialer`. `proxyOutboundUoT` drops its `policy.active()` check and always wraps the socket in `newPolicyPacketConn`.
- `myserver.go`: `NewMyServer` takes the policy.
- `main.go`: `obs := outboundMap(nil, outbound.NewDirect())`. Pass `obs` to `acl.NewEngineFromFile` / `NewEngineFromString`, and build `newOutboundPolicy(aclEngine, dnsResolver, !cfg.Outbound.AllowPrivate, obs["default"])`.

- [ ] **Step 8: Run tests to verify they pass**

Run: `go vet ./... && go test -race ./...`
Expected: PASS, including every pre-existing `acl`, `TestPolicy*` and `inbound_tcp` test.

- [ ] **Step 9: Commit**

```bash
git add acl/ cmd/server/
git commit -m "refactor(acl): route rules to outbound values"
```

---

### Task 4: UoT opens its socket on the first allowed packet's outbound

**Files:**
- Modify: `cmd/server/acl.go` (replace `policyPacketConn` with `routedPacketConn`), `cmd/server/outbound_tcp.go` (`proxyOutboundUoT`)
- Test: `cmd/server/acl_test.go`, `cmd/server/private_test.go`

**Interfaces:**
- Consumes: `selectRoute`, `route`, `stubOutbound` (Task 3).
- Produces:
  ```go
  func newRoutedPacketConn(ctx context.Context, p *outboundPolicy) *routedPacketConn // implements N.PacketConn and N.FrontHeadroom
  type policyDecision struct { rejected bool; route route }
  ```

- [ ] **Step 1: Write the failing tests**

`newTestPacketConn(t, p)` becomes `newRoutedPacketConn(context.Background(), p)`. The existing `TestPolicyPacketConn*` tests (renamed `TestRoutedPacketConn*`) and `TestPolicyPacketConnDropsPrivate` build their policy with `direct := &stubOutbound{packets: &stubPacketConn{}}` as fallback and as the map's `direct`. They then assert on `direct.packets.written` with the same expected values as today. New tests:
```go
func TestRoutedPacketConnOpensOnFirstAllowedPacket(t *testing.T) {
    // rules "reject(10.0.0.0/8)\ndirect(all)\n"
    // write 10.1.2.3:53 -> direct.listens == 0
    // write 8.8.8.8:53, then 1.1.1.1:53 -> direct.listens == 1; written == [8.8.8.8:53 1.1.1.1:53]
}
func TestRoutedPacketConnBindsFirstOutbound(t *testing.T) {
    // obs {warp}; rules "warp(1.1.1.1)\ndirect(all)\n"
    // write 8.8.8.8:53 then 1.1.1.1:53 -> direct.packets.written == [8.8.8.8:53]; warp.listens == 0
}
func TestRoutedPacketConnRemoteKeepsDomain(t *testing.T) // fallback warp (remote), res 1.2.3.4: write example.com:53 -> warp.packets.written == [example.com:53]
func TestRoutedPacketConnListenErrorEndsStream(t *testing.T) // direct.listenErr = errors.New("boom"): WritePacket returns an error
func TestRoutedPacketConnCloseUnblocksRead(t *testing.T) {
    // go c.ReadPacket(buf) with no packet written; c.Close(); ReadPacket returns err != nil within 1s
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test -run 'RoutedPacketConn|DropsPrivate' ./cmd/server/`
Expected: FAIL (undefined `newRoutedPacketConn`).

- [ ] **Step 3: Implement `routedPacketConn`**

Fields: `ctx`, `policy`, `cache map[string]policyDecision` (same 256-entry bound and eviction as today), `mu sync.Mutex` guarding `outbound`, `conn` and `closed`, plus `ready chan struct{}`, which is closed once `conn` is set or the conn is closed.

`WritePacket(b, destination)`:
1. Look up or compute the decision as today. Errors become `rejected`, logged at debug level unless they are reject or private errors.
2. If rejected, release `b` and return nil.
3. Under `mu`: if `closed`, release `b` and return `net.ErrClosed`. If `conn == nil`, call `d.route.outbound.ListenUDP(c.ctx)`. On error, release `b` and return the error, which ends the stream; hysteria fails fast the same way. On success, set `outbound` and `conn` and close `ready`.
4. If `d.route.outbound != c.outbound`, release `b` and drop the packet with a debug log. This differs from hysteria on purpose. Hysteria sends such packets out the session's outbound, so traffic the ACL routes to one egress can leave through another.
5. Return `conn.WritePacket(b, d.route.target)`.

`ReadPacket` waits on `ready`, then returns `net.ErrClosed` if `conn` is nil, else `conn.ReadPacket(b)`. `Close` is idempotent: it sets `closed`, closes `ready` if it is still open, and closes `conn` if one exists. `FrontHeadroom()` returns `3 + M.MaxSocksaddrLength`, so `CopyPacketConn` leaves room for a SOCKS5 UDP header. The deadline setters and `LocalAddr` forward to `conn` when it is open, and are no-ops or return `&net.UDPAddr{}` before that.

`proxyOutboundUoT`: delete the `net.ListenPacket` call. Report handshake success right after the request is read, then `bufio.CopyPacketConn(ctx, uotConn, newRoutedPacketConn(ctx, policy))`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go vet ./... && go test -race ./...`
Expected: PASS, including `TestUoTStreamIsNotTraced` (both UoT versions still echo through the direct outbound).

- [ ] **Step 5: Commit**

```bash
git add cmd/server/
git commit -m "feat(server): bind uot streams to the first packet's outbound"
```

---

### Task 5: Wire `outbounds` config into the server, end-to-end tests, docs

**Files:**
- Modify: `cmd/server/outbound.go` (add `newOutbounds`), `cmd/server/main.go`
- Test: `cmd/server/outbound_test.go`, `cmd/server/inbound_tcp_test.go`
- Modify: `README.md`, `CLAUDE.md`

**Interfaces:**
- Consumes: `config.OutboundEntry` (Task 2), `outbound.NewSOCKS5`, `outboundtest.NewSOCKS5Server` (Task 1), `outboundMap`, `newOutboundPolicy` (Task 3), `routedPacketConn` (Task 4).
- Produces: `func newOutbounds(entries []config.OutboundEntry) (map[string]outbound.Outbound, error)`

- [ ] **Step 1: Write the failing tests**

```go
func TestNewOutbounds(t *testing.T) {
    // entries [{Name: "warp", Type: "SOCKS5", SOCKS5: {Addr: "127.0.0.1:40000"}}, {Name: "d", Type: "direct"}]
    // obs["warp"] is *outbound.SOCKS5; obs["d"] is *outbound.Direct; obs["default"] == obs["warp"]
    // entries with Type "http" -> err != nil
}
```
In `inbound_tcp_test.go`, give `openStream` a `policy *outboundPolicy` parameter. Existing callers pass `newOutboundPolicy(nil, nil, false, nil)`. Then add:
```go
func TestTCPThroughSOCKS5(t *testing.T) {
    srv := outboundtest.NewSOCKS5Server(t, "u", "p")
    echo := tcpEcho(t)
    conn := openStream(t, stats.NewRegistry(), echo, []byte("ping"), newOutboundPolicy(nil, nil, false, outbound.NewSOCKS5(srv.Addr, "u", "p")))
    // readPSH(t, conn, 1) == "ping"; srv.ConnectDestinations() == []string{echo.String()}
}
func TestUoTThroughSOCKS5(t *testing.T) {
    // uot.Version stream to udpEcho(t) through the same policy; readPSH(t, conn, 1) is non-empty
}
```

- [ ] **Step 2: Run to verify failure**

Run: `go test -run 'NewOutbounds|ThroughSOCKS5' ./cmd/server/`
Expected: FAIL (undefined `newOutbounds`; `openStream` arity).

- [ ] **Step 3: Implement `newOutbounds` and the wiring in `main.go`**

`newOutbounds` maps each entry by `Kind()`: `direct` becomes `outbound.NewDirect()` and `socks5` becomes `outbound.NewSOCKS5(addr, username, password)`. Any other kind returns an error naming the entry. The result is `outboundMap(list, outbound.NewDirect())`. In `main.go`, call `newOutbounds(cfg.Outbounds)` before building the ACL (fatal on error). Log `[Outbound] <name>: socks5 via <addr>` for each SOCKS5 entry. Leave credentials out of the log. Use the returned map where Task 3 put `outboundMap(nil, …)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go vet ./... && go test -race ./...`
Expected: PASS.

- [ ] **Step 5: Update docs**

`README.md` (Chinese, matching the surrounding sections):
- Add a commented `outbounds:` example to the YAML block with one `socks5` entry (`addr`, `username`, `password`) and one `direct` entry.
- Replace the ACL section's line that says the ACL has no outbounds control: rule targets are now `direct`, `reject`, `default` and any `outbounds` name, case-insensitive.
- Add a `### 出站（outbounds）` section stating: supported types are `direct` and `socks5`; `default` means the first entry; without ACL, all traffic uses `default`; user entries override the built-in names; SOCKS5 receives the domain and resolves it remotely; with `allowPrivate: false`, the domain is still resolved and checked locally first, so a domain that cannot be resolved locally is rejected; UDP uses UDP ASSOCIATE, and a UoT stream stays on the outbound of its first allowed packet, dropping packets that the ACL routes elsewhere; `direct` options (`bindIPv4` etc.) and `http` outbounds are not supported.

`CLAUDE.md`:
- `acl/` bullet: drop "without outbounds control"; say rules compile against a name → `outbound.Outbound` map (`Compile[O]`, `Engine[O]`).
- Add an `outbound/` bullet: the `Outbound` interface, `Direct`/`Reject`/`SOCKS5`, `RemoteResolve`, and the two SOCKS5 fixes (headroom copy, unspecified bind address).
- `cmd/server/acl.go` paragraph: `dialAddr` → `selectRoute` returning `route{outbound, target}`; `policyPacketConn` → `routedPacketConn` (lazy socket, first packet binds the outbound, mismatches dropped).

- [ ] **Step 6: Commit**

```bash
git add cmd/server/ README.md CLAUDE.md
git commit -m "feat(server): configure socks5 outbounds"
```
