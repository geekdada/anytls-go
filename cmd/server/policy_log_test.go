package main

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"anytls/resolver"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

// capturePolicyLogs swaps the global logrus hooks for a test hook. Tests that
// use it must not call t.Parallel, because the logger is process-wide.
func capturePolicyLogs(t *testing.T) *logtest.Hook {
	t.Helper()
	logger := logrus.StandardLogger()
	previousHooks := logger.ReplaceHooks(make(logrus.LevelHooks))
	previousLevel, previousOutput := logger.GetLevel(), logger.Out
	hook := logtest.NewGlobal()
	logger.SetLevel(logrus.DebugLevel)
	logger.SetOutput(io.Discard)
	t.Cleanup(func() {
		logger.ReplaceHooks(previousHooks)
		logger.SetLevel(previousLevel)
		logger.SetOutput(previousOutput)
	})
	return hook
}

// policyWarnings counts warn-or-worse entries whose message starts with prefix.
// It fails on any entry more severe than warn. The prefix keeps logs from
// goroutines of other tests out of the count.
func policyWarnings(t *testing.T, hook *logtest.Hook, prefix string) int {
	t.Helper()
	count := 0
	for _, entry := range hook.AllEntries() {
		if !strings.HasPrefix(entry.Message, prefix) || entry.Level > logrus.WarnLevel {
			continue
		}
		if entry.Level != logrus.WarnLevel {
			t.Errorf("log %q level = %s, want warn", entry.Message, entry.Level)
		}
		count++
	}
	return count
}

type udpLogStep struct {
	addr      string
	wantWarns int
}

// The steps follow the hysteria log timing described on logDrop.
func TestRoutedPacketConnPolicyLogTiming(t *testing.T) {
	for _, tc := range []struct {
		name         string
		blockPrivate bool
		resolveFails bool
		steps        []udpLogStep
	}{
		{name: "silent after the socket opens", steps: []udpLogStep{
			{"8.8.8.8:53", 0}, {"10.0.0.2:53", 0}, {"10.0.0.2:53", 0},
		}},
		{name: "warns on every rejection before the socket opens", steps: []udpLogStep{
			{"10.0.0.1:53", 1}, {"10.0.0.1:53", 1}, {"10.0.0.2:53", 1}, {"8.8.8.8:53", 0}, {"10.0.0.2:53", 0},
		}},
		{name: "private destination before the socket opens", blockPrivate: true, steps: []udpLogStep{
			{"192.168.1.1:53", 1}, {"192.168.1.1:53", 1}, {"8.8.8.8:53", 0}, {"192.168.1.2:53", 0},
		}},
		{name: "resolution failure is not warned", resolveFails: true, steps: []udpLogStep{
			{"first.invalid:53", 0}, {"first.invalid:53", 0},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook := capturePolicyLogs(t)
			direct := &stubOutbound{packets: &stubPacketConn{}}
			p := newOutboundPolicy(testEngineWith(t, "reject(10.0.0.0/8)\ndirect(all)\n", outboundMap(nil, direct)), nil, tc.blockPrivate, direct)
			if tc.resolveFails {
				p.resolver = &stubResolver{result: resolver.Result{Err: errors.New("lookup failed")}}
			}
			c := newRoutedPacketConn(context.Background(), p)
			defer c.Close()

			for i, step := range tc.steps {
				hook.Reset()
				writeTestPacket(t, c, step.addr)
				if got := policyWarnings(t, hook, "routedPacketConn"); got != step.wantWarns {
					t.Fatalf("step %d (%s): warnings = %d, want %d", i, step.addr, got, step.wantWarns)
				}
			}
		})
	}
}

func TestRoutedPacketConnListenFailureWarns(t *testing.T) {
	hook := capturePolicyLogs(t)
	listenErr := errors.New("listen failed")
	direct := &stubOutbound{listenErr: listenErr}
	c := newRoutedPacketConn(context.Background(), newOutboundPolicy(nil, nil, false, direct))
	defer c.Close()
	if err := c.WritePacket(buf.NewSize(1), M.ParseSocksaddr("8.8.8.8:53")); !errors.Is(err, listenErr) {
		t.Fatalf("WritePacket error = %v, want %v", err, listenErr)
	}
	if got := policyWarnings(t, hook, "routedPacketConn"); got != 1 {
		t.Fatalf("warnings = %d, want 1", got)
	}
}

// Hysteria reports ACL rejection and dial failure through the same TCPError
// warning, once per stream.
func TestProxyOutboundTCPFailureWarns(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules string
	}{
		{name: "acl rejection", rules: "reject(all)\n"},
		{name: "dial failure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook := capturePolicyLogs(t)
			stub := &stubOutbound{}
			p := newOutboundPolicy(nil, nil, false, stub)
			if tc.rules != "" {
				p.acl = testEngineWith(t, tc.rules, outboundMap(nil, stub))
			}
			serverConn, clientConn := net.Pipe()
			defer serverConn.Close()
			defer clientConn.Close()

			if err := proxyOutboundTCP(context.Background(), serverConn, M.ParseSocksaddr("8.8.8.8:443"), nil, p); err == nil {
				t.Fatal("expected proxyOutboundTCP to fail")
			}
			if got := policyWarnings(t, hook, "proxyOutboundTCP"); got != 1 {
				t.Fatalf("warnings = %d, want 1", got)
			}
		})
	}
}
