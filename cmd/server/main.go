package main

import (
	"context"
	"crypto/tls"
	"flag"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"anytls/acl"
	"anytls/auth"
	"anytls/config"
	"anytls/limiter"
	"anytls/proxy/padding"
	"anytls/stats"
	"anytls/util"

	"github.com/sirupsen/logrus"
)

func main() {
	configPath := flag.String("c", "", "path to YAML config file")
	listen := flag.String("l", "0.0.0.0:8443", "server listen port")
	password := flag.String("p", "", "password")
	paddingScheme := flag.String("padding-scheme", "", "padding-scheme")
	flag.Parse()

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		logrus.Fatalln(err)
	}

	// CLI flags override YAML when explicitly set. Flags left at their defaults
	// don't override a value the YAML may have provided.
	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	if explicit["l"] || cfg.Listen == "" {
		cfg.Listen = *listen
	}
	if explicit["p"] {
		cfg.Password = *password
	}
	if explicit["padding-scheme"] {
		cfg.PaddingScheme = *paddingScheme
	}

	if cfg.PaddingScheme != "" {
		if f, err := os.Open(cfg.PaddingScheme); err == nil {
			b, err := io.ReadAll(f)
			if err != nil {
				logrus.Fatalln(err)
			}
			if padding.UpdatePaddingScheme(b) {
				logrus.Infoln("loaded padding scheme file:", cfg.PaddingScheme)
			} else {
				logrus.Errorln("wrong format padding scheme file:", cfg.PaddingScheme)
			}
			f.Close()
		} else {
			logrus.Fatalln(err)
		}
	}

	logLevel, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)

	var authn auth.Authenticator
	switch {
	case cfg.UseHTTPAuth():
		authn = auth.NewHTTPAuthenticator(cfg.Auth.HTTP.URL, cfg.Auth.HTTP.Insecure)
		logrus.Infoln("[Auth] using HTTP backend at", cfg.Auth.HTTP.URL)
		if ttl, _ := cfg.AuthCacheTTL(); ttl > 0 {
			size := cfg.Auth.HTTP.CacheSize
			if size <= 0 {
				size = 4096
			}
			negTTL, _ := cfg.AuthNegativeCacheTTL()
			authn = auth.NewCachingAuthenticator(authn, ttl, size, negTTL)
			logrus.Infoln("[Auth] result cache enabled, ttl", ttl, "size", size, "negativeTTL", negTTL)
		}
	default:
		if cfg.Password == "" {
			logrus.Fatalln("please set password (config.password or -p)")
		}
		authn = auth.NewPasswordAuthenticator(cfg.Password)
	}

	logrus.Infoln("[Server]", util.ProgramVersionName)
	logrus.Infoln("[Server] Listening TCP", cfg.Listen)

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		logrus.Fatalln("listen server tcp:", err)
	}

	var tlsConfig *tls.Config
	if cfg.TLSEnabled() {
		loader, err := util.NewFileCertificateLoader(cfg.TLS.Cert, cfg.TLS.Key)
		if err != nil {
			logrus.Fatalln("tls:", err)
		}
		tlsConfig = &tls.Config{GetCertificate: loader.GetCertificate}
		logrus.Infoln("[TLS] using certificate", cfg.TLS.Cert)
	} else {
		tlsCert, err := util.GenerateKeyPair(time.Now, "")
		if err != nil {
			logrus.Fatalln("generate tls cert:", err)
		}
		tlsConfig = &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return tlsCert, nil
		}}
		logrus.Infoln("[TLS] using auto-generated self-signed certificate")
	}

	var registry *stats.Registry
	if cfg.StatsEnabled() {
		registry = stats.NewRegistry()
	}

	var aclEngine *acl.Engine
	if cfg.ACLEnabled() {
		geoInterval, err := cfg.GeoUpdateInterval()
		if err != nil {
			logrus.Fatalln(err)
		}
		geoLoader := &acl.FileGeoLoader{
			GeoIPFilename:   cfg.ACL.GeoIP,
			GeoSiteFilename: cfg.ACL.GeoSite,
			UpdateInterval:  geoInterval,
		}
		if cfg.ACL.File != "" {
			aclEngine, err = acl.NewEngineFromFile(cfg.ACL.File, geoLoader)
			if err != nil {
				logrus.Fatalln("acl:", err)
			}
			logrus.Infoln("[ACL] loaded rules from file:", cfg.ACL.File)
		} else {
			aclEngine, err = acl.NewEngineFromString(strings.Join(cfg.ACL.Inline, "\n"), geoLoader)
			if err != nil {
				logrus.Fatalln("acl:", err)
			}
			logrus.Infoln("[ACL] loaded", len(cfg.ACL.Inline), "inline rules")
		}
	}

	upBps, downBps, err := cfg.BandwidthLimits()
	if err != nil {
		logrus.Fatalln(err)
	}
	limits := limiter.NewRegistry(upBps, downBps)
	if limits != nil {
		logrus.Infoln("[Bandwidth] up", bandwidthLabel(upBps), "down", bandwidthLabel(downBps), "(per device)")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if cfg.StatsEnabled() {
		go func() {
			logrus.Infoln("[Stats] Listening HTTP", cfg.TrafficStats.Listen)
			if err := stats.Serve(ctx, stats.ServerOptions{
				Listen:   cfg.TrafficStats.Listen,
				Secret:   cfg.TrafficStats.Secret,
				Registry: registry,
			}); err != nil && err != context.Canceled {
				logrus.Errorln("[Stats] server exited:", err)
			}
		}()
	}

	server := NewMyServer(tlsConfig, authn, registry, limits, aclEngine)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		c, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				logrus.Fatalln("accept:", err)
			}
		}
		go handleTcpConnection(ctx, c, server)
	}
}

// bandwidthLabel renders a bits-per-second cap for logging; 0 means unlimited.
func bandwidthLabel(bps uint64) string {
	if bps == 0 {
		return "unlimited"
	}
	return strconv.FormatUint(bps, 10) + " bps"
}
