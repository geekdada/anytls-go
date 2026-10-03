package util

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// certCheckInterval limits how often GetCertificate stats the cert files. A
// check per handshake costs two syscalls, and a changed file would otherwise
// be reloaded by every concurrent handshake at once.
const certCheckInterval = time.Second

type FileCertificateLoader struct {
	certPath string
	keyPath  string

	mu            sync.RWMutex
	cert          *tls.Certificate
	modTime       time.Time
	lastLoggedErr string
	lastLoggedAt  time.Time

	checkInterval time.Duration
	lastCheck     atomic.Int64 // unix nanos
}

func NewFileCertificateLoader(certPath, keyPath string) (*FileCertificateLoader, error) {
	l := &FileCertificateLoader{
		certPath:      certPath,
		keyPath:       keyPath,
		checkInterval: certCheckInterval,
	}
	if err := l.reload(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *FileCertificateLoader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	var reloadErr error
	if l.dueForCheck() {
		reloadErr = l.reloadIfChanged()
	}
	l.mu.RLock()
	cert := l.cert
	l.mu.RUnlock()
	if reloadErr != nil {
		if cert == nil {
			return nil, reloadErr
		}
		l.logReloadError(reloadErr)
	}
	return cert, nil
}

// dueForCheck lets one handshake per interval check the files. The CAS makes
// concurrent handshakes skip instead of reloading in parallel.
func (l *FileCertificateLoader) dueForCheck() bool {
	now := time.Now().UnixNano()
	last := l.lastCheck.Load()
	if now-last < int64(l.checkInterval) {
		return false
	}
	return l.lastCheck.CompareAndSwap(last, now)
}

func (l *FileCertificateLoader) logReloadError(err error) {
	msg := err.Error()
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if msg == l.lastLoggedErr && now.Sub(l.lastLoggedAt) < time.Second {
		return
	}
	l.lastLoggedErr = msg
	l.lastLoggedAt = now
	logrus.Warnf("tls cert reload failed, serving last good certificate: %v", err)
}

func (l *FileCertificateLoader) reloadIfChanged() error {
	modTime, err := certKeyModTime(l.certPath, l.keyPath)
	if err != nil {
		return err
	}
	l.mu.RLock()
	unchanged := !modTime.After(l.modTime)
	l.mu.RUnlock()
	if unchanged {
		return nil
	}
	return l.reload()
}

func (l *FileCertificateLoader) reload() error {
	modTime, err := certKeyModTime(l.certPath, l.keyPath)
	if err != nil {
		return err
	}
	certPEM, err := os.ReadFile(l.certPath)
	if err != nil {
		return fmt.Errorf("read tls cert %q: %w", l.certPath, err)
	}
	keyPEM, err := os.ReadFile(l.keyPath)
	if err != nil {
		return fmt.Errorf("read tls key %q: %w", l.keyPath, err)
	}
	keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("parse tls cert/key: %w", err)
	}
	l.mu.Lock()
	l.cert = &keyPair
	l.modTime = modTime
	l.mu.Unlock()
	return nil
}

func certKeyModTime(certPath, keyPath string) (time.Time, error) {
	certInfo, err := os.Stat(certPath)
	if err != nil {
		return time.Time{}, fmt.Errorf("stat tls cert %q: %w", certPath, err)
	}
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		return time.Time{}, fmt.Errorf("stat tls key %q: %w", keyPath, err)
	}
	modTime := certInfo.ModTime()
	if keyInfo.ModTime().After(modTime) {
		modTime = keyInfo.ModTime()
	}
	return modTime, nil
}
