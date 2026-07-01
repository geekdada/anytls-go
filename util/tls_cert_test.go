package util

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeCertKey(t *testing.T, dir, base string, cert *tls.Certificate) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, base+".crt")
	keyPath = filepath.Join(dir, base+".key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func certCN(t *testing.T, cert *tls.Certificate) string {
	t.Helper()
	x, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return x.Subject.CommonName
}

func TestFileCertificateLoader(t *testing.T) {
	dir := t.TempDir()
	first, err := GenerateKeyPair(time.Now, "first.example.com")
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := writeCertKey(t, dir, "server", first)

	loader, err := NewFileCertificateLoader(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := loader.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if certCN(t, got) != "first.example.com" {
		t.Fatalf("CN = %q, want first.example.com", certCN(t, got))
	}

	second, err := GenerateKeyPair(time.Now, "second.example.com")
	if err != nil {
		t.Fatal(err)
	}
	writeCertKey(t, dir, "server", second)
	time.Sleep(10 * time.Millisecond)

	got, err = loader.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if certCN(t, got) != "second.example.com" {
		t.Fatalf("after reload CN = %q, want second.example.com", certCN(t, got))
	}
}

func TestNewFileCertificateLoaderMissingCert(t *testing.T) {
	dir := t.TempDir()
	_, err := NewFileCertificateLoader(filepath.Join(dir, "missing.crt"), filepath.Join(dir, "missing.key"))
	if err == nil {
		t.Fatal("expected error for missing cert")
	}
}
