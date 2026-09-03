// Package tlsutil generates and loads the self-signed certificates SpawnRelay
// uses for its tunnel and admin listeners, and computes the certificate
// fingerprints clients pin against.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Fingerprint returns the SHA-256 fingerprint of a DER certificate in the
// form "sha256:<hex>".
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// NormalizeFingerprint accepts "sha256:hex", "SHA256:HEX", "AA:BB:..", or bare
// hex and returns the canonical lowercase "sha256:hex" form.
func NormalizeFingerprint(fp string) (string, error) {
	fp = strings.TrimSpace(strings.ToLower(fp))
	fp = strings.TrimPrefix(fp, "sha256:")
	fp = strings.ReplaceAll(fp, ":", "")
	if len(fp) != 64 {
		return "", errors.New("fingerprint must be a 64 hex character SHA-256 digest")
	}
	if _, err := hex.DecodeString(fp); err != nil {
		return "", errors.New("fingerprint is not valid hex")
	}
	return "sha256:" + fp, nil
}

// GenerateSelfSigned creates a self-signed ECDSA P-256 certificate for hosts.
func GenerateSelfSigned(commonName string, hosts []string, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"SpawnRelay"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// LoadOrCreate loads certPath/keyPath, generating a self-signed pair when they
// do not exist yet. It returns the certificate and its leaf fingerprint.
func LoadOrCreate(certPath, keyPath, commonName string, hosts []string, validity time.Duration) (tls.Certificate, string, bool, error) {
	created := false
	_, errCert := os.Stat(certPath)
	_, errKey := os.Stat(keyPath)
	if os.IsNotExist(errCert) || os.IsNotExist(errKey) {
		certPEM, keyPEM, err := GenerateSelfSigned(commonName, hosts, validity)
		if err != nil {
			return tls.Certificate{}, "", false, fmt.Errorf("generate certificate: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
			return tls.Certificate{}, "", false, err
		}
		if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
			return tls.Certificate{}, "", false, err
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			return tls.Certificate{}, "", false, err
		}
		created = true
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, "", false, fmt.Errorf("load certificate %s: %w", certPath, err)
	}
	if len(cert.Certificate) == 0 {
		return tls.Certificate{}, "", false, errors.New("certificate file contains no certificates")
	}
	return cert, Fingerprint(cert.Certificate[0]), created, nil
}

// PinnedVerifier returns a VerifyPeerCertificate callback that accepts only a
// leaf certificate whose SHA-256 fingerprint matches fingerprint.
func PinnedVerifier(fingerprint string) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("server presented no certificate")
		}
		got := Fingerprint(rawCerts[0])
		if got != fingerprint {
			return fmt.Errorf("server certificate fingerprint %s does not match pinned %s", got, fingerprint)
		}
		return nil
	}
}
