package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestParseGoogleCertCacheTTL(t *testing.T) {
	if got := parseGoogleCertCacheTTL("public, max-age=1234, must-revalidate"); got != 1234*time.Second {
		t.Fatalf("expected ttl 1234s, got %v", got)
	}
	if got := parseGoogleCertCacheTTL("public, max-age=oops"); got != time.Hour {
		t.Fatalf("expected default ttl for invalid cache-control, got %v", got)
	}
}

func TestParseGoogleRSAPublicKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	t.Run("public key pem", func(t *testing.T) {
		der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			t.Fatalf("failed to marshal public key: %v", err)
		}
		block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
		parsedKey, err := parseGoogleRSAPublicKey(string(block))
		if err != nil {
			t.Fatalf("failed to parse public key pem: %v", err)
		}
		if parsedKey.N.Cmp(privateKey.PublicKey.N) != 0 {
			t.Fatalf("parsed public key modulus mismatch")
		}
	})

	t.Run("certificate pem", func(t *testing.T) {
		certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "google-test"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}, &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "google-test"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}, &privateKey.PublicKey, privateKey)
		if err != nil {
			t.Fatalf("failed to create certificate: %v", err)
		}

		block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		parsedKey, err := parseGoogleRSAPublicKey(string(block))
		if err != nil {
			t.Fatalf("failed to parse certificate pem: %v", err)
		}
		if parsedKey.N.Cmp(privateKey.PublicKey.N) != 0 {
			t.Fatalf("parsed certificate public key modulus mismatch")
		}
	})
}

func TestIsGoogleIssuer(t *testing.T) {
	if !isGoogleIssuer("https://accounts.google.com") {
		t.Fatalf("expected https issuer to be valid")
	}
	if !isGoogleIssuer("accounts.google.com") {
		t.Fatalf("expected bare issuer to be valid")
	}
	if isGoogleIssuer("https://evil.example.com") {
		t.Fatalf("expected non-google issuer to be invalid")
	}
}

func TestCanLinkGoogleEmail(t *testing.T) {
	if !canLinkGoogleEmail("user@example.com", true) {
		t.Fatalf("expected verified email to be linkable")
	}
	if canLinkGoogleEmail("user@example.com", false) {
		t.Fatalf("expected unverified email to be rejected for account linking")
	}
	if canLinkGoogleEmail("", true) {
		t.Fatalf("expected empty email to be rejected for account linking")
	}
}
