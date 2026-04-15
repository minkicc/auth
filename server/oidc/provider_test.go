package oidc

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestVerifyPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if !verifyPKCE(verifier, challenge, "S256") {
		t.Fatalf("expected pkce verification to succeed")
	}
	if verifyPKCE("wrong", challenge, "S256") {
		t.Fatalf("expected pkce verification to fail for wrong verifier")
	}
}

func TestMatchSecret(t *testing.T) {
	if !matchSecret("plain-secret", "plain-secret") {
		t.Fatalf("expected plain secret to match")
	}
	if matchSecret("plain-secret", "wrong") {
		t.Fatalf("expected plain secret mismatch")
	}

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte("s3cr3t"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to hash secret: %v", err)
	}
	if !matchSecret(string(hashedSecret), "s3cr3t") {
		t.Fatalf("expected bcrypt secret to match")
	}
	if matchSecret(string(hashedSecret), "wrong") {
		t.Fatalf("expected bcrypt secret mismatch")
	}
}
