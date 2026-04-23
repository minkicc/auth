package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestSignAndVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "mkauth-plugin.yaml")
	privateKeyPath := filepath.Join(dir, "signing.key.pem")
	publicKeyPath := filepath.Join(dir, "signing.pub")
	signaturePath := filepath.Join(dir, "mkauth-plugin.sig")

	if err := os.WriteFile(manifestPath, []byte("id: claims-http\nname: Claims HTTP Action\ntype: flow_action\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	if err := run([]string{"genkey", "-key-id", "test-signer", "-out-private", privateKeyPath, "-out-public", publicKeyPath}); err != nil {
		t.Fatalf("genkey failed: %v", err)
	}
	if err := run([]string{"sign", "-manifest", manifestPath, "-private-key", privateKeyPath, "-key-id", "test-signer", "-out", signaturePath}); err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if err := run([]string{"verify", "-manifest", manifestPath, "-signature", signaturePath, "-public-key-file", publicKeyPath}); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestVerifyRejectsTamperedManifest(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "mkauth-plugin.yaml")
	signaturePath := filepath.Join(dir, "mkauth-plugin.sig")

	if err := os.WriteFile(manifestPath, []byte("id: claims-http\nname: Claims HTTP Action\ntype: flow_action\n"), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	signature := ed25519.Sign(privateKey, []byte("id: claims-http\nname: Claims HTTP Action\ntype: flow_action\n"))
	if err := os.WriteFile(signaturePath, []byte("key_id: \"test-signer\"\nalgorithm: \"ed25519\"\nsignature: \""+base64.StdEncoding.EncodeToString(signature)+"\"\n"), 0o644); err != nil {
		t.Fatalf("write signature: %v", err)
	}
	if err := os.WriteFile(manifestPath, []byte("id: claims-http\nname: Tampered\ntype: flow_action\n"), 0o644); err != nil {
		t.Fatalf("tamper manifest: %v", err)
	}

	if err := run([]string{"verify", "-manifest", manifestPath, "-signature", signaturePath, "-public-key", base64.StdEncoding.EncodeToString(publicKey)}); err == nil {
		t.Fatalf("expected tampered manifest verification to fail")
	}
}
