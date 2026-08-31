package oidc

import (
	"os"
	"path/filepath"
	"testing"

	"cc.minki/auth/server/config"
)

func TestNewTokenSignerPersistsGeneratedPrivateKey(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "keys", "oidc.pem")
	first, err := newTokenSigner(config.OIDCConfig{PrivateKeyFile: keyPath, KeyID: "test-key"})
	if err != nil {
		t.Fatalf("create first signer: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat generated key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected key permissions: %o", info.Mode().Perm())
	}
	second, err := newTokenSigner(config.OIDCConfig{PrivateKeyFile: keyPath, KeyID: "test-key"})
	if err != nil {
		t.Fatalf("create second signer: %v", err)
	}
	if first.privateKey.N.Cmp(second.privateKey.N) != 0 {
		t.Fatal("expected signer to reuse the persisted private key")
	}
}
