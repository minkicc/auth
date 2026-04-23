package plugins

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
	"minki.cc/mkauth/server/config"
)

type SignatureEnvelope struct {
	KeyID     string `json:"key_id" yaml:"key_id"`
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	Signature string `json:"signature" yaml:"signature"`
}

type VerificationResult struct {
	Verified bool
	KeyID    string
}

type LocalPlugin struct {
	Directory     string
	Manifest      Manifest
	ManifestBytes []byte
	State         *State
	Enabled       bool
	PackageSHA256 string
	Verification  VerificationResult
}

func inspectLocalPluginDir(directory string, cfg config.PluginsConfig, enabledFilter, disabledFilter map[string]struct{}) (*LocalPlugin, error) {
	manifestPath, ok := findManifest(directory)
	if !ok {
		return nil, nil
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read plugin manifest %q: %w", manifestPath, err)
	}
	manifest, err := LoadManifestContent(manifestBytes, manifestPath)
	if err != nil {
		return nil, err
	}
	state, err := LoadState(directory)
	if err != nil {
		return nil, err
	}
	verification, err := verifyManifestSignature(directory, manifestBytes, cfg)
	if err != nil {
		return nil, err
	}
	if err := ValidateManifestPermissions(manifest, cfg); err != nil {
		return nil, fmt.Errorf("plugin in %q: %w", directory, err)
	}
	packageSHA256 := ""
	if state != nil {
		packageSHA256 = strings.TrimSpace(state.PackageSHA256)
	}
	return &LocalPlugin{
		Directory:     directory,
		Manifest:      manifest,
		ManifestBytes: manifestBytes,
		State:         state,
		Enabled:       resolveEnabled(manifest.ID, state, enabledFilter, disabledFilter),
		PackageSHA256: packageSHA256,
		Verification:  verification,
	}, nil
}

func verifyManifestSignature(directory string, manifestBytes []byte, cfg config.PluginsConfig) (VerificationResult, error) {
	signature, err := loadSignatureEnvelope(directory)
	if err != nil {
		return VerificationResult{}, err
	}
	if signature == nil {
		if cfg.RequireSignature {
			return VerificationResult{}, fmt.Errorf("plugin in %q requires a trusted signature", directory)
		}
		return VerificationResult{}, nil
	}

	algorithm := strings.ToLower(strings.TrimSpace(signature.Algorithm))
	if algorithm == "" {
		algorithm = "ed25519"
	}
	if algorithm != "ed25519" {
		return VerificationResult{}, fmt.Errorf("plugin in %q uses unsupported signature algorithm %q", directory, signature.Algorithm)
	}

	keyID := strings.TrimSpace(signature.KeyID)
	if keyID == "" {
		return VerificationResult{}, fmt.Errorf("plugin in %q missing signature key_id", directory)
	}

	publicKey, err := trustedPublicKey(cfg.TrustedSigners, keyID, algorithm)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("plugin in %q: %w", directory, err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signature.Signature))
	if err != nil {
		return VerificationResult{}, fmt.Errorf("plugin in %q has invalid base64 signature: %w", directory, err)
	}
	if !ed25519.Verify(publicKey, manifestBytes, sigBytes) {
		return VerificationResult{}, fmt.Errorf("plugin in %q failed signature verification for key %q", directory, keyID)
	}
	return VerificationResult{Verified: true, KeyID: keyID}, nil
}

func loadSignatureEnvelope(directory string) (*SignatureEnvelope, error) {
	path, ok := findSignatureFile(directory)
	if !ok {
		return nil, nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read plugin signature %q: %w", path, err)
	}
	var envelope SignatureEnvelope
	if err := yaml.Unmarshal(content, &envelope); err != nil {
		return nil, fmt.Errorf("parse plugin signature %q: %w", path, err)
	}
	return &envelope, nil
}

func findSignatureFile(directory string) (string, bool) {
	for _, name := range []string{"mkauth-plugin.sig", "plugin.sig"} {
		path := filepath.Join(directory, name)
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}

func trustedPublicKey(signers []config.PluginSignerConfig, keyID, algorithm string) (ed25519.PublicKey, error) {
	for _, signer := range signers {
		if strings.TrimSpace(signer.ID) != keyID {
			continue
		}
		signerAlgorithm := strings.ToLower(strings.TrimSpace(signer.Algorithm))
		if signerAlgorithm == "" {
			signerAlgorithm = "ed25519"
		}
		if signerAlgorithm != algorithm {
			return nil, fmt.Errorf("trusted signer %q does not support algorithm %q", keyID, algorithm)
		}
		publicKey, err := parsePublicKey(signer.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("trusted signer %q has invalid public key: %w", keyID, err)
		}
		return publicKey, nil
	}
	return nil, fmt.Errorf("plugin signer %q is not trusted", keyID)
}

func parsePublicKey(raw string) (ed25519.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("public key is required")
	}
	if block, _ := pem.Decode([]byte(raw)); block != nil {
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		edKey, ok := publicKey.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not ed25519")
		}
		return edKey, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", ed25519.PublicKeySize, len(decoded))
	}
	return ed25519.PublicKey(decoded), nil
}

func sha256Hex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
