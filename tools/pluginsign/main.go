package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printRootUsage()
		return nil
	}

	switch args[0] {
	case "genkey":
		return runGenKey(args[1:])
	case "sign":
		return runSign(args[1:])
	case "verify":
		return runVerify(args[1:])
	case "-h", "--help", "help":
		printRootUsage()
		return nil
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func runGenKey(args []string) error {
	fs := flag.NewFlagSet("genkey", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	keyID := fs.String("key-id", "mkauth-dev", "trusted signer id")
	outPrivate := fs.String("out-private", "plugin-signing.key.pem", "output private key PEM path")
	outPublic := fs.String("out-public", "plugin-signing.pub", "output public key base64 path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519 key pair: %w", err)
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})

	if err := os.WriteFile(*outPrivate, privatePEM, 0o600); err != nil {
		return fmt.Errorf("write private key %q: %w", *outPrivate, err)
	}

	publicBase64 := base64.StdEncoding.EncodeToString(publicKey)
	if err := os.WriteFile(*outPublic, []byte(publicBase64+"\n"), 0o644); err != nil {
		return fmt.Errorf("write public key %q: %w", *outPublic, err)
	}

	fmt.Printf("Private key written to: %s\n", *outPrivate)
	fmt.Printf("Public key written to: %s\n", *outPublic)
	fmt.Println("Config snippet:")
	fmt.Printf("trusted_signers:\n  - id: %q\n    algorithm: %q\n    public_key: %q\n", *keyID, "ed25519", publicBase64)
	return nil
}

func runSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	manifestPath := fs.String("manifest", "", "path to mkauth-plugin.yaml")
	privateKeyPath := fs.String("private-key", "", "path to ed25519 private key PEM")
	keyID := fs.String("key-id", "mkauth-dev", "trusted signer id")
	out := fs.String("out", "", "output signature path (defaults to manifest dir/mkauth-plugin.sig)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*manifestPath) == "" {
		return errors.New("sign requires -manifest")
	}
	if strings.TrimSpace(*privateKeyPath) == "" {
		return errors.New("sign requires -private-key")
	}

	manifestContent, err := os.ReadFile(*manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest %q: %w", *manifestPath, err)
	}
	privateKey, err := loadPrivateKey(*privateKeyPath)
	if err != nil {
		return err
	}

	signature := ed25519.Sign(privateKey, manifestContent)
	signaturePath := strings.TrimSpace(*out)
	if signaturePath == "" {
		signaturePath = filepath.Join(filepath.Dir(*manifestPath), "mkauth-plugin.sig")
	}
	content := fmt.Sprintf("key_id: %q\nalgorithm: %q\nsignature: %q\n", *keyID, "ed25519", base64.StdEncoding.EncodeToString(signature))
	if err := os.WriteFile(signaturePath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write signature %q: %w", signaturePath, err)
	}

	fmt.Printf("Signature written to: %s\n", signaturePath)
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	manifestPath := fs.String("manifest", "", "path to mkauth-plugin.yaml")
	signaturePath := fs.String("signature", "", "path to mkauth-plugin.sig")
	publicKeyPath := fs.String("public-key-file", "", "path to signer public key (base64 or PEM)")
	publicKeyRaw := fs.String("public-key", "", "signer public key in base64 or PEM")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*manifestPath) == "" {
		return errors.New("verify requires -manifest")
	}
	if strings.TrimSpace(*signaturePath) == "" {
		*signaturePath = filepath.Join(filepath.Dir(*manifestPath), "mkauth-plugin.sig")
	}
	if strings.TrimSpace(*publicKeyPath) == "" && strings.TrimSpace(*publicKeyRaw) == "" {
		return errors.New("verify requires -public-key-file or -public-key")
	}

	manifestContent, err := os.ReadFile(*manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest %q: %w", *manifestPath, err)
	}
	signatureEnvelope, err := loadSignatureEnvelope(*signaturePath)
	if err != nil {
		return err
	}
	if strings.ToLower(signatureEnvelope.Algorithm) != "ed25519" {
		return fmt.Errorf("unsupported signature algorithm %q", signatureEnvelope.Algorithm)
	}

	publicKeySource := strings.TrimSpace(*publicKeyRaw)
	if publicKeySource == "" {
		raw, err := os.ReadFile(*publicKeyPath)
		if err != nil {
			return fmt.Errorf("read public key %q: %w", *publicKeyPath, err)
		}
		publicKeySource = string(raw)
	}
	publicKey, err := parsePublicKey(publicKeySource)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signatureEnvelope.Signature))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(publicKey, manifestContent, signature) {
		return errors.New("signature verification failed")
	}

	fmt.Printf("Signature verified successfully for key_id=%s\n", signatureEnvelope.KeyID)
	return nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key %q: %w", path, err)
	}
	block, _ := pem.Decode(content)
	if block == nil {
		return nil, fmt.Errorf("private key %q is not valid PEM", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key %q: %w", path, err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key %q is not ed25519", path)
	}
	return privateKey, nil
}

func parsePublicKey(raw string) (ed25519.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("public key is required")
	}
	if block, _ := pem.Decode([]byte(raw)); block != nil {
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		publicKey, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("PEM public key is not ed25519")
		}
		return publicKey, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d public key bytes, got %d", ed25519.PublicKeySize, len(decoded))
	}
	return ed25519.PublicKey(decoded), nil
}

type signatureEnvelope struct {
	KeyID     string
	Algorithm string
	Signature string
}

func loadSignatureEnvelope(path string) (signatureEnvelope, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return signatureEnvelope{}, fmt.Errorf("read signature %q: %w", path, err)
	}
	lines := strings.Split(string(content), "\n")
	env := signatureEnvelope{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch key {
		case "key_id":
			env.KeyID = value
		case "algorithm":
			env.Algorithm = value
		case "signature":
			env.Signature = value
		}
	}
	if strings.TrimSpace(env.KeyID) == "" {
		return signatureEnvelope{}, fmt.Errorf("signature %q missing key_id", path)
	}
	if strings.TrimSpace(env.Algorithm) == "" {
		env.Algorithm = "ed25519"
	}
	if strings.TrimSpace(env.Signature) == "" {
		return signatureEnvelope{}, fmt.Errorf("signature %q missing signature", path)
	}
	return env, nil
}

func printRootUsage() {
	fmt.Println("Usage:")
	fmt.Println("  go run ./pluginsign genkey -key-id mkauth-dev -out-private ./plugin-signing.key.pem -out-public ./plugin-signing.pub")
	fmt.Println("  go run ./pluginsign sign -manifest ../examples/plugins/http-claims-action/mkauth-plugin.yaml -private-key ./plugin-signing.key.pem -key-id mkauth-dev")
	fmt.Println("  go run ./pluginsign verify -manifest ../examples/plugins/http-claims-action/mkauth-plugin.yaml -signature ../examples/plugins/http-claims-action/mkauth-plugin.sig -public-key-file ./plugin-signing.pub")
}
