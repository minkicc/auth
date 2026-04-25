package secureconfig

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
)

const encryptedPrefix = "enc:v1:"

type Codec struct {
	encryptKey  []byte
	decryptKeys [][]byte
}

var (
	defaultCodecMu sync.RWMutex
	defaultCodec   *Codec
)

func New(rawKeys ...string) (*Codec, error) {
	normalizedKeys := normalizeKeys(rawKeys)
	if len(normalizedKeys) == 0 {
		return nil, nil
	}
	decryptKeys := make([][]byte, 0, len(normalizedKeys))
	for _, rawKey := range normalizedKeys {
		sum := sha256.Sum256([]byte(rawKey))
		key := make([]byte, len(sum))
		copy(key, sum[:])
		decryptKeys = append(decryptKeys, key)
	}
	return &Codec{
		encryptKey:  decryptKeys[0],
		decryptKeys: decryptKeys,
	}, nil
}

func SetDefault(codec *Codec) {
	defaultCodecMu.Lock()
	defaultCodec = codec
	defaultCodecMu.Unlock()
}

func Default() *Codec {
	defaultCodecMu.RLock()
	codec := defaultCodec
	defaultCodecMu.RUnlock()
	return codec
}

func Enabled() bool {
	return Default() != nil
}

func LooksEncrypted(raw string) bool {
	return strings.HasPrefix(strings.TrimSpace(raw), encryptedPrefix)
}

func SealJSON(value any) (string, error) {
	if codec := Default(); codec != nil {
		return codec.SealJSON(value)
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func OpenJSON(raw string, out any) error {
	if codec := Default(); codec != nil {
		return codec.OpenJSON(raw, out)
	}
	if strings.HasPrefix(strings.TrimSpace(raw), encryptedPrefix) {
		return fmt.Errorf("secure config requires secrets.encryption_key to decrypt stored data")
	}
	return json.Unmarshal([]byte(raw), out)
}

func (c *Codec) SealJSON(value any) (string, error) {
	if c == nil {
		return SealJSON(value)
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(c.encryptKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, payload, nil)
	blob := append(nonce, ciphertext...)
	return encryptedPrefix + base64.RawURLEncoding.EncodeToString(blob), nil
}

func (c *Codec) OpenJSON(raw string, out any) error {
	raw = strings.TrimSpace(raw)
	if c == nil {
		return OpenJSON(raw, out)
	}
	if !strings.HasPrefix(raw, encryptedPrefix) {
		return json.Unmarshal([]byte(raw), out)
	}
	encoded := strings.TrimPrefix(raw, encryptedPrefix)
	blob, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("decode secure config: %w", err)
	}
	var decryptErr error
	for _, key := range c.decryptKeys {
		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		if len(blob) < gcm.NonceSize() {
			return fmt.Errorf("decode secure config: ciphertext too short")
		}
		nonce := blob[:gcm.NonceSize()]
		ciphertext := blob[gcm.NonceSize():]
		payload, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			decryptErr = err
			continue
		}
		return json.Unmarshal(payload, out)
	}
	if decryptErr != nil {
		return fmt.Errorf("decrypt secure config: %w", decryptErr)
	}
	return fmt.Errorf("decrypt secure config: no keys configured")
}

func normalizeKeys(rawKeys []string) []string {
	if len(rawKeys) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(rawKeys))
	normalized := make([]string, 0, len(rawKeys))
	for _, rawKey := range rawKeys {
		rawKey = strings.TrimSpace(rawKey)
		if rawKey == "" {
			continue
		}
		if _, exists := seen[rawKey]; exists {
			continue
		}
		seen[rawKey] = struct{}{}
		normalized = append(normalized, rawKey)
	}
	return normalized
}
