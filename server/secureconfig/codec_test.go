package secureconfig

import (
	"strings"
	"testing"
)

func TestCodecEncryptsAndDecryptsJSON(t *testing.T) {
	codec, err := New("test-key")
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	sealed, err := codec.SealJSON(map[string]string{"client_secret": "super-secret"})
	if err != nil {
		t.Fatalf("SealJSON() returned error: %v", err)
	}
	if !strings.HasPrefix(sealed, encryptedPrefix) {
		t.Fatalf("expected encrypted prefix, got %q", sealed)
	}
	var decoded map[string]string
	if err := codec.OpenJSON(sealed, &decoded); err != nil {
		t.Fatalf("OpenJSON() returned error: %v", err)
	}
	if decoded["client_secret"] != "super-secret" {
		t.Fatalf("unexpected decoded payload: %#v", decoded)
	}
}

func TestOpenJSONWithoutCodecStillSupportsPlaintext(t *testing.T) {
	SetDefault(nil)
	var decoded map[string]string
	if err := OpenJSON(`{"client_secret":"plain"}`, &decoded); err != nil {
		t.Fatalf("OpenJSON() returned error: %v", err)
	}
	if decoded["client_secret"] != "plain" {
		t.Fatalf("unexpected decoded payload: %#v", decoded)
	}
}

func TestCodecSupportsFallbackKeysForRotation(t *testing.T) {
	oldCodec, err := New("old-key")
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	sealed, err := oldCodec.SealJSON(map[string]string{"client_secret": "legacy-secret"})
	if err != nil {
		t.Fatalf("SealJSON() returned error: %v", err)
	}

	rotatedCodec, err := New("new-key", "old-key")
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	var decoded map[string]string
	if err := rotatedCodec.OpenJSON(sealed, &decoded); err != nil {
		t.Fatalf("OpenJSON() with fallback returned error: %v", err)
	}
	if decoded["client_secret"] != "legacy-secret" {
		t.Fatalf("unexpected decoded payload: %#v", decoded)
	}

	resealed, err := rotatedCodec.SealJSON(decoded)
	if err != nil {
		t.Fatalf("SealJSON() returned error: %v", err)
	}
	if resealed == sealed {
		t.Fatalf("expected resealed payload to change")
	}
}
