package storage

import "testing"

func TestNewStorageClientSupportsR2(t *testing.T) {
	client, err := NewStorageClient(&Config{
		ClientConfig: ClientConfig{
			Provider:        R2,
			Endpoint:        "https://example-account.r2.cloudflarestorage.com",
			AccessKeyID:     "test-access-key",
			SecretAccessKey: "test-secret-key",
		},
		BucketConfig: BucketConfig{
			AttatchBucket: "mkauth-avatar",
		},
	})
	if err != nil {
		t.Fatalf("NewStorageClient returned error: %v", err)
	}
	if client == nil || client.Bucket == nil {
		t.Fatalf("expected R2 storage client and bucket to be initialized")
	}

	cfg := client.Bucket.GetConfig()
	if cfg.Provider != R2 {
		t.Fatalf("expected provider %q, got %q", R2, cfg.Provider)
	}
	if cfg.Region != "auto" {
		t.Fatalf("expected default R2 region auto, got %q", cfg.Region)
	}
	if cfg.AttatchBucket != "mkauth-avatar" {
		t.Fatalf("expected bucket mkauth-avatar, got %q", cfg.AttatchBucket)
	}
}
