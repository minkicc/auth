package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalStorageObjectLifecycle(t *testing.T) {
	root := t.TempDir()
	client, err := NewLocalClient(&ClientConfig{Provider: LOCAL, LocalPath: root})
	if err != nil {
		t.Fatalf("create local client: %v", err)
	}
	bucket := client.NewBucket(&BucketConfig{AttatchBucket: "attachments"})
	if _, err := bucket.PutObject(&PutObjectInput{ObjectName: "avatars/user/avatar.png", Reader: bytes.NewBufferString("image-data")}); err != nil {
		t.Fatalf("put object: %v", err)
	}
	content, err := bucket.GetObject("avatars/user/avatar.png")
	if err != nil || string(content) != "image-data" {
		t.Fatalf("get object: content=%q err=%v", content, err)
	}
	if _, err := bucket.GetObjectInfo("avatars/user/avatar.png"); err != nil {
		t.Fatalf("stat object: %v", err)
	}
	if _, err := bucket.CopyObject("avatars/user/avatar.png", "avatars/user/copy.png"); err != nil {
		t.Fatalf("copy object: %v", err)
	}
	if err := bucket.DeleteObject("avatars/user/copy.png"); err != nil {
		t.Fatalf("delete object: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "attachments", "avatars", "user", "copy.png")); !os.IsNotExist(err) {
		t.Fatalf("expected copied object to be deleted, got %v", err)
	}
}

func TestLocalStorageRejectsPathTraversal(t *testing.T) {
	client, err := NewLocalClient(&ClientConfig{Provider: LOCAL, LocalPath: t.TempDir()})
	if err != nil {
		t.Fatalf("create local client: %v", err)
	}
	bucket := client.NewBucket(&BucketConfig{AttatchBucket: "attachments"})
	for _, objectName := range []string{"../outside", "/absolute", `..\outside`} {
		if _, err := bucket.PutObjectByte(objectName, []byte("bad")); err == nil {
			t.Fatalf("expected %q to be rejected", objectName)
		}
	}
}
