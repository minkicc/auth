/*
 * Licensed under the MIT License.
 */

package storage

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const defaultLocalStoragePath = "data/storage"

type LocalClient struct {
	config *ClientConfig
	root   string
}

func NewLocalClient(config *ClientConfig) (Client, error) {
	root := strings.TrimSpace(config.LocalPath)
	if root == "" {
		root = defaultLocalStoragePath
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve local storage path: %w", err)
	}
	if err := os.MkdirAll(absRoot, 0o755); err != nil {
		return nil, fmt.Errorf("create local storage path: %w", err)
	}
	return &LocalClient{config: config, root: absRoot}, nil
}

type LocalBucket struct {
	DefaultBucket
	config *BucketConfig
	client *LocalClient
	root   string
}

func (c *LocalClient) NewBucket(config *BucketConfig) Bucket {
	bucketName := strings.TrimSpace(config.AttatchBucket)
	bucket := &LocalBucket{
		config: config,
		client: c,
		root:   filepath.Join(c.root, bucketName),
	}
	bucket.That = bucket
	return bucket
}

func (b *LocalBucket) GetConfig() *Config {
	return &Config{ClientConfig: *b.client.config, BucketConfig: *b.config}
}

func (b *LocalBucket) objectPath(objectName string) (string, error) {
	if strings.TrimSpace(b.config.AttatchBucket) == "" || strings.ContainsAny(b.config.AttatchBucket, `/\\`) {
		return "", errors.New("invalid local storage bucket")
	}
	objectName = strings.TrimSpace(strings.ReplaceAll(objectName, `\`, "/"))
	cleaned := filepath.Clean(filepath.FromSlash(objectName))
	if objectName == "" || cleaned == "." || filepath.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", errors.New("invalid local storage object path")
	}
	candidate := filepath.Join(b.root, cleaned)
	relative, err := filepath.Rel(b.root, candidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("local storage object escapes bucket")
	}
	return candidate, nil
}

func (b *LocalBucket) PutObject(input *PutObjectInput) (*UploadInfo, error) {
	if input == nil || input.Reader == nil {
		return nil, errors.New("local storage object reader is required")
	}
	destination, err := b.objectPath(input.ObjectName)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return nil, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".upload-*")
	if err != nil {
		return nil, err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return nil, err
	}
	if _, err := io.Copy(temporary, input.Reader); err != nil {
		temporary.Close()
		return nil, err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return nil, err
	}
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(temporaryName, destination); err != nil {
		return nil, err
	}
	info, err := os.Stat(destination)
	if err != nil {
		return nil, err
	}
	return &UploadInfo{VersionID: strconv.FormatInt(info.ModTime().UnixNano(), 10)}, nil
}

func (b *LocalBucket) GetObjectInfo(objectName string) (*ObjectInfo, error) {
	objectPath, err := b.objectPath(objectName)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(objectPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("local storage object is not a regular file")
	}
	return &ObjectInfo{VersionID: strconv.FormatInt(info.ModTime().UnixNano(), 10)}, nil
}

func (b *LocalBucket) GetObject(objectName string) ([]byte, error) {
	objectPath, err := b.objectPath(objectName)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(objectPath)
}

func (b *LocalBucket) GenerateAccessKey(string, int, int, string) (*AccessKeyValue, error) {
	return nil, errors.New("temporary access keys are not supported by local storage")
}

func (b *LocalBucket) CopyObject(sourceName, destinationName string) (*UploadInfo, error) {
	source, err := b.GetObject(sourceName)
	if err != nil {
		return nil, err
	}
	return b.PutObjectByte(destinationName, source)
}

func (b *LocalBucket) CopyDirectory(sourceDirectory, destinationDirectory string) (*UploadInfo, error) {
	sourceRoot, err := b.objectPath(sourceDirectory)
	if err != nil {
		return nil, err
	}
	if _, err := b.objectPath(destinationDirectory); err != nil {
		return nil, err
	}
	err = filepath.WalkDir(sourceRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			return err
		}
		destinationName := filepath.ToSlash(filepath.Join(destinationDirectory, relative))
		sourceName := filepath.ToSlash(filepath.Join(sourceDirectory, relative))
		_, err = b.CopyObject(sourceName, destinationName)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &UploadInfo{}, nil
}

func (b *LocalBucket) DeleteObject(objectName string) error {
	objectPath, err := b.objectPath(objectName)
	if err != nil {
		return err
	}
	return os.Remove(objectPath)
}
