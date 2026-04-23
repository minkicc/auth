package plugins

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const pluginDownloadTimeout = 20 * time.Second

func (r *Runtime) ListCatalogEntries(ctx context.Context) ([]CatalogEntry, error) {
	if r == nil {
		return nil, nil
	}
	return LoadCatalogEntries(ctx, r.cfg)
}

func (r *Runtime) InstallCatalogEntry(ctx context.Context, catalogID, pluginID string, replace bool) (Summary, error) {
	if r == nil {
		return Summary{}, fmt.Errorf("plugin runtime is not initialized")
	}
	catalogID = strings.TrimSpace(catalogID)
	pluginID = strings.TrimSpace(pluginID)
	if catalogID == "" || pluginID == "" {
		return Summary{}, fmt.Errorf("catalog_id and plugin_id are required")
	}

	items, err := LoadCatalogEntries(ctx, r.cfg)
	if err != nil {
		return Summary{}, err
	}
	for _, item := range items {
		if item.CatalogID == catalogID && item.ID == pluginID {
			return r.InstallURL(ctx, item.DownloadURL, item.PackageSHA256, fmt.Sprintf("catalog:%s:%s", catalogID, pluginID), replace)
		}
	}
	return Summary{}, fmt.Errorf("catalog plugin %s/%s was not found", catalogID, pluginID)
}

func (r *Runtime) InstallURL(ctx context.Context, rawURL, expectedSHA256, source string, replace bool) (Summary, error) {
	if r == nil {
		return Summary{}, fmt.Errorf("plugin runtime is not initialized")
	}
	downloadURL, err := validateRemoteURL(rawURL)
	if err != nil {
		return Summary{}, err
	}
	if err := requireHostAllowed("plugin download", downloadURL, r.cfg.AllowedDownloadHosts, len(r.cfg.AllowedDownloadHosts) == 0); err != nil {
		return Summary{}, err
	}
	content, filename, err := downloadPluginArchive(ctx, downloadURL, allowlistForRequest(downloadURL.Host, r.cfg.AllowedDownloadHosts), r.cfg.AllowPrivateNetworks)
	if err != nil {
		return Summary{}, err
	}
	if expected := strings.TrimSpace(strings.ToLower(expectedSHA256)); expected != "" {
		actual := sha256Hex(content)
		if actual != expected {
			return Summary{}, fmt.Errorf("downloaded plugin checksum mismatch: expected %s got %s", expected, actual)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	return r.installArchiveLocked(filename, content, replace, sourceForURLInstall(downloadURL.String(), source))
}

func sourceForURLInstall(downloadURL, source string) string {
	source = strings.TrimSpace(source)
	if source != "" {
		return source
	}
	return "url:" + strings.TrimSpace(downloadURL)
}

func downloadPluginArchive(ctx context.Context, downloadURL *url.URL, allowlist []string, allowPrivateNetworks bool) ([]byte, string, error) {
	client := newRestrictedHTTPClient(pluginDownloadTimeout, allowlist, allowPrivateNetworks)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		return nil, "", fmt.Errorf("create plugin download request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("download plugin archive: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", fmt.Errorf("plugin archive download returned status %d", resp.StatusCode)
	}

	content, err := io.ReadAll(io.LimitReader(resp.Body, maxPluginPackageSize+1))
	if err != nil {
		return nil, "", fmt.Errorf("read plugin archive: %w", err)
	}
	if len(content) > maxPluginPackageSize {
		return nil, "", fmt.Errorf("plugin archive exceeds the size limit")
	}
	filename := downloadFileName(downloadURL, resp.Header.Get("Content-Disposition"))
	if filename == "" {
		filename = "plugin.zip"
	}
	return content, filename, nil
}

func downloadFileName(downloadURL *url.URL, contentDisposition string) string {
	if contentDisposition != "" {
		if _, params, err := mime.ParseMediaType(contentDisposition); err == nil {
			if filename := strings.TrimSpace(params["filename"]); filename != "" {
				return path.Base(strings.ReplaceAll(filename, "\\", "/"))
			}
		}
	}
	if downloadURL == nil {
		return ""
	}
	name := path.Base(downloadURL.Path)
	if name == "." || name == "/" {
		return ""
	}
	return name
}
