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
		r.appendAudit(AuditEvent{
			Action:   "install_catalog",
			PluginID: pluginID,
			Source:   fmt.Sprintf("catalog:%s:%s", catalogID, pluginID),
			Actor:    AuditActorFromContext(ctx),
			Success:  false,
			Error:    "catalog_id and plugin_id are required",
			Details: map[string]string{
				"replace": fmt.Sprintf("%t", replace),
			},
		})
		return Summary{}, fmt.Errorf("catalog_id and plugin_id are required")
	}

	items, err := LoadCatalogEntries(ctx, r.cfg)
	if err != nil {
		r.appendAudit(AuditEvent{
			Action:   "install_catalog",
			PluginID: pluginID,
			Source:   fmt.Sprintf("catalog:%s:%s", catalogID, pluginID),
			Actor:    AuditActorFromContext(ctx),
			Success:  false,
			Error:    auditError(err),
			Details: map[string]string{
				"replace": fmt.Sprintf("%t", replace),
			},
		})
		return Summary{}, err
	}
	for _, item := range items {
		if item.CatalogID == catalogID && item.ID == pluginID {
			return r.installURL(ctx, item.DownloadURL, item.PackageSHA256, fmt.Sprintf("catalog:%s:%s", catalogID, pluginID), replace, "install_catalog")
		}
	}
	r.appendAudit(AuditEvent{
		Action:   "install_catalog",
		PluginID: pluginID,
		Source:   fmt.Sprintf("catalog:%s:%s", catalogID, pluginID),
		Actor:    AuditActorFromContext(ctx),
		Success:  false,
		Error:    fmt.Sprintf("catalog plugin %s/%s was not found", catalogID, pluginID),
		Details: map[string]string{
			"replace": fmt.Sprintf("%t", replace),
		},
	})
	return Summary{}, fmt.Errorf("catalog plugin %s/%s was not found", catalogID, pluginID)
}

func (r *Runtime) InstallURL(ctx context.Context, rawURL, expectedSHA256, source string, replace bool) (Summary, error) {
	return r.installURL(ctx, rawURL, expectedSHA256, source, replace, "install_url")
}

func (r *Runtime) installURL(ctx context.Context, rawURL, expectedSHA256, source string, replace bool, action string) (summary Summary, err error) {
	if r == nil {
		return Summary{}, fmt.Errorf("plugin runtime is not initialized")
	}
	sourceValue := sourceForURLInstall(rawURL, source)
	actor := AuditActorFromContext(ctx)
	filename := ""
	pluginID, pluginName, version := "", "", ""
	previousDetails := map[string]string(nil)
	defer func() {
		if summary.ID != "" {
			pluginID = summary.ID
			pluginName = summary.Name
			version = summary.Version
		}
		r.appendAudit(AuditEvent{
			Action:     action,
			PluginID:   pluginID,
			PluginName: pluginName,
			Version:    version,
			Source:     sourceValue,
			Actor:      actor,
			Success:    err == nil,
			Error:      auditError(err),
			Details: mergeAuditDetails(auditSummaryDetails(summary), previousDetails, map[string]string{
				"filename":                filename,
				"expected_package_sha256": strings.TrimSpace(strings.ToLower(expectedSHA256)),
				"replace":                 fmt.Sprintf("%t", replace),
				"requested_download_url":  strings.TrimSpace(rawURL),
			}),
		})
	}()

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
	if manifest, _, _, parseErr := parsePluginArchive(content); parseErr == nil {
		pluginID = manifest.ID
		pluginName = manifest.Name
		version = manifest.Version
	}
	if expected := strings.TrimSpace(strings.ToLower(expectedSHA256)); expected != "" {
		actual := sha256Hex(content)
		if actual != expected {
			return Summary{}, fmt.Errorf("downloaded plugin checksum mismatch: expected %s got %s", expected, actual)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if replace && pluginID != "" {
		if previous, ok := r.registry.Get(pluginID); ok {
			previousDetails = auditPreviousSummaryDetails(previous)
		}
	}
	summary, err = r.installArchiveLocked(filename, content, replace, sourceValue)
	return summary, err
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
