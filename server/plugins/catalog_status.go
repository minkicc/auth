package plugins

import (
	"strconv"
	"strings"
)

func annotateCatalogEntries(entries []CatalogEntry, registry *Registry) []CatalogEntry {
	if len(entries) == 0 || registry == nil {
		return entries
	}
	annotated := make([]CatalogEntry, len(entries))
	copy(annotated, entries)
	for i := range annotated {
		installed, ok := registry.Get(annotated[i].ID)
		if !ok {
			continue
		}
		annotated[i].Installed = true
		annotated[i].InstalledVersion = installed.Version
		annotated[i].InstalledSource = installed.Source
		annotated[i].InstalledPackageSHA256 = installed.PackageSHA256
		annotated[i].UpdateAvailable, annotated[i].UpdateReason = catalogUpdateStatus(annotated[i], installed)
	}
	return annotated
}

func catalogUpdateStatus(entry CatalogEntry, installed Summary) (bool, string) {
	catalogVersion := strings.TrimSpace(entry.Version)
	installedVersion := strings.TrimSpace(installed.Version)
	if cmp, ok := comparePluginVersions(catalogVersion, installedVersion); ok {
		if cmp > 0 {
			return true, "newer_version"
		}
		if cmp < 0 {
			return false, ""
		}
	} else if catalogVersion != "" && installedVersion != "" && catalogVersion != installedVersion {
		return true, "version_changed"
	}

	catalogSHA := strings.TrimSpace(strings.ToLower(entry.PackageSHA256))
	installedSHA := strings.TrimSpace(strings.ToLower(installed.PackageSHA256))
	if catalogSHA != "" && installedSHA != "" && catalogSHA != installedSHA {
		return true, "package_changed"
	}
	return false, ""
}

func comparePluginVersions(next, current string) (int, bool) {
	nextVersion, ok := parsePluginVersion(next)
	if !ok {
		return 0, false
	}
	currentVersion, ok := parsePluginVersion(current)
	if !ok {
		return 0, false
	}
	maxLen := len(nextVersion.parts)
	if len(currentVersion.parts) > maxLen {
		maxLen = len(currentVersion.parts)
	}
	for i := 0; i < maxLen; i++ {
		nextPart, currentPart := 0, 0
		if i < len(nextVersion.parts) {
			nextPart = nextVersion.parts[i]
		}
		if i < len(currentVersion.parts) {
			currentPart = currentVersion.parts[i]
		}
		if nextPart > currentPart {
			return 1, true
		}
		if nextPart < currentPart {
			return -1, true
		}
	}
	if nextVersion.prerelease == "" && currentVersion.prerelease != "" {
		return 1, true
	}
	if nextVersion.prerelease != "" && currentVersion.prerelease == "" {
		return -1, true
	}
	if nextVersion.prerelease > currentVersion.prerelease {
		return 1, true
	}
	if nextVersion.prerelease < currentVersion.prerelease {
		return -1, true
	}
	return 0, true
}

type pluginVersion struct {
	parts      []int
	prerelease string
}

func parsePluginVersion(raw string) (pluginVersion, bool) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "v")
	raw = strings.TrimPrefix(raw, "V")
	if raw == "" {
		return pluginVersion{}, false
	}
	if buildIndex := strings.Index(raw, "+"); buildIndex >= 0 {
		raw = raw[:buildIndex]
	}
	version := pluginVersion{}
	if preIndex := strings.Index(raw, "-"); preIndex >= 0 {
		version.prerelease = raw[preIndex+1:]
		raw = raw[:preIndex]
	}
	segments := strings.Split(raw, ".")
	version.parts = make([]int, 0, len(segments))
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return pluginVersion{}, false
		}
		value, err := strconv.Atoi(segment)
		if err != nil || value < 0 {
			return pluginVersion{}, false
		}
		version.parts = append(version.parts, value)
	}
	return version, len(version.parts) > 0
}
