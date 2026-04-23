package plugins

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const StateFileName = "mkauth-plugin.state.yaml"

type State struct {
	Enabled       *bool             `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Source        string            `json:"source,omitempty" yaml:"source,omitempty"`
	PackageSHA256 string            `json:"package_sha256,omitempty" yaml:"package_sha256,omitempty"`
	Config        map[string]string `json:"config,omitempty" yaml:"config,omitempty"`
	InstalledAt   string            `json:"installed_at,omitempty" yaml:"installed_at,omitempty"`
	UpdatedAt     string            `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
}

func LoadState(directory string) (*State, error) {
	directory = filepath.Clean(directory)
	if directory == "." || directory == "" {
		return nil, nil
	}
	content, err := os.ReadFile(filepath.Join(directory, StateFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read plugin state in %q: %w", directory, err)
	}
	var state State
	if err := yaml.Unmarshal(content, &state); err != nil {
		return nil, fmt.Errorf("parse plugin state in %q: %w", directory, err)
	}
	return &state, nil
}

func SaveState(directory string, state State) error {
	directory = filepath.Clean(directory)
	if directory == "." || directory == "" {
		return fmt.Errorf("plugin state directory is required")
	}
	if state.UpdatedAt == "" {
		state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	content, err := yaml.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal plugin state in %q: %w", directory, err)
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create plugin state directory %q: %w", directory, err)
	}
	if err := os.WriteFile(filepath.Join(directory, StateFileName), content, 0o600); err != nil {
		return fmt.Errorf("write plugin state in %q: %w", directory, err)
	}
	return nil
}
