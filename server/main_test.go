package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"minki.cc/mkauth/server/config"
)

func TestCollectAllowedOrigins(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			Google: config.GoogleConfig{
				RedirectURL: "https://console.example.com/google/callback",
			},
			Weixin: config.WeixinConfig{
				RedirectURL: "https://console.example.com/weixin/callback",
			},
		},
		OIDC: config.OIDCConfig{
			Issuer: "https://auth.example.com",
			Clients: []config.OIDCClientConfig{
				{
					ClientID: "demo-spa",
					RedirectURIs: []string{
						"https://app.example.com/auth/callback",
						"https://app.example.com/another",
						"http://localhost:3000/callback",
					},
				},
			},
		},
	}

	got := collectAllowedOrigins(cfg)
	want := []string{
		"http://localhost:3000",
		"https://app.example.com",
		"https://auth.example.com",
		"https://console.example.com",
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collectAllowedOrigins() = %v, want %v", got, want)
	}
}

func TestDatabaseConfigEffectiveDriver(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.DatabaseConfig
		want string
	}{
		{
			name: "defaults to sqlite without mysql config",
			cfg:  config.DatabaseConfig{},
			want: "sqlite",
		},
		{
			name: "uses mysql when mysql config is present",
			cfg: config.DatabaseConfig{
				Host:     "127.0.0.1",
				Username: "root",
				Database: "mkauth",
			},
			want: "mysql",
		},
		{
			name: "explicit sqlite overrides mysql fields",
			cfg: config.DatabaseConfig{
				Driver:   "sqlite",
				Host:     "127.0.0.1",
				Username: "root",
				Database: "mkauth",
			},
			want: "sqlite",
		},
		{
			name: "explicit mysql is respected",
			cfg: config.DatabaseConfig{
				Driver: "mysql",
			},
			want: "mysql",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.EffectiveDriver(); got != tt.want {
				t.Fatalf("EffectiveDriver() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOpenDatabaseFallsBackToSQLite(t *testing.T) {
	sqlitePath := filepath.Join(t.TempDir(), "data", "mkauth.sqlite3")
	db, err := openDatabase(config.DatabaseConfig{
		SQLitePath: sqlitePath,
	})
	if err != nil {
		t.Fatalf("openDatabase() returned error: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db.DB() returned error: %v", err)
	}
	defer sqlDB.Close()

	if _, err := os.Stat(sqlitePath); err != nil {
		t.Fatalf("expected sqlite database file to exist at %s: %v", sqlitePath, err)
	}
}
