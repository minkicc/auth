/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
	"minki.cc/mkauth/server/auth/storage"
)

// Config Main configuration structure
type Config struct {
	// Server         ServerConfig        `json:"server" yaml:"server"`
	Auth           AuthConfig       `json:"auth" yaml:"auth"`
	Database       DatabaseConfig   `json:"db" yaml:"db"`
	Redis          RedisConfig      `json:"redis" yaml:"redis"`
	OIDC           OIDCConfig       `json:"oidc" yaml:"oidc"`
	IAM            IAMConfig        `json:"iam" yaml:"iam"`
	Plugins        PluginsConfig    `json:"plugins" yaml:"plugins"`
	Admin          AdminConfig      `json:"auth_admin" yaml:"auth_admin"`
	Storage        storage.Config   `json:"storage" yaml:"storage"`
	TrustedClients []TrustedClient  `json:"auth_trusted_clients" yaml:"auth_trusted_clients"` // 受信任的第三方客户端配置
	StorageUrl     StorageUrlConfig `json:"storage_public_url" yaml:"storage_public_url"`     // 存储URL配置
}

type StorageUrlConfig struct {
	Attatch string `json:"attatch" yaml:"attatch"`
}

// ServerConfig Server configuration
// type ServerConfig struct {
// 	Port         int    `json:"port" yaml:"port"`
// 	ReadTimeout  string `json:"read_timeout" yaml:"read_timeout"`   // Using string format like "15s", "5m"
// 	WriteTimeout string `json:"write_timeout" yaml:"write_timeout"` // Using string format like "15s", "5m"
// }

// AuthConfig Authentication configuration
type AuthConfig struct {
	EnabledProviders []string         `json:"enabled_providers" yaml:"enabled_providers"` // "account", "email", "weixin", "google", "phone"
	Google           GoogleConfig     `json:"google" yaml:"google"`
	Weixin           WeixinConfig     `json:"weixin" yaml:"weixin"`
	WeixinMini       WeixinMiniConfig `json:"weixin_mini" yaml:"weixin_mini"`
	Smtp             SmtpConfig       `json:"smtp" yaml:"smtp"`
	SMS              SMSConfig        `json:"sms" yaml:"sms"` // New: SMS configuration
}

// IAMConfig contains optional CIAM/IAM extensions.
type IAMConfig struct {
	EnterpriseOIDC []EnterpriseOIDCProviderConfig `json:"enterprise_oidc" yaml:"enterprise_oidc"`
	EnterpriseSAML []EnterpriseSAMLProviderConfig `json:"enterprise_saml" yaml:"enterprise_saml"`
	SCIMInbound    []SCIMInboundConfig            `json:"scim_inbound" yaml:"scim_inbound"`
}

// EnterpriseOIDCProviderConfig describes an upstream enterprise OIDC provider.
type EnterpriseOIDCProviderConfig struct {
	Slug           string   `json:"slug" yaml:"slug"`
	Name           string   `json:"name" yaml:"name"`
	OrganizationID string   `json:"organization_id" yaml:"organization_id"`
	Priority       int      `json:"priority" yaml:"priority"`
	IsDefault      bool     `json:"is_default" yaml:"is_default"`
	AutoRedirect   bool     `json:"auto_redirect" yaml:"auto_redirect"`
	Issuer         string   `json:"issuer" yaml:"issuer"`
	ClientID       string   `json:"client_id" yaml:"client_id"`
	ClientSecret   string   `json:"client_secret" yaml:"client_secret"`
	RedirectURI    string   `json:"redirect_uri" yaml:"redirect_uri"`
	Scopes         []string `json:"scopes" yaml:"scopes"`
}

// EnterpriseSAMLProviderConfig describes an upstream enterprise SAML provider.
type EnterpriseSAMLProviderConfig struct {
	Slug                 string `json:"slug" yaml:"slug"`
	Name                 string `json:"name" yaml:"name"`
	OrganizationID       string `json:"organization_id" yaml:"organization_id"`
	Priority             int    `json:"priority" yaml:"priority"`
	IsDefault            bool   `json:"is_default" yaml:"is_default"`
	AutoRedirect         bool   `json:"auto_redirect" yaml:"auto_redirect"`
	IDPMetadataURL       string `json:"idp_metadata_url" yaml:"idp_metadata_url"`
	IDPMetadataXML       string `json:"idp_metadata_xml" yaml:"idp_metadata_xml"`
	EntityID             string `json:"entity_id" yaml:"entity_id"`
	ACSURL               string `json:"acs_url" yaml:"acs_url"`
	NameIDFormat         string `json:"name_id_format" yaml:"name_id_format"`
	EmailAttribute       string `json:"email_attribute" yaml:"email_attribute"`
	UsernameAttribute    string `json:"username_attribute" yaml:"username_attribute"`
	DisplayNameAttribute string `json:"display_name_attribute" yaml:"display_name_attribute"`
	AllowIDPInitiated    bool   `json:"allow_idp_initiated" yaml:"allow_idp_initiated"`
	DefaultRedirectURI   string `json:"default_redirect_uri" yaml:"default_redirect_uri"`
}

// SCIMInboundConfig describes an inbound SCIM 2.0 provisioning connection.
type SCIMInboundConfig struct {
	Enabled         bool   `json:"enabled" yaml:"enabled"`
	Slug            string `json:"slug" yaml:"slug"`
	Name            string `json:"name" yaml:"name"`
	OrganizationID  string `json:"organization_id" yaml:"organization_id"`
	BearerToken     string `json:"bearer_token" yaml:"bearer_token"`
	BearerTokenHash string `json:"bearer_token_hash" yaml:"bearer_token_hash"`
}

// PluginsConfig enables installable manifest plugins and configurable runtime actions.
type PluginsConfig struct {
	Enabled              bool                  `json:"enabled" yaml:"enabled"`
	Directories          []string              `json:"directories" yaml:"directories"`
	EnabledPlugins       []string              `json:"enabled_plugins" yaml:"enabled_plugins"`
	DisabledPlugins      []string              `json:"disabled_plugins" yaml:"disabled_plugins"`
	AllowedPermissions   []string              `json:"allowed_permissions" yaml:"allowed_permissions"`
	RequireSignature     bool                  `json:"require_signature" yaml:"require_signature"`
	AllowPrivateNetworks bool                  `json:"allow_private_networks" yaml:"allow_private_networks"`
	AllowedCatalogHosts  []string              `json:"allowed_catalog_hosts" yaml:"allowed_catalog_hosts"`
	AllowedDownloadHosts []string              `json:"allowed_download_hosts" yaml:"allowed_download_hosts"`
	AllowedActionHosts   []string              `json:"allowed_action_hosts" yaml:"allowed_action_hosts"`
	TrustedSigners       []PluginSignerConfig  `json:"trusted_signers" yaml:"trusted_signers"`
	Catalogs             []PluginCatalogConfig `json:"catalogs" yaml:"catalogs"`
	HTTPActions          []HTTPActionConfig    `json:"http_actions" yaml:"http_actions"`
}

type PluginSignerConfig struct {
	ID        string `json:"id" yaml:"id"`
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	PublicKey string `json:"public_key" yaml:"public_key"`
}

type PluginCatalogConfig struct {
	ID      string `json:"id" yaml:"id"`
	Name    string `json:"name" yaml:"name"`
	URL     string `json:"url" yaml:"url"`
	Enabled bool   `json:"enabled" yaml:"enabled"`
}

// HTTPActionConfig describes a remotely executed flow/action plugin.
type HTTPActionConfig struct {
	ID        string   `json:"id" yaml:"id"`
	Name      string   `json:"name" yaml:"name"`
	Enabled   bool     `json:"enabled" yaml:"enabled"`
	Events    []string `json:"events" yaml:"events"`
	URL       string   `json:"url" yaml:"url"`
	Secret    string   `json:"secret" yaml:"secret"`
	TimeoutMS int      `json:"timeout_ms" yaml:"timeout_ms"`
	FailOpen  bool     `json:"fail_open" yaml:"fail_open"`
}

// GoogleConfig Google OAuth configuration
type GoogleConfig struct {
	ClientID     string   `json:"client_id" yaml:"client_id"`
	ClientSecret string   `json:"client_secret" yaml:"client_secret"`
	RedirectURL  string   `json:"redirect_url" yaml:"redirect_url"`
	Scopes       []string `json:"scopes" yaml:"scopes"`
}

// WeixinConfig WeChat login configuration
type WeixinConfig struct {
	AppID             string `json:"app_id" yaml:"app_id"`
	AppSecret         string `json:"app_secret" yaml:"app_secret"`
	RedirectURL       string `json:"redirect_url" yaml:"redirect_url"`
	DomainVerifyToken string `json:"domain_verify_token" yaml:"domain_verify_token"`
}

// WeixinMiniConfig WeChat mini login configuration
type WeixinMiniConfig struct {
	AppID     string `json:"app_id" yaml:"app_id"`
	AppSecret string `json:"app_secret" yaml:"app_secret"`
	GrantType string `json:"grant_type" yaml:"grant_type"`
}

// SMSConfig SMS configuration
type SMSConfig struct {
	Provider   string `json:"provider" yaml:"provider"`       // SMS service provider, such as "aliyun", "tencent", etc.
	AccessKey  string `json:"access_key" yaml:"access_key"`   // Access key
	SecretKey  string `json:"secret_key" yaml:"secret_key"`   // Secret key
	SignName   string `json:"sign_name" yaml:"sign_name"`     // SMS signature
	TemplateID string `json:"template_id" yaml:"template_id"` // Template ID
	Region     string `json:"region" yaml:"region"`           // Region
}

// AdminConfig Administrator configuration
type AdminConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"` // Whether to enable admin page
	// Port         int       `json:"port" yaml:"port"`                   // Admin page listening port, separate from main service
	SecretKey    string    `json:"secret_key" yaml:"secret_key"`       // Admin page session key
	Accounts     []Account `json:"accounts" yaml:"accounts"`           // Admin account list
	AllowedIPs   []string  `json:"allowed_ips" yaml:"allowed_ips"`     // List of allowed IP addresses
	RequireTLS   bool      `json:"require_tls" yaml:"require_tls"`     // Whether to force TLS usage
	SessionTTL   int       `json:"session_ttl" yaml:"session_ttl"`     // Session validity period (minutes)
	LoginTimeout int       `json:"login_timeout" yaml:"login_timeout"` // Login timeout (seconds)
}

// Account Administrator account
type Account struct {
	Username string   `json:"username" yaml:"username"` // Username
	Password string   `json:"password" yaml:"password"` // Password (encrypted storage)
	Roles    []string `json:"roles" yaml:"roles"`       // Role list
}

// DatabaseConfig Database configuration
type DatabaseConfig struct {
	Driver     string `json:"driver" yaml:"driver"`
	SQLitePath string `json:"sqlite_path" yaml:"sqlite_path"`
	Username   string `json:"user" yaml:"user"`
	Password   string `json:"password" yaml:"password"`
	Host       string `json:"host" yaml:"host"`
	Port       int    `json:"port" yaml:"port"`
	Database   string `json:"database" yaml:"database"`
	Charset    string `json:"charset" yaml:"charset"`
}

// RedisConfig Redis configuration
type RedisConfig struct {
	Host string `json:"addr" yaml:"addr"`
	// Port     int    `json:"port" yaml:"port"`
	Password string `json:"password" yaml:"password"`
	DB       int    `json:"db" yaml:"db"`
}

// SmtpConfig Email configuration
type SmtpConfig struct {
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
	From     string `json:"from" yaml:"from"`
	// BaseURL  string `json:"base_url"` // Used to generate verification links
}

// TrustedClient 受信任的第三方客户端配置
type TrustedClient struct {
	ClientID     string   `json:"client_id" yaml:"client_id"`         // 客户端ID
	ClientSecret string   `json:"client_secret" yaml:"client_secret"` // 客户端密钥
	AllowedIPs   []string `json:"allowed_ips" yaml:"allowed_ips"`     // 允许的IP地址列表
	Scopes       []string `json:"scopes" yaml:"scopes"`               // 允许的权限范围
}

type OIDCConfig struct {
	Enabled               bool               `json:"enabled" yaml:"enabled"`
	Issuer                string             `json:"issuer" yaml:"issuer"`
	KeyID                 string             `json:"key_id" yaml:"key_id"`
	PrivateKeyPEM         string             `json:"private_key_pem" yaml:"private_key_pem"`
	PrivateKeyFile        string             `json:"private_key_file" yaml:"private_key_file"`
	CodeTTLSeconds        int                `json:"code_ttl_seconds" yaml:"code_ttl_seconds"`
	AccessTokenTTLSeconds int                `json:"access_token_ttl_seconds" yaml:"access_token_ttl_seconds"`
	IDTokenTTLSeconds     int                `json:"id_token_ttl_seconds" yaml:"id_token_ttl_seconds"`
	Clients               []OIDCClientConfig `json:"clients" yaml:"clients"`
}

type OIDCClientConfig struct {
	ClientID     string   `json:"client_id" yaml:"client_id"`
	ClientSecret string   `json:"client_secret" yaml:"client_secret"`
	RedirectURIs []string `json:"redirect_uris" yaml:"redirect_uris"`
	Scopes       []string `json:"scopes" yaml:"scopes"`
	Public       bool     `json:"public" yaml:"public"`
	RequirePKCE  bool     `json:"require_pkce" yaml:"require_pkce"`
}

func (c *TrustedClient) HasScope(_scope string) bool {
	for _, scope := range c.Scopes {
		if scope == _scope {
			return true
		}
	}
	return false
}

// LoadConfig Load configuration from file
func LoadConfig(path string) (*Config, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := &Config{}
	if err := yaml.Unmarshal(file, config); err != nil {
		return nil, err
	}

	return config, nil
}

const (
	DefaultDatabaseDriver = "sqlite"
	DefaultSQLitePath     = "data/mkauth.sqlite3"
	DefaultMySQLPort      = 3306
	DefaultMySQLCharset   = "utf8mb4"
)

func (dc *DatabaseConfig) EffectiveDriver() string {
	driver := strings.ToLower(strings.TrimSpace(dc.Driver))
	switch driver {
	case "mysql", "sqlite":
		return driver
	}
	if driver != "" {
		return driver
	}
	if dc.HasMySQLConfig() {
		return "mysql"
	}
	return DefaultDatabaseDriver
}

func (dc *DatabaseConfig) HasMySQLConfig() bool {
	return strings.TrimSpace(dc.Username) != "" ||
		strings.TrimSpace(dc.Host) != "" ||
		strings.TrimSpace(dc.Database) != ""
}

func (dc *DatabaseConfig) SQLitePathOrDefault() string {
	if path := strings.TrimSpace(dc.SQLitePath); path != "" {
		return path
	}
	return DefaultSQLitePath
}

func (dc *DatabaseConfig) mysqlPort() int {
	if dc.Port > 0 {
		return dc.Port
	}
	return DefaultMySQLPort
}

func (dc *DatabaseConfig) mysqlCharset() string {
	if charset := strings.TrimSpace(dc.Charset); charset != "" {
		return charset
	}
	return DefaultMySQLCharset
}

// GetDSN Get database connection string
func (dc *DatabaseConfig) GetDSN() string {
	return dc.Username + ":" + dc.Password + "@tcp(" + dc.Host + ":" + fmt.Sprintf("%d", dc.mysqlPort()) + ")/" + dc.Database + "?charset=" + dc.mysqlCharset() + "&parseTime=True&loc=Local"
}

// GetRedisAddr Get Redis connection address
func (rc *RedisConfig) GetRedisAddr() string {
	return rc.Host
}
