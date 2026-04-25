package oidc

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"minki.cc/mkauth/server/config"
)

func (p *Provider) Reload() error {
	if p == nil {
		return nil
	}
	clients, err := p.buildClients()
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.clients = clients
	p.mu.Unlock()
	return nil
}

func (p *Provider) HasStaticClientID(clientID string) bool {
	if p == nil {
		return false
	}
	clientID = strings.TrimSpace(clientID)
	for _, client := range p.staticClientConfigs() {
		if client.ClientID == clientID {
			return true
		}
	}
	return false
}

func (p *Provider) StaticClients() []config.OIDCClientConfig {
	if p == nil {
		return nil
	}
	staticClients := p.staticClientConfigs()
	return append([]config.OIDCClientConfig(nil), staticClients...)
}

func (p *Provider) AllowedOrigins() []string {
	clients := p.currentClients()
	origins := make(map[string]struct{}, len(clients))
	for _, client := range clients {
		for _, redirectURI := range client.RedirectURIs {
			parsed, err := url.Parse(strings.TrimSpace(redirectURI))
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				continue
			}
			origins[parsed.Scheme+"://"+parsed.Host] = struct{}{}
		}
	}
	allowedOrigins := make([]string, 0, len(origins))
	for origin := range origins {
		allowedOrigins = append(allowedOrigins, origin)
	}
	sort.Strings(allowedOrigins)
	return allowedOrigins
}

func (p *Provider) buildClients() ([]config.OIDCClientConfig, error) {
	staticClients := p.staticClientConfigs()
	seen := make(map[string]struct{}, len(staticClients))

	for _, client := range staticClients {
		client = NormalizeClientConfig(client)
		if err := ValidateClientConfig(client); err != nil {
			return nil, err
		}
		if _, exists := seen[client.ClientID]; exists {
			return nil, fmt.Errorf("duplicate oidc client_id %q", client.ClientID)
		}
		seen[client.ClientID] = struct{}{}
	}

	if p.db == nil {
		return nil, nil
	}

	if err := autoMigrateClientRecords(p.db); err != nil {
		return nil, err
	}

	clients := make([]config.OIDCClientConfig, 0)
	var records []ClientRecord
	if err := p.db.Where("enabled = ?", true).Order("created_at ASC").Find(&records).Error; err != nil {
		return nil, err
	}
	for _, record := range records {
		client, err := ClientConfigFromRecord(record)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[client.ClientID]; exists {
			return nil, fmt.Errorf("duplicate oidc client_id %q", client.ClientID)
		}
		seen[client.ClientID] = struct{}{}
		clients = append(clients, client)
	}
	return clients, nil
}

func (p *Provider) currentClients() []config.OIDCClientConfig {
	if p == nil {
		return nil
	}
	staticClients := p.staticClientConfigs()
	p.mu.RLock()
	dynamicClients := append([]config.OIDCClientConfig(nil), p.clients...)
	p.mu.RUnlock()
	if len(staticClients) == 0 && len(dynamicClients) == 0 {
		return nil
	}
	clients := make([]config.OIDCClientConfig, 0, len(staticClients)+len(dynamicClients))
	clients = append(clients, staticClients...)
	clients = append(clients, dynamicClients...)
	return clients
}

func (p *Provider) staticClientConfigs() []config.OIDCClientConfig {
	if p == nil {
		return nil
	}
	if len(p.cfg.Clients) > 0 {
		return append([]config.OIDCClientConfig(nil), p.cfg.Clients...)
	}
	if len(p.staticCfgs) > 0 {
		return append([]config.OIDCClientConfig(nil), p.staticCfgs...)
	}
	return nil
}
